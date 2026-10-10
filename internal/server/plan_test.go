package server

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

const quarantine = "OU=Quarantine," + people

// planEnv is an environment with the scope OU and its quarantine OU.
func planEnv(t *testing.T, extra string) *env {
	t.Helper()
	e := newEnv(t, extra)
	e.dir.addOU(people)
	e.dir.addOU(quarantine)
	return e
}

func createParams(id string) *provapi.UserCreateParams {
	return &provapi.UserCreateParams{ScopeOU: people, SAM: "ana." + id, UPN: "ana." + id + "@example.com", CN: "Ana Silva " + id,
		Mail: "ana." + id + "@example.com", GivenName: "Ana", Sn: "Silva", DisplayName: "Ana Silva",
		Fields: map[string]string{"title": "Engineer", "employeeID": "E-" + id, "mobile": ""}, Marker: provapi.Marker(id),
		Reference: "run-1"}
}

// create runs user.create and returns the new account.
func (e *env) create(id string) (provapi.UserCreateResult, *fakeObj) {
	e.t.Helper()
	var r provapi.UserCreateResult
	e.ok(provapi.OpUserCreate, createParams(id), &r)
	o := e.dir.objs[escape.NormalizeDN(r.DN)]
	if o == nil {
		e.t.Fatalf("created account %s not in the directory", r.DN)
	}
	return r, o
}

// markedUser adds an account carrying the marker of id.
func (e *env) markedUser(dn, sam, id string) *fakeObj {
	o := e.dir.addUser(dn, sam, sam+"@example.com", false)
	o.entry.Marker = provapi.Marker(id)
	return o
}

// auditText exports the whole audit log.
func (e *env) auditText() string {
	e.t.Helper()
	var buf bytes.Buffer
	if _, err := e.st.ExportAudit(context.Background(), &buf); err != nil {
		e.t.Fatal(err)
	}
	return buf.String()
}

func TestUserCreate(t *testing.T) {
	e := planEnv(t, "")
	r, o := e.create("101")
	if r.SID == "" || r.ObjectGUID == "" || r.SAM != "ana.101" || !strings.HasPrefix(r.DN, "CN=Ana Silva 101,OU=People") {
		t.Fatalf("result %+v", r)
	}
	got := o.entry
	if got.Enabled() || got.PwdLastSet != 0 || got.Marker != "google-first:101" || got.Title != "Engineer" ||
		got.EmployeeID != "E-101" || got.Mobile != "" || got.GivenName != "Ana" || got.UserPrincipalName != "ana.101@example.com" {
		t.Fatalf("created %+v", got)
	}
	if len(e.dir.passwords) != 1 || e.dir.passwords[0] != passwordLength {
		t.Fatalf("passwords %v", e.dir.passwords)
	}
	ev := e.lastAudit()
	if ev.Op != "user.create" || ev.Result != "ok" || ev.TargetSAM != "ana.101" || ev.TargetSID != r.SID || ev.Reference != "run-1" ||
		!strings.Contains(ev.Detail, "marker google-first:101") || !strings.Contains(ev.Detail, "parent ou=people") {
		t.Fatalf("audit %+v", ev)
	}
	// No personal data beyond the logon name in the audit log.
	for _, v := range []string{"ana.101@example.com", "Ana Silva", "Engineer", "E-101"} {
		if strings.Contains(e.auditText(), v) {
			t.Fatalf("%q in the audit log", v)
		}
	}
	// The new account is an ordinary in-scope account: an invitation can
	// be issued for it.
	var chk provapi.UserResult
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: r.SID}, &chk)
	if !chk.InScope || chk.Privileged || chk.Enabled {
		t.Fatalf("user.check %+v", chk)
	}
	e.issue(o, provapi.PurposeInvite)
	// Below the scope OU is fine too.
	sub := createParams("102")
	sub.ScopeOU = quarantine
	e.ok(provapi.OpUserCreate, sub, nil)
}

func TestRandomPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		pw, err := randomPassword(nameParts("ana.silva", "Ana Silva", "Ana", "Silva"))
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != passwordLength || seen[pw] {
			t.Fatalf("length %d or repeated", len(pw))
		}
		seen[pw] = true
		for _, class := range passwordClasses {
			if !strings.ContainsAny(pw, class) {
				t.Fatalf("a class is missing in a password")
			}
		}
		for _, part := range []string{"ana", "silva"} {
			if strings.Contains(strings.ToLower(pw), part) {
				t.Fatalf("a password contains %q", part)
			}
		}
	}
}

func TestUserCreateRefusals(t *testing.T) {
	e := planEnv(t, "")
	e.dir.addOU("OU=Staff,OU=Lab,DC=example,DC=com")
	e.dir.addUser("CN=Box,"+people, "box", "", false, "top", "container")
	other := e.dir.addUser("CN=Other,OU=Staff,OU=Lab,DC=example,DC=com", "taken", "taken@example.com", false)
	other.entry.UserPrincipalName = "taken.upn@example.com"
	other.entry.ProxyAddresses = []string{"SMTP:taken@example.com", "smtp:alias@example.com"}
	other.entry.Marker = provapi.Marker("999")
	e.dir.addUser("CN=Ana Silva 7,"+people, "someone", "", false)

	type refusal struct {
		mod   func(p *provapi.UserCreateParams)
		code  provapi.ErrorCode
		kinds []string
	}
	cases := map[string]refusal{
		"outside scope": {func(p *provapi.UserCreateParams) { p.ScopeOU = "OU=Staff,OU=Lab,DC=example,DC=com" }, provapi.CodeOutOfScope, nil},
		"domain head":   {func(p *provapi.UserCreateParams) { p.ScopeOU = "DC=example,DC=com" }, provapi.CodeOutOfScope, nil},
		"trick": {func(p *provapi.UserCreateParams) {
			p.ScopeOU = `OU=x\,OU=People\,OU=Lab\,DC=example\,DC=com,DC=example,DC=com`
		},
			provapi.CodeOutOfScope, nil},
		"missing OU":    {func(p *provapi.UserCreateParams) { p.ScopeOU = "OU=Nope," + people }, provapi.CodeNotFound, nil},
		"container":     {func(p *provapi.UserCreateParams) { p.ScopeOU = "CN=Box," + people }, provapi.CodeInvalidParams, nil},
		"dn exists":     {func(p *provapi.UserCreateParams) { p.CN = "Ana Silva 7" }, provapi.CodeExists, []string{"dn"}},
		"sam":           {func(p *provapi.UserCreateParams) { p.SAM = "TAKEN" }, provapi.CodeExists, []string{"sam"}},
		"upn":           {func(p *provapi.UserCreateParams) { p.UPN = "taken.upn@example.com" }, provapi.CodeExists, []string{"upn"}},
		"mail":          {func(p *provapi.UserCreateParams) { p.Mail = "Taken@example.com" }, provapi.CodeExists, []string{"mail"}},
		"mail as alias": {func(p *provapi.UserCreateParams) { p.Mail = "alias@example.com" }, provapi.CodeExists, []string{"mail"}},
		"mail as upn":   {func(p *provapi.UserCreateParams) { p.Mail = "taken.upn@example.com" }, provapi.CodeExists, []string{"mail"}},
		"marker":        {func(p *provapi.UserCreateParams) { p.Marker = provapi.Marker("999") }, provapi.CodeExists, []string{"marker"}},
		"several": {func(p *provapi.UserCreateParams) { p.SAM, p.Mail = "taken", "taken@example.com" }, provapi.CodeExists,
			[]string{"mail", "sam"}},
	}
	for name, tc := range cases {
		p := createParams("70")
		tc.mod(p)
		pe := e.refused(provapi.OpUserCreate, admin, p, tc.code)
		if tc.kinds != nil && !slices.Equal(pe.Kinds, tc.kinds) {
			t.Errorf("%s: kinds %v, want %v", name, pe.Kinds, tc.kinds)
		}
		if ev := e.lastAudit(); ev.Op != "user.create" || ev.Result != string(tc.code) {
			t.Errorf("%s: audit %+v", name, ev)
		}
	}
	if len(e.dir.applied) != 0 || len(e.dir.passwords) != 0 {
		t.Fatal("a refused create reached the directory")
	}

	// The schema lacks the marker attribute.
	e.dir.noMarker = true
	e.refused(provapi.OpUserCreate, admin, createParams("8"), provapi.CodeSchemaMissing)
	e.dir.noMarker = false

	// A directory read failure refuses.
	e.dir.readErr = errors.New("ldap down")
	e.refused(provapi.OpUserCreate, admin, createParams("8"), provapi.CodeDirectory)
	e.dir.readErr = nil

	// A refused write (here: access denied) is a directory error.
	e.dir.applyErr = errors.New("insufficient access")
	e.refused(provapi.OpUserCreate, admin, createParams("8"), provapi.CodeDirectory)

	// The directory implementation cannot create: directory error, named.
	e.dir.applyErr = directory.ErrUnsupported
	pe := e.refused(provapi.OpUserCreate, admin, createParams("8"), provapi.CodeDirectory)
	if !strings.Contains(pe.Message, "cannot create") {
		t.Fatalf("message %q", pe.Message)
	}

	// No scope at all.
	e.cfg.Scope.OUs = nil
	e.refused(provapi.OpUserCreate, admin, createParams("9"), provapi.CodeOutOfScope)
}

func TestUserCreateCeiling(t *testing.T) {
	e := planEnv(t, "\n[limits]\ncreates_per_hour = 1\n")
	e.create("1")
	e.refused(provapi.OpUserCreate, admin, createParams("2"), provapi.CodeRateLimited)
	e.clk.add(61 * time.Minute)
	e.create("2")
	var st provapi.StatusResult
	e.ok(provapi.OpStatus, nil, &st)
	if st.Limits.Creates.Used != 1 || st.Limits.Creates.Ceiling != 1 || st.Limits.Updates.Ceiling != 200 ||
		st.Limits.Moves.Ceiling != 200 || st.Limits.Disables.Ceiling != 200 {
		t.Fatalf("status limits %+v", st.Limits)
	}
	z := planEnv(t, "\n[limits]\ncreates_per_hour = 0\n")
	z.refused(provapi.OpUserCreate, admin, createParams("3"), provapi.CodeRateLimited)
}

func TestUserUpdate(t *testing.T) {
	e := planEnv(t, "\n[limits]\nupdates_per_hour = 4\n")
	r, o := e.create("201")
	marker := provapi.Marker("201")
	upd := func(changes ...provapi.UserChange) *provapi.UserUpdateParams {
		return &provapi.UserUpdateParams{SID: r.SID, Marker: marker, Changes: changes, Reference: "run-2"}
	}
	var w provapi.UserWriteResult
	e.ok(provapi.OpUserUpdate, upd(
		provapi.UserChange{Attr: "sn", Before: "Silva", After: "Souza"},
		provapi.UserChange{Attr: "employeeID", Before: "E-201", After: ""},
		provapi.UserChange{Attr: "department", Before: "", After: "Sales"},
		provapi.UserChange{Attr: "proxyAddresses", Before: "", After: provapi.JoinValues([]string{"smtp:old@example.com"})},
	), &w)
	if !w.Changed || w.SID != r.SID || w.Enabled {
		t.Fatalf("result %+v", w)
	}
	got := o.entry
	if got.Surname != "Souza" || got.EmployeeID != "" || got.Department != "Sales" || !slices.Equal(got.ProxyAddresses, []string{"smtp:old@example.com"}) {
		t.Fatalf("entry %+v", got)
	}
	ev := e.lastAudit()
	if ev.Op != "user.update" || ev.Result != "ok" || ev.Reference != "run-2" || !strings.Contains(ev.Detail, "changed sn,employeeID,department,proxyAddresses") ||
		strings.Contains(ev.Detail, "Souza") || strings.Contains(ev.Detail, "old@example.com") {
		t.Fatalf("audit %+v", ev)
	}

	// A rename: the new address may be the account's own alias, and the
	// old one moves to the aliases. Proxy addresses compare as a set.
	o.entry.ProxyAddresses = []string{"smtp:z@example.com", "smtp:new@example.com"}
	e.ok(provapi.OpUserUpdate, upd(
		provapi.UserChange{Attr: "mail", Before: "ana.201@example.com", After: "new@example.com"},
		provapi.UserChange{Attr: "proxyAddresses", Before: "smtp:new@example.com\nsmtp:z@example.com",
			After: "smtp:ana.201@example.com\nsmtp:new@example.com\nsmtp:z@example.com"},
	), nil)
	if o.entry.Mail != "new@example.com" || len(o.entry.ProxyAddresses) != 3 {
		t.Fatalf("rename %+v", o.entry)
	}

	writes := len(e.dir.applied)
	// The current value differs from before: conflict, nothing written.
	pe := e.refused(provapi.OpUserUpdate, admin, upd(
		provapi.UserChange{Attr: "givenName", Before: "Anna", After: "Ana Maria"},
		provapi.UserChange{Attr: "sn", Before: "Souza", After: "Lima"},
		provapi.UserChange{Attr: "title", Before: "", After: "Lead"},
	), provapi.CodeConflict)
	if !slices.Equal(pe.Kinds, []string{"givenName", "title"}) {
		t.Fatalf("kinds %v", pe.Kinds)
	}
	if o.entry.Surname != "Souza" {
		t.Fatal("a conflicting update wrote a value")
	}
	// The new address is another object's.
	e.dir.addUser("CN=Bob,OU=Staff,OU=Lab,DC=example,DC=com", "bob", "bob@example.com", false)
	pe = e.refused(provapi.OpUserUpdate, admin, upd(provapi.UserChange{Attr: "mail", Before: "new@example.com", After: "BOB@example.com"}),
		provapi.CodeExists)
	if !slices.Equal(pe.Kinds, []string{"mail"}) {
		t.Fatalf("kinds %v", pe.Kinds)
	}
	// Another marker, or none.
	bad := upd(provapi.UserChange{Attr: "sn", Before: "Souza", After: "Lima"})
	bad.Marker = provapi.Marker("202")
	e.refused(provapi.OpUserUpdate, admin, bad, provapi.CodeMarkerMismatch)
	plain := e.dir.addUser("CN=Plain,"+people, "plain", "plain@example.com", false)
	plain.entry.Surname = "P"
	e.refused(provapi.OpUserUpdate, admin, &provapi.UserUpdateParams{SID: plain.entry.SID.String(), Marker: marker,
		Changes: []provapi.UserChange{{Attr: "sn", Before: "P", After: "Q"}}}, provapi.CodeMarkerMismatch)
	if ev := e.lastAudit(); !strings.Contains(ev.Detail, "no marker") || strings.Contains(ev.Detail, "google-first:") {
		t.Fatalf("audit %+v", ev)
	}
	// Moved out of the scope by someone else.
	out := e.markedUser("CN=Out,OU=Staff,OU=Lab,DC=example,DC=com", "out", "203")
	out.entry.Surname = "O"
	e.refused(provapi.OpUserUpdate, admin, &provapi.UserUpdateParams{SID: out.entry.SID.String(), Marker: provapi.Marker("203"),
		Changes: []provapi.UserChange{{Attr: "sn", Before: "O", After: "Q"}}}, provapi.CodeOutOfScope)
	if len(e.dir.applied) != writes {
		t.Fatal("a refused update reached the directory")
	}
	// Ceiling: two used above, two more allowed.
	e.ok(provapi.OpUserUpdate, upd(provapi.UserChange{Attr: "sn", Before: "Souza", After: "Lima"}), nil)
	e.ok(provapi.OpUserUpdate, upd(provapi.UserChange{Attr: "sn", Before: "Lima", After: "Souza"}), nil)
	e.refused(provapi.OpUserUpdate, admin, upd(provapi.UserChange{Attr: "sn", Before: "Souza", After: "Lima"}), provapi.CodeRateLimited)
}

func TestUserSetEnabledAndMove(t *testing.T) {
	e := planEnv(t, "")
	r, o := e.create("301")
	marker := provapi.Marker("301")
	tok := e.issue(o, provapi.PurposeInvite)

	// Disable an account already disabled: no write, open tokens revoked
	// (an invitation would enable it again).
	var w provapi.UserWriteResult
	e.ok(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: r.SID, Enabled: false, Marker: marker}, &w)
	if w.Changed || w.Enabled {
		t.Fatalf("result %+v", w)
	}
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeRevoked)
	if ev := e.lastAudit(); ev.Op != "token.check" {
		t.Fatalf("audit %+v", ev)
	}

	// Enable, then disable and quarantine, then back.
	e.ok(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: r.SID, Enabled: true, Marker: marker}, &w)
	if !w.Changed || !w.Enabled || !o.entry.Enabled() {
		t.Fatalf("enable %+v", w)
	}
	tok = e.issue(o, provapi.PurposeReset)
	e.ok(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: r.SID, Enabled: false, Marker: marker, Reference: "run-3"}, &w)
	if !w.Changed || w.Enabled || o.entry.Enabled() {
		t.Fatalf("disable %+v", w)
	}
	if ev := e.lastAudit(); ev.Op != "user.set_enabled" || !strings.Contains(ev.Detail, "account disabled") ||
		!strings.Contains(ev.Detail, "revoked 1 open token") || ev.Reference != "run-3" {
		t.Fatalf("audit %+v", ev)
	}
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeRevoked)

	e.ok(provapi.OpUserMove, &provapi.UserMoveParams{SID: r.SID, ToOU: quarantine, Marker: marker}, &w)
	if !w.Changed || !strings.HasSuffix(w.DN, ","+quarantine) || o.entry.DN != w.DN {
		t.Fatalf("move %+v (%s)", w, o.entry.DN)
	}
	if ev := e.lastAudit(); ev.Op != "user.move" || !strings.Contains(ev.Detail, "to ou=quarantine,ou=people") {
		t.Fatalf("audit %+v", ev)
	}
	// Already there: no write.
	n := len(e.dir.applied)
	e.ok(provapi.OpUserMove, &provapi.UserMoveParams{SID: r.SID, ToOU: "ou=quarantine, " + people, Marker: marker}, &w)
	if w.Changed || len(e.dir.applied) != n {
		t.Fatal("a move to the same OU wrote")
	}
	e.ok(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: r.SID, Enabled: true, Marker: marker}, nil)
	e.ok(provapi.OpUserMove, &provapi.UserMoveParams{SID: r.SID, ToOU: people, Marker: marker}, &w)
	if !w.Changed || !w.Enabled || !strings.HasSuffix(w.DN, ","+people) || strings.Contains(w.DN, "Quarantine") {
		t.Fatalf("move back %+v", w)
	}

	// Refusals.
	e.dir.addOU("OU=Staff,OU=Lab,DC=example,DC=com")
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: r.SID, ToOU: "OU=Staff,OU=Lab,DC=example,DC=com", Marker: marker},
		provapi.CodeOutOfScope)
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: r.SID, ToOU: "OU=Missing," + people, Marker: marker},
		provapi.CodeNotFound)
	e.dir.addUser("CN=Box,"+people, "box", "", false, "top", "container")
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: r.SID, ToOU: "CN=Box," + people, Marker: marker},
		provapi.CodeInvalidParams)
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: r.SID, ToOU: quarantine, Marker: provapi.Marker("302")},
		provapi.CodeMarkerMismatch)
	e.refused(provapi.OpUserSetEnabled, admin, &provapi.UserSetEnabledParams{SID: r.SID, Enabled: false, Marker: provapi.Marker("302")},
		provapi.CodeMarkerMismatch)
	// A same-named account in the quarantine OU: the move collides.
	e.dir.addUser("CN=Ana Silva 301,"+quarantine, "dup", "", false)
	pe := e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: r.SID, ToOU: quarantine, Marker: marker}, provapi.CodeExists)
	if !slices.Equal(pe.Kinds, []string{"dn"}) {
		t.Fatalf("kinds %v", pe.Kinds)
	}
	if !o.entry.Enabled() || !strings.HasSuffix(o.entry.DN, ","+people) {
		t.Fatal("a refused operation changed the account")
	}
}

func TestMoveAcrossScopes(t *testing.T) {
	e := newEnvText(t, strings.Replace(testConf, `ous = ["OU=People,OU=Lab,DC=example,DC=com"]`,
		`ous = ["OU=People,OU=Lab,DC=example,DC=com", "OU=Staff,OU=Lab,DC=example,DC=com"]`, 1))
	e.dir.addOU(people)
	e.dir.addOU("OU=Staff,OU=Lab,DC=example,DC=com")
	u := e.markedUser("CN=Cross,"+people, "cross", "401")
	// Both OUs are delegated, but not the same scope OU.
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: u.entry.SID.String(), ToOU: "OU=Staff,OU=Lab,DC=example,DC=com",
		Marker: provapi.Marker("401")}, provapi.CodeOutOfScope)
	if len(e.dir.applied) != 0 {
		t.Fatal("a cross-scope move reached the directory")
	}
}

func TestPlanCeilings(t *testing.T) {
	e := planEnv(t, "\n[limits]\nmoves_per_hour = 0\ndisables_per_hour = 1\nenables_per_hour = 0\n")
	u := e.markedUser("CN=Ceil,"+people, "ceil", "501")
	v := e.markedUser("CN=Ceil2,"+people, "ceil2", "502")
	e.refused(provapi.OpUserMove, admin, &provapi.UserMoveParams{SID: u.entry.SID.String(), ToOU: quarantine, Marker: provapi.Marker("501")},
		provapi.CodeRateLimited)
	e.ok(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: u.entry.SID.String(), Enabled: false, Marker: provapi.Marker("501")}, nil)
	e.refused(provapi.OpUserSetEnabled, admin, &provapi.UserSetEnabledParams{SID: v.entry.SID.String(), Enabled: false, Marker: provapi.Marker("502")},
		provapi.CodeRateLimited)
	// An enable by user.set_enabled counts under enables_per_hour.
	e.refused(provapi.OpUserSetEnabled, admin, &provapi.UserSetEnabledParams{SID: u.entry.SID.String(), Enabled: true, Marker: provapi.Marker("501")},
		provapi.CodeRateLimited)
	if ev := e.lastAudit(); ev.Result != "rate_limited" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestPlanOpsRefusePrivileged(t *testing.T) {
	e := planEnv(t, `
[privileged]
extra_group_sids = ["S-1-5-21-1-2-3-4000"]
`)
	byRole := e.markedUser("CN=Role,"+people, "role", "601")
	byRole.groups = append(byRole.groups, mustSID("S-1-5-21-1-2-3-4000"))
	byAdminCount := e.markedUser("CN=AC,"+people, "ac", "602")
	byAdminCount.entry.AdminCount = true
	byACL := e.markedUser("CN=ACL,"+people, "acl", "603")
	e.dir.priv[byACL.entry.SID.String()] = []privilege.Reason{{Kind: privilege.KindACL, Detail: people}}
	for id, o := range map[string]*fakeObj{"601": byRole, "602": byAdminCount, "603": byACL} {
		s, m := o.entry.SID.String(), provapi.Marker(id)
		o.entry.Surname = "S"
		for op, p := range map[provapi.Op]provapi.Params{
			provapi.OpUserUpdate:     &provapi.UserUpdateParams{SID: s, Marker: m, Changes: []provapi.UserChange{{Attr: "sn", Before: "S", After: "T"}}},
			provapi.OpUserSetEnabled: &provapi.UserSetEnabledParams{SID: s, Enabled: false, Marker: m},
			provapi.OpUserMove:       &provapi.UserMoveParams{SID: s, ToOU: quarantine, Marker: m},
		} {
			pe := e.refused(op, admin, p, provapi.CodePrivileged)
			if len(pe.Kinds) == 0 {
				t.Errorf("%s %s: no kinds", op, id)
			}
			if ev := e.lastAudit(); ev.Op != string(op) || !strings.Contains(ev.Detail, "privileged:") {
				t.Errorf("%s %s: audit %+v", op, id, ev)
			}
		}
	}
	if len(e.dir.applied) != 0 {
		t.Fatal("a write reached the directory for a privileged account")
	}
	// A computer or a group with the marker is not a user account.
	pc := e.dir.addUser("CN=PC,"+people, "pc$", "", false, "top", "person", "organizationalPerson", "user", "computer")
	pc.entry.Marker = provapi.Marker("604")
	e.refused(provapi.OpUserSetEnabled, admin, &provapi.UserSetEnabledParams{SID: pc.entry.SID.String(), Marker: provapi.Marker("604")},
		provapi.CodeNotFound)
}
