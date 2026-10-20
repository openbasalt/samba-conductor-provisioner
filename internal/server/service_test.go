package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

const (
	people   = "OU=People,OU=Lab,DC=example,DC=com"
	testConf = `
[domain]
realm = "EXAMPLE.COM"
ca_file = "/etc/conductor-provisioner/domain-ca.pem"
[account]
username = "svc-conductor-prov"
[scope]
ous = ["OU=People,OU=Lab,DC=example,DC=com"]
[api]
allowed_uids = [1001]
`
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t    *testing.T
	clk  *clock
	dir  *fakeDir
	st   *store.Store
	svc  *Service
	cfg  *config.Config
	logs *syncBuffer
}

// syncBuffer is a log sink safe for the server's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var admin = provapi.Actor{User: "helpdesk", SID: "S-1-5-21-1-2-3-1500", Session: "sess-1", IP: "192.0.2.10"}

func newEnv(t *testing.T, extra string) *env {
	t.Helper()
	return newEnvText(t, testConf+extra)
}

// newEnvText builds the environment from a whole configuration.
func newEnvText(t *testing.T, text string) *env {
	t.Helper()
	cfg, err := config.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	st, err := store.Open(context.Background(), ":memory:", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetClock(clk.now)
	dir := newFakeDir(clk.now)
	logs := &syncBuffer{}
	svc, err := NewService(Options{Config: cfg, Store: st, Directory: dir, Version: "test", Now: clk.now,
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, clk: clk, dir: dir, st: st, svc: svc, cfg: cfg, logs: logs}
}

func (e *env) do(op provapi.Op, actor provapi.Actor, params provapi.Params) provapi.Response {
	e.t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		e.t.Fatal(err)
	}
	req := provapi.Request{Version: provapi.ProtocolVersion, ID: provapi.NewRequestID(), Op: op, Actor: actor, Params: raw,
		SentAt: e.clk.now()}
	return e.svc.Handle(context.Background(), req)
}

func (e *env) ok(op provapi.Op, params provapi.Params, out any) {
	e.t.Helper()
	resp := e.do(op, admin, params)
	if !resp.OK {
		e.t.Fatalf("%s: %+v", op, resp.Error)
	}
	if out != nil {
		if err := provapi.DecodeResult(resp, out); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) refused(op provapi.Op, actor provapi.Actor, params provapi.Params, code provapi.ErrorCode) *provapi.Error {
	e.t.Helper()
	resp := e.do(op, actor, params)
	if resp.OK || resp.Error == nil {
		e.t.Fatalf("%s: want %s, got OK", op, code)
	}
	if resp.Error.Code != code {
		e.t.Fatalf("%s: want %s, got %s (%s)", op, code, resp.Error.Code, resp.Error.Message)
	}
	return resp.Error
}

func (e *env) issue(o *fakeObj, purpose string) provapi.TokenIssueResult {
	e.t.Helper()
	var r provapi.TokenIssueResult
	e.ok(provapi.OpTokenIssue, &provapi.TokenIssueParams{SID: o.entry.SID.String(), Purpose: purpose, Reference: "ref-1"}, &r)
	return r
}

func (e *env) lastAudit() store.AuditEvent {
	e.t.Helper()
	ev, err := e.st.ListAudit(context.Background(), 1)
	if err != nil || len(ev) != 1 {
		e.t.Fatalf("audit: %v %d", err, len(ev))
	}
	return ev[0]
}

func TestRegistryCoversAllowlist(t *testing.T) {
	for op := range provapi.Allowlist {
		h, ok := registry[op]
		if !ok {
			t.Errorf("no handler for %s", op)
			continue
		}
		if h.mutating != op.Mutating() {
			t.Errorf("%s: registry mutating=%v, provapi says %v", op, h.mutating, op.Mutating())
		}
	}
	for op := range registry {
		if _, ok := provapi.Allowlist[op]; !ok {
			t.Errorf("handler for %s, which is not allowlisted", op)
		}
	}
}

func TestInviteFlow(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Ana,"+people, "ana", "ana@example.com", true)
	tok := e.issue(u, provapi.PurposeInvite)
	if tok.Token == "" || tok.SAM != "ana" || tok.Mail != "ana@example.com" {
		t.Fatalf("issue: %+v", tok)
	}
	if want := e.clk.now().Add(72 * time.Hour); !tok.ExpiresAt.Equal(want) {
		t.Fatalf("expires %s, want %s", tok.ExpiresAt, want)
	}
	var chk provapi.TokenCheckResult
	e.ok(provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: tok.Token}, &chk)
	if chk.Purpose != "invite" || chk.PasswordSet || chk.SID != u.entry.SID.String() {
		t.Fatalf("check: %+v", chk)
	}
	// Completing before the password step is refused.
	e.refused(provapi.OpInviteComplete, provapi.Actor{User: provapi.PublicUser, Session: "link-1"},
		&provapi.InviteCompleteParams{Token: tok.Token}, provapi.CodeInvalidParams)

	public := provapi.Actor{User: provapi.PublicUser, Session: "link-1", IP: "198.51.100.7"}
	resp := e.do(provapi.OpPasswordSet, public, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "S3cret-Passw0rd!"})
	if !resp.OK {
		t.Fatalf("password.set: %+v", resp.Error)
	}
	e.ok(provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: tok.Token}, &chk)
	if !chk.PasswordSet {
		t.Fatal("password_set not reported")
	}
	// The invitation's expiry shrinks to the complete window.
	if want := e.clk.now().Add(30 * time.Minute); !chk.ExpiresAt.Equal(want) {
		t.Fatalf("expires %s, want %s", chk.ExpiresAt, want)
	}
	// A second password.set on the same invitation is refused.
	e.refused(provapi.OpPasswordSet, public, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Another-Passw0rd!"}, provapi.CodeUsed)

	var done provapi.InviteCompleteResult
	resp = e.do(provapi.OpInviteComplete, public, &provapi.InviteCompleteParams{Token: tok.Token})
	if !resp.OK {
		t.Fatalf("complete: %+v", resp.Error)
	}
	_ = provapi.DecodeResult(resp, &done)
	if done.SAM != "ana" {
		t.Fatalf("complete: %+v", done)
	}
	got, _ := e.dir.Get(context.Background(), u.entry.DN)
	if !got.Enabled() {
		t.Fatal("account not enabled")
	}
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeUsed)

	// The password never reaches the audit log, the logs or the database.
	var buf bytes.Buffer
	if _, err := e.st.ExportAudit(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"S3cret-Passw0rd!", "Another-Passw0rd!", tok.Token} {
		if strings.Contains(buf.String(), secret) || strings.Contains(e.logs.String(), secret) {
			t.Fatalf("%q leaked into the audit log or the logs", secret)
		}
	}
	for _, p := range e.dir.applied {
		if strings.Contains(p.String(), "S3cret") {
			t.Fatal("password rendered in a preview")
		}
	}
}

func TestResetFlowUnlocks(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Bia,"+people, "bia", "bia@example.com", false)
	u.entry.LockoutTime = 5
	u.entry.ComputedUAC = ad.UACLockout
	tok := e.issue(u, provapi.PurposeReset)
	if want := e.clk.now().Add(30 * time.Minute); !tok.ExpiresAt.Equal(want) {
		t.Fatalf("expires %s, want %s", tok.ExpiresAt, want)
	}
	var r provapi.PasswordSetResult
	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "N3w-Passw0rd!", Unlock: true}, &r)
	if r.Purpose != "reset" || r.SAM != "bia" {
		t.Fatalf("%+v", r)
	}
	got, _ := e.dir.Get(context.Background(), u.entry.DN)
	if got.LockoutTime != 0 || got.Locked() {
		t.Fatal("lockout not cleared")
	}
	// A reset token is consumed by password.set.
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "N3w-Passw0rd!2"}, provapi.CodeUsed)
	e.refused(provapi.OpInviteComplete, admin, &provapi.InviteCompleteParams{Token: tok.Token}, provapi.CodeUsed)
}

func TestScope(t *testing.T) {
	e := newEnv(t, "")
	cases := []struct {
		dn   string
		code provapi.ErrorCode // "" = allowed
	}{
		{"CN=In," + people, ""},
		{"CN=Deep,OU=Sub," + people, ""},
		{"cn=Case,ou=PEOPLE,ou=lab,dc=EXAMPLE,dc=com", ""},
		{"CN=Spaced, OU=People , OU=Lab,DC=example,DC=com", ""},
		{"CN=Out,OU=Staff,OU=Lab,DC=example,DC=com", provapi.CodeOutOfScope},
		{"CN=Trailing," + people + ",DC=evil", provapi.CodeOutOfScope},
		{"CN=Prefix,OU=People2,OU=Lab,DC=example,DC=com", provapi.CodeOutOfScope},
		{`CN=Esc\,OU=People\,OU=Lab\,DC=example\,DC=com,OU=Other,DC=example,DC=com`, provapi.CodeOutOfScope},
		{"CN=Users-container,CN=Users,DC=example,DC=com", provapi.CodeOutOfScope},
	}
	for i, tc := range cases {
		u := e.dir.addUser(tc.dn, fmt.Sprintf("user%d", i), "", true)
		p := &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: provapi.PurposeInvite}
		if tc.code == "" {
			e.ok(provapi.OpTokenIssue, p, nil)
			continue
		}
		e.refused(provapi.OpTokenIssue, admin, p, tc.code)
		var r provapi.UserResult
		e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.entry.SID.String()}, &r)
		if r.InScope {
			t.Errorf("%s: user.check says in scope", tc.dn)
		}
	}
}

func TestEmptyScopeRefusesEverything(t *testing.T) {
	e := newEnv(t, "")
	e.cfg.Scope.OUs = nil
	u := e.dir.addUser("CN=In,"+people, "in", "", true)
	e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: "invite"}, provapi.CodeOutOfScope)
}

func TestPrivileged(t *testing.T) {
	e := newEnv(t, `
[privileged]
extra_group_sids = ["S-1-5-21-1-2-3-4000"]
`)
	byGroup := e.dir.addUser("CN=G,"+people, "g", "", false)
	byGroup.groups = append(byGroup.groups, e.dir.addUser("CN=Nested,OU=Groups,DC=example,DC=com", "nested", "", false, "group").entry.SID)
	e.dir.priv[byGroup.groups[0].String()] = []privilege.Reason{{Kind: privilege.KindGroup, Detail: "S-1-5-21-1-2-3-512"}}

	byAdminCount := e.dir.addUser("CN=A,"+people, "a", "", false)
	byAdminCount.entry.AdminCount = true

	byACL := e.dir.addUser("CN=Acl,"+people, "acl", "", false)
	e.dir.priv[byACL.entry.SID.String()] = []privilege.Reason{{Kind: privilege.KindACL, Detail: people + ": (A;;WP;;;S-1-5-21-1-2-3-x)"}}

	byOwner := e.dir.addUser("CN=Own,"+people, "own", "", false)
	e.dir.priv[byOwner.entry.SID.String()] = []privilege.Reason{{Kind: privilege.KindOwner, Detail: "CN={GPO},CN=Policies"}}

	byRole := e.dir.addUser("CN=Role,"+people, "role", "", false)
	byRole.groups = append(byRole.groups, mustSID("S-1-5-21-1-2-3-4000"))

	for name, o := range map[string]*fakeObj{"group": byGroup, "adminCount": byAdminCount, "acl": byACL, "owner": byOwner, "role": byRole} {
		pe := e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: o.entry.SID.String(), Purpose: "reset"}, provapi.CodePrivileged)
		if len(pe.Kinds) == 0 || strings.Contains(pe.Message, "S-1-5") {
			t.Errorf("%s: kinds %v, message %q (details must stay in the audit)", name, pe.Kinds, pe.Message)
		}
		if ev := e.lastAudit(); ev.Result != "privileged" || !strings.Contains(ev.Detail, "privileged:") {
			t.Errorf("%s: audit %+v", name, ev)
		}
		var r provapi.UserResult
		e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: o.entry.SID.String()}, &r)
		if !r.Privileged || len(r.PrivilegedReasons) == 0 || !r.InScope {
			t.Errorf("%s: user.check %+v", name, r)
		}
	}
	// A plain user is not privileged.
	plain := e.dir.addUser("CN=Plain,"+people, "plain", "", false)
	var r provapi.UserResult
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: plain.entry.SID.String()}, &r)
	if r.Privileged || len(r.PrivilegedReasons) != 0 {
		t.Fatalf("plain: %+v", r)
	}

	// Privilege acquired after issue blocks the token's use.
	tok := e.issue(plain, provapi.PurposeReset)
	plain.entry.AdminCount = true
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "x-Passw0rd!"}, provapi.CodePrivileged)
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodePrivileged)
	if len(e.dir.applied) != 0 {
		t.Fatal("a write reached the directory")
	}
}

func TestNotAUser(t *testing.T) {
	e := newEnv(t, "")
	pc := e.dir.addUser("CN=PC1,"+people, "pc1$", "", false, "top", "person", "organizationalPerson", "user", "computer")
	grp := e.dir.addUser("CN=G1,"+people, "g1", "", false, "top", "group")
	for _, o := range []*fakeObj{pc, grp} {
		e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: o.entry.SID.String(), Purpose: "invite"}, provapi.CodeNotFound)
		e.refused(provapi.OpUserCheck, admin, &provapi.UserCheckParams{SID: o.entry.SID.String()}, provapi.CodeNotFound)
	}
	e.refused(provapi.OpUserCheck, admin, &provapi.UserCheckParams{SID: "S-1-5-21-9-9-9-9999"}, provapi.CodeNotFound)
}

func TestCeilings(t *testing.T) {
	e := newEnv(t, `
[limits]
token_issues_per_hour = 2
password_sets_per_hour = 1
enables_per_hour = 0
[tokens]
per_user_per_day = 10
`)
	u1 := e.dir.addUser("CN=C1,"+people, "c1", "", true)
	u2 := e.dir.addUser("CN=C2,"+people, "c2", "", true)
	t1 := e.issue(u1, "invite")
	t2 := e.issue(u2, "invite")
	e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u1.entry.SID.String(), Purpose: "invite"}, provapi.CodeRateLimited)

	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: t1.Token, NewPassword: "P4ssword-one"}, nil)
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: t2.Token, NewPassword: "P4ssword-two"}, provapi.CodeRateLimited)
	// enables_per_hour = 0 refuses every enable.
	e.refused(provapi.OpInviteComplete, admin, &provapi.InviteCompleteParams{Token: t1.Token}, provapi.CodeRateLimited)

	// The window slides: an hour later the ceilings allow again.
	e.clk.add(61 * time.Minute)
	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: t2.Token, NewPassword: "P4ssword-two"}, nil)
	if !strings.Contains(e.logs.String(), "hourly ceiling reached") {
		t.Fatal("ceiling not logged")
	}
	var st provapi.StatusResult
	e.ok(provapi.OpStatus, nil, &st)
	if st.Limits.PasswordSets.Used != 1 || st.Limits.PasswordSets.Ceiling != 1 || st.Limits.Enables.Ceiling != 0 {
		t.Fatalf("status limits %+v", st.Limits)
	}
}

func TestPerUserDailyLimit(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=D,"+people, "d", "", false)
	for range 3 {
		e.issue(u, "reset")
	}
	e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: "reset"}, provapi.CodeRateLimited)
	e.clk.add(24*time.Hour + time.Second)
	e.issue(u, "reset")
}

func TestStaleRevokedExpired(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=S,"+people, "s", "", false)

	// pwdLastSet changed after issue: stale, and the token is revoked.
	tok := e.issue(u, "reset")
	u.entry.PwdLastSet += 10
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeStale)
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeRevoked)

	// objectGUID changed (account deleted and re-created with the SID
	// reused is impossible in AD, but the binding is checked anyway).
	tok = e.issue(u, "reset")
	u.entry.GUID[0] ^= 0xff
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, provapi.CodeStale)
	u.entry.GUID[0] ^= 0xff

	// Revoked by an administrator.
	tok = e.issue(u, "invite")
	var rv provapi.TokenRevokeResult
	e.ok(provapi.OpTokenRevoke, &provapi.TokenRevokeParams{SID: u.entry.SID.String(), Reason: "admin"}, &rv)
	if rv.Revoked != 1 {
		t.Fatalf("revoked %d", rv.Revoked)
	}
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, provapi.CodeRevoked)

	// Expired.
	e.clk.add(25 * time.Hour) // a new day for the per-user limit
	tok = e.issue(u, "reset")
	e.clk.add(31 * time.Minute)
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeExpired)
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: tok.Token}, provapi.CodeExpired)

	// Unknown token.
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: strings.Repeat("A", 43)}, provapi.CodeNotFound)
	if len(e.dir.applied) != 0 {
		t.Fatal("a write reached the directory")
	}
}

func TestSupersede(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Sup,"+people, "sup", "", true)
	first := e.issue(u, "invite")
	second := e.issue(u, "invite")
	e.refused(provapi.OpTokenCheck, admin, &provapi.TokenCheckParams{Token: first.Token}, provapi.CodeRevoked)
	e.ok(provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: second.Token}, nil)
	var list []provapi.TokenInfo
	e.ok(provapi.OpTokenList, &provapi.TokenListParams{SID: u.entry.SID.String()}, &list)
	if len(list) != 2 || list[0].TokenID != second.TokenID || list[0].State != "open" || list[1].State != "revoked" || list[0].IssuedBy != admin.String() {
		t.Fatalf("list %+v", list)
	}
	var r provapi.UserResult
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.entry.SID.String()}, &r)
	if len(r.PendingTokens) != 1 || r.PendingTokens[0].Purpose != "invite" {
		t.Fatalf("pending %+v", r.PendingTokens)
	}
}

func TestCompleteWindow(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=W,"+people, "w", "", true)
	tok := e.issue(u, "invite")
	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, nil)
	e.clk.add(31 * time.Minute)
	e.refused(provapi.OpInviteComplete, admin, &provapi.InviteCompleteParams{Token: tok.Token}, provapi.CodeExpired)
	got, _ := e.dir.Get(context.Background(), u.entry.DN)
	if got.Enabled() {
		t.Fatal("enabled after the window")
	}
}

func TestInviteNeverReenablesAdminDisable(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=E,"+people, "e", "", false) // enabled at issue
	tok := e.issue(u, "invite")
	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, nil)
	u.entry.UAC |= ad.UACAccountDisable // an administrator disables it
	e.refused(provapi.OpInviteComplete, admin, &provapi.InviteCompleteParams{Token: tok.Token}, provapi.CodeStale)
	got, _ := e.dir.Get(context.Background(), u.entry.DN)
	if got.Enabled() {
		t.Fatal("re-enabled an account an administrator disabled")
	}
}

func TestPasswordPolicyMapping(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=P,"+people, "p", "", false)
	for msg, reason := range map[string]string{
		"check_password_restrictions: the password is too short. It should be equal or longer than 7 characters!": provapi.ReasonTooShort,
		"check_password_restrictions: the password does not meet the complexity criteria!":                        provapi.ReasonComplexity,
		"check_password_restrictions: the password was already used (in history)!":                                provapi.ReasonHistory,
		"check_password_restrictions: password is too young to change!":                                           provapi.ReasonTooYoung,
		"something else": provapi.ReasonOther,
	} {
		tok := e.issue(u, "reset")
		e.dir.applyErr = fmt.Errorf("%w: %w", ad.ErrPasswordPolicy, errors.New("0000052D: Constraint violation - "+msg))
		pe := e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "weak"}, provapi.CodePasswordPolicy)
		if pe.Reason != reason {
			t.Errorf("%q: reason %q, want %q", msg, pe.Reason, reason)
		}
		// A refused password leaves the token usable.
		e.ok(provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: tok.Token}, nil)
		e.clk.add(25 * time.Hour)
	}
	tok := e.issue(u, "reset")
	e.dir.applyErr = fmt.Errorf("%w: insufficient access", ad.ErrAccessDenied)
	e.refused(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, provapi.CodeDirectory)
}

func TestUserFind(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Fin,"+people, "fin", "fin@example.com", false)
	for _, q := range []string{"fin", "FIN", "fin@example.com"} {
		var r provapi.UserResult
		e.ok(provapi.OpUserFind, &provapi.UserFindParams{UsernameOrMail: q}, &r)
		if r.SID != u.entry.SID.String() || !r.InScope || r.Privileged || !r.Enabled {
			t.Fatalf("%s: %+v", q, r)
		}
	}
	e.refused(provapi.OpUserFind, admin, &provapi.UserFindParams{UsernameOrMail: "nobody"}, provapi.CodeNotFound)
	if ev := e.lastAudit(); strings.Contains(ev.Detail, "nobody") || !strings.Contains(ev.Detail, "identifier ") {
		t.Fatalf("the identifier must be audited as a digest only: %q", ev.Detail)
	}
	// Two accounts with the same mail: no single match.
	e.dir.addUser("CN=Fin2,"+people, "fin2", "fin@example.com", false)
	e.refused(provapi.OpUserFind, admin, &provapi.UserFindParams{UsernameOrMail: "fin@example.com"}, provapi.CodeNotFound)
	// A computer never matches.
	e.dir.addUser("CN=PC,"+people, "pc$", "pc@example.com", false, "user", "computer")
	e.refused(provapi.OpUserFind, admin, &provapi.UserFindParams{UsernameOrMail: "pc@example.com"}, provapi.CodeNotFound)
}

func TestIndexCache(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=I,"+people, "i", "", false)
	check := func() {
		e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.entry.SID.String()}, nil)
	}
	check()
	check()
	if e.dir.builds != 1 {
		t.Fatalf("builds %d, want 1 (cached)", e.dir.builds)
	}
	e.clk.add(61 * time.Second)
	check()
	if e.dir.builds != 2 {
		t.Fatalf("builds %d, want 2 (expired)", e.dir.builds)
	}
	// A privilege added in the directory is seen after the cache age.
	e.dir.priv[u.entry.SID.String()] = []privilege.Reason{{Kind: privilege.KindGroup}}
	e.clk.add(61 * time.Second)
	var r provapi.UserResult
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.entry.SID.String()}, &r)
	if !r.Privileged {
		t.Fatal("rebuilt index not used")
	}
	// A failed build refuses (never acts without an index).
	e.dir.readErr = errors.New("ldap down")
	e.clk.add(61 * time.Second)
	e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: "reset"}, provapi.CodeDirectory)
}

func TestProtocolRefusals(t *testing.T) {
	e := newEnv(t, "")
	base := func() provapi.Request {
		return provapi.Request{Version: provapi.ProtocolVersion, ID: "req-12345678", Op: provapi.OpStatus, Actor: admin}
	}
	cases := map[string]func(r *provapi.Request){
		"unknown op": func(r *provapi.Request) { r.Op = "user.delete" },
		"unknown field": func(r *provapi.Request) {
			r.Op, r.Params = provapi.OpUserCheck, json.RawMessage(`{"sid":"S-1-5-21-1-2-3-4","dn":"x"}`)
		},
		"bad version":     func(r *provapi.Request) { r.Version = 2 },
		"bad id":          func(r *provapi.Request) { r.ID = "x" },
		"no actor":        func(r *provapi.Request) { r.Actor = provapi.Actor{} },
		"bad actor sid":   func(r *provapi.Request) { r.Actor.SID = "S-1-x" },
		"public with sid": func(r *provapi.Request) { r.Actor.User = provapi.PublicUser },
		"control chars":   func(r *provapi.Request) { r.Actor.User = "a\nb" },
		"bad token":       func(r *provapi.Request) { r.Op, r.Params = provapi.OpTokenCheck, json.RawMessage(`{"token":"short"}`) },
		"bad purpose": func(r *provapi.Request) {
			r.Op, r.Params = provapi.OpTokenIssue, json.RawMessage(`{"sid":"S-1-5-21-1","purpose":"admin"}`)
		},
		"trailing": func(r *provapi.Request) {
			r.Op, r.Params = provapi.OpUserCheck, json.RawMessage(`{"sid":"S-1-5-21-1-2"} {}`)
		},
		"NUL password": func(r *provapi.Request) {
			r.Op, r.Params = provapi.OpPasswordSet, json.RawMessage(`{"token":"`+strings.Repeat("A", 43)+`","new_password":"a\u0000b"}`)
		},
	}
	for name, mod := range cases {
		req := base()
		mod(&req)
		resp := e.svc.Handle(context.Background(), req)
		if resp.OK || resp.Error.Code != provapi.CodeInvalidParams {
			t.Errorf("%s: %+v", name, resp)
		}
		if ev := e.lastAudit(); ev.Result != "invalid_params" {
			t.Errorf("%s: refusal not audited: %+v", name, ev)
		}
	}
	// Successful reads are not audited; refusals and mutations are.
	before, _ := e.st.ListAudit(context.Background(), 1)
	e.ok(provapi.OpStatus, nil, nil)
	after, _ := e.st.ListAudit(context.Background(), 1)
	if before[0].Seq != after[0].Seq {
		t.Fatal("a successful read was audited")
	}
}

func TestAuditChainOverService(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Au,"+people, "au", "", true)
	tok := e.issue(u, "invite")
	e.ok(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: "Pw-123456789"}, nil)
	e.ok(provapi.OpInviteComplete, &provapi.InviteCompleteParams{Token: tok.Token}, nil)
	res, err := e.st.VerifyAudit(context.Background())
	if err != nil || res.BrokenAt != 0 || res.Rows != 3 {
		t.Fatalf("verify %+v %v", res, err)
	}
	ev, _ := e.st.ListAudit(context.Background(), 3)
	ops := []string{ev[2].Op, ev[1].Op, ev[0].Op}
	if strings.Join(ops, ",") != "token.issue,password.set,invite.complete" {
		t.Fatalf("ops %v", ops)
	}
	for _, x := range ev {
		if x.TokenID != tok.TokenID || x.TargetSAM != "au" || x.Result != "ok" || x.Actor != admin.String() || x.Reference != "ref-1" {
			t.Fatalf("audit row %+v", x)
		}
	}
}

func TestConcurrentPasswordSetUsesTokenOnce(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Race,"+people, "race", "", false)
	tok := e.issue(u, "reset")
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0
	for i := range 8 {
		wg.Go(func() {
			resp := e.do(provapi.OpPasswordSet, admin, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: fmt.Sprintf("Pw-12345678%d", i)})
			if resp.OK {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if okCount != 1 || len(e.dir.applied) != 1 {
		t.Fatalf("ok %d, writes %d", okCount, len(e.dir.applied))
	}
}

func mustSID(s string) sid.SID { return sid.MustParse(s) }
