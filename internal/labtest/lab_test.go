//go:build lab

// The lab tests run the service against the Samba lab
// (https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md).
//
// Environment, as for the ad module's lab tests: AD_LAB_REALM, AD_LAB_DNS,
// AD_LAB_CA, AD_LAB_ADMIN_USER and AD_LAB_ADMIN_PASSWORD; plus
// PROV_LAB_ACCOUNT (default svc-conductor-prov) and
// PROV_LAB_ACCOUNT_PASSWORD for an account delegated on the scope OU as
// docs/delegation.md describes (`conductor-provisioner delegation preview`
// prints the commands), and optionally PROV_LAB_SCOPE_OU (default
// OU=People,OU=Lab,<domain>). The seeded lab has lab.admin and
// helpdesk.user privileged and normal.user not.
//
// TestLabInvitation creates a disabled account in the scope OU with the
// administrator, then issues an invitation, sets the password and
// completes it through the service with the delegated account, signs in
// with the new password, and deletes the account.
//
// TestLabGoogleFirst needs the delegation with the Google-first rights
// (`conductor-provisioner delegation preview --google-first`) and a
// quarantine OU below the scope OU (PROV_LAB_QUARANTINE_OU, default
// OU=Quarantine,<scope OU>; created by the administrator when missing).
// Through the service it creates a Google-first account, updates it,
// disables it and moves it to the quarantine OU, re-enables it and moves
// it back; it checks the refusals for privileged accounts (out of scope,
// and a Google-first account the administrator made a member of Domain
// Admins), then deletes the account with the administrator.
package labtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/internal/secret"
	"github.com/openbasalt/samba-conductor-provisioner/internal/server"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

func env(t *testing.T, name, def string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		if def == "" {
			t.Skipf("%s not set", name)
		}
		return def
	}
	return v
}

func adConfig(t *testing.T) ad.Config {
	t.Helper()
	pemData, err := os.ReadFile(env(t, "AD_LAB_CA", ""))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ad.CertPoolFromPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return ad.Config{Realm: env(t, "AD_LAB_REALM", ""), Resolver: ad.NewDNSResolver(strings.Split(env(t, "AD_LAB_DNS", ""), ",")...),
		RootCAs: pool, Preferred: []string{labDC(t)}}
}

// labDC is the DC both the administrator and the service use, so the test
// does not depend on replication between the two DCs (PROV_LAB_DC, default
// dc1 of the realm).
func labDC(t *testing.T) string {
	t.Helper()
	return env(t, "PROV_LAB_DC", "dc1."+strings.ToLower(env(t, "AD_LAB_REALM", "")))
}

func adminConn(t *testing.T, ctx context.Context) *ad.Conn {
	t.Helper()
	cfg := adConfig(t)
	s, err := ad.SignIn(ctx, cfg, env(t, "AD_LAB_ADMIN_USER", ""), env(t, "AD_LAB_ADMIN_PASSWORD", ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	c, err := ad.Connect(ctx, cfg, ad.KerberosAuth(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "Pv-" + hex.EncodeToString(b) + "!a"
}

type harness struct {
	t   *testing.T
	svc *server.Service
}

var labActor = provapi.Actor{User: "lab.admin", SID: "S-1-5-21-1-1-1-500", Session: "lab-session", IP: "192.0.2.1"}

func (h *harness) call(op provapi.Op, p provapi.Params, out any) *provapi.Error {
	h.t.Helper()
	raw, _ := json.Marshal(p)
	resp := h.svc.Handle(context.Background(), provapi.Request{Version: provapi.ProtocolVersion, ID: provapi.NewRequestID(),
		Op: op, Actor: labActor, Params: raw, SentAt: time.Now()})
	if !resp.OK {
		return resp.Error
	}
	if out != nil {
		if err := provapi.DecodeResult(resp, out); err != nil {
			h.t.Fatal(err)
		}
	}
	return nil
}

// labService is the service under test with the delegated account, and
// the administrator's connection that prepares and checks the directory.
type labService struct {
	h     *harness
	admin *ad.Conn
	st    *store.Store
	scope string
	realm string
}

func newLabService(t *testing.T, ctx context.Context) *labService {
	t.Helper()
	accountPassword := env(t, "PROV_LAB_ACCOUNT_PASSWORD", "")
	admin := adminConn(t, ctx)
	scope := env(t, "PROV_LAB_SCOPE_OU", "OU=People,OU=Lab,"+admin.BaseDN())
	realm := env(t, "AD_LAB_REALM", "")

	dir := t.TempDir()
	cfgText := fmt.Sprintf(`
[domain]
realm = %q
ca_file = %q
dns_servers = %s
preferred = [%q]
[account]
username = %q
[scope]
ous = [%q]
[privileged]
index_cache_seconds = 0
[state]
database = %q
[api]
allowed_uids = [1001]
`, realm, env(t, "AD_LAB_CA", ""), tomlList(strings.Split(env(t, "AD_LAB_DNS", ""), ",")), labDC(t),
		env(t, "PROV_LAB_ACCOUNT", "svc-conductor-prov"), scope, filepath.Join(dir, "p.db"))
	cfg, err := config.Parse(cfgText)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := secret.Seal([]byte(accountPassword), []byte(cfg.Account.Username))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sealed.Close)
	d, err := directory.NewAD(cfg, sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	st, err := store.Open(ctx, cfg.State.Database, store.AuditKey(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc, err := server.NewService(server.Options{Config: cfg, Store: st, Directory: d, Version: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	return &labService{h: &harness{t: t, svc: svc}, admin: admin, st: st, scope: scope, realm: realm}
}

func TestLabInvitation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ls := newLabService(t, ctx)
	h, admin, st, scope, realm := ls.h, ls.admin, ls.st, ls.scope, ls.realm

	// Privileged accounts are refused, an ordinary one is not.
	for sam, privileged := range map[string]bool{"lab.admin": true, "helpdesk.user": true, "normal.user": false} {
		u, err := admin.FindUser(ctx, sam)
		if err != nil {
			t.Fatalf("%s: %v", sam, err)
		}
		var r provapi.UserResult
		if pe := h.call(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.SID.String()}, &r); pe != nil {
			t.Fatalf("%s: %v", sam, pe)
		}
		if r.Privileged != privileged {
			t.Errorf("%s: privileged=%v (%v), want %v", sam, r.Privileged, r.PrivilegedReasons, privileged)
		}
		if privileged {
			// Out of scope is checked first; inside the scope the refusal
			// must name the privilege.
			want := provapi.CodeOutOfScope
			if r.InScope {
				want = provapi.CodePrivileged
			}
			pe := h.call(provapi.OpTokenIssue, &provapi.TokenIssueParams{SID: u.SID.String(), Purpose: "reset"}, nil)
			if pe == nil || pe.Code != want {
				t.Errorf("%s: token.issue: %v, want %s", sam, pe, want)
			}
		}
	}

	// A new, disabled account in the scope OU.
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	sam := "prov-lab-" + hex.EncodeToString(b)
	op, err := ad.CreateUser(ad.NewUser{ParentDN: scope, CN: sam, SAMAccountName: sam,
		UserPrincipalName: sam + "@" + strings.ToLower(realm), Mail: sam + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Apply(ctx, op); err != nil {
		t.Fatal(err)
	}
	u, err := admin.FindUser(ctx, sam)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if del, err := ad.DeleteObject(u.DN); err == nil {
			_ = admin.Apply(context.Background(), del)
		}
	})

	var found provapi.UserResult
	if pe := h.call(provapi.OpUserFind, &provapi.UserFindParams{UsernameOrMail: sam + "@example.com"}, &found); pe != nil {
		t.Fatal(pe)
	}
	if found.SID != u.SID.String() || !found.InScope || found.Privileged || found.Enabled {
		t.Fatalf("user.find %+v", found)
	}
	var tok provapi.TokenIssueResult
	if pe := h.call(provapi.OpTokenIssue, &provapi.TokenIssueParams{SID: u.SID.String(), Purpose: "invite"}, &tok); pe != nil {
		t.Fatal(pe)
	}
	pw := randomPassword()
	if pe := h.call(provapi.OpPasswordSet, &provapi.PasswordSetParams{Token: tok.Token, NewPassword: pw}, nil); pe != nil {
		t.Fatal(pe)
	}
	if pe := h.call(provapi.OpInviteComplete, &provapi.InviteCompleteParams{Token: tok.Token}, nil); pe != nil {
		t.Fatal(pe)
	}
	after, err := admin.GetUser(ctx, u.DN)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Enabled() {
		t.Fatal("the invited account is not enabled")
	}
	s, err := ad.SignIn(ctx, adConfig(t), sam, pw)
	if err != nil {
		t.Fatalf("sign-in with the new password: %v", err)
	}
	s.Close()
	if pe := h.call(provapi.OpTokenCheck, &provapi.TokenCheckParams{Token: tok.Token}, nil); pe == nil || pe.Code != provapi.CodeUsed {
		t.Fatalf("used token: %v", pe)
	}
	if res, err := st.VerifyAudit(ctx); err != nil || res.BrokenAt != 0 {
		t.Fatalf("audit %+v %v", res, err)
	}
}

func tomlList(v []string) string {
	q := make([]string, 0, len(v))
	for _, s := range v {
		q = append(q, fmt.Sprintf("%q", s))
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func TestLabGoogleFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ls := newLabService(t, ctx)
	h, admin := ls.h, ls.admin
	quarantine := env(t, "PROV_LAB_QUARANTINE_OU", "OU=Quarantine,"+ls.scope)
	qParent, qName, err := escape.ParentDN(quarantine)
	if err != nil {
		t.Fatalf("PROV_LAB_QUARANTINE_OU: %v", err)
	}
	if op, err := ad.CreateOU(ad.NewOU{ParentDN: qParent, Name: qName}); err == nil {
		if err := admin.Apply(ctx, op); err == nil {
			t.Cleanup(func() {
				if del, err := ad.DeleteObject(quarantine); err == nil {
					_ = admin.Apply(context.Background(), del)
				}
			})
		} else if !errors.Is(err, ad.ErrAlreadyExists) {
			t.Fatalf("quarantine OU: %v", err)
		}
	}

	b := make([]byte, 3)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	id := fmt.Sprintf("%d", 100000000000+int(b[0])<<16+int(b[1])<<8+int(b[2]))
	marker := provapi.Marker(id)
	sam := "gf-lab-" + suffix
	create := &provapi.UserCreateParams{ScopeOU: ls.scope, SAM: sam, UPN: sam + "@" + strings.ToLower(ls.realm),
		CN: "GF Lab " + suffix, Mail: sam + "@example.com", GivenName: "Gf", Sn: "Lab", DisplayName: "Gf Lab " + suffix,
		Fields: map[string]string{"title": "Tester", "employeeID": "L-" + suffix}, Marker: marker, Reference: "lab-run"}
	var created provapi.UserCreateResult
	if pe := h.call(provapi.OpUserCreate, create, &created); pe != nil {
		t.Fatalf("user.create: %v", pe)
	}
	userSID, err := sid.Parse(created.SID)
	if err != nil {
		t.Fatalf("user.create result %+v: %v", created, err)
	}
	t.Cleanup(func() {
		if dn, err := admin.FindBySID(context.Background(), userSID); err == nil {
			if del, err := ad.DeleteObject(dn); err == nil {
				_ = admin.Apply(context.Background(), del)
			}
		}
	})
	read := func() *ldap.Entry {
		t.Helper()
		dn, err := admin.FindBySID(ctx, userSID)
		if err != nil {
			t.Fatal(err)
		}
		e, err := admin.Get(ctx, dn, "distinguishedName", "userAccountControl", "pwdLastSet", "sn", "title", "employeeID",
			"proxyAddresses", provapi.MarkerAttribute)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	disabled := func(e *ldap.Entry) bool {
		v, _ := strconv.ParseUint(e.GetAttributeValue("userAccountControl"), 10, 32)
		return ad.UAC(v).Has(ad.UACAccountDisable)
	}
	e := read()
	if !disabled(e) || e.GetAttributeValue("pwdLastSet") != "0" || e.GetAttributeValue(provapi.MarkerAttribute) != marker ||
		e.GetAttributeValue("title") != "Tester" {
		t.Fatalf("created account: dn %s uac %s pwdLastSet %s marker %q title %q", e.DN, e.GetAttributeValue("userAccountControl"),
			e.GetAttributeValue("pwdLastSet"), e.GetAttributeValue(provapi.MarkerAttribute), e.GetAttributeValue("title"))
	}
	// The same values again are refused: the account exists.
	if pe := h.call(provapi.OpUserCreate, create, nil); pe == nil || pe.Code != provapi.CodeExists {
		t.Fatalf("second user.create: %v", pe)
	}

	// Update the Google-owned attributes.
	upd := &provapi.UserUpdateParams{SID: created.SID, Marker: marker, Reference: "lab-run", Changes: []provapi.UserChange{
		{Attr: "sn", Before: "Lab", After: "Lab Updated"},
		{Attr: "employeeID", Before: "L-" + suffix, After: ""},
		{Attr: "proxyAddresses", Before: "", After: provapi.JoinValues([]string{"smtp:" + sam + "-old@example.com"})},
	}}
	if pe := h.call(provapi.OpUserUpdate, upd, nil); pe != nil {
		t.Fatalf("user.update: %v", pe)
	}
	e = read()
	if e.GetAttributeValue("sn") != "Lab Updated" || e.GetAttributeValue("employeeID") != "" ||
		len(e.GetAttributeValues("proxyAddresses")) != 1 {
		t.Fatalf("updated account: sn %q employeeID %q proxyAddresses %v", e.GetAttributeValue("sn"),
			e.GetAttributeValue("employeeID"), e.GetAttributeValues("proxyAddresses"))
	}
	// The same update again: the current values are no longer the before
	// values.
	if pe := h.call(provapi.OpUserUpdate, upd, nil); pe == nil || pe.Code != provapi.CodeConflict {
		t.Fatalf("second user.update: %v", pe)
	}

	// Enable (as an invitation would), then disable and quarantine.
	var w provapi.UserWriteResult
	if pe := h.call(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: created.SID, Enabled: true, Marker: marker}, &w); pe != nil || !w.Enabled {
		t.Fatalf("enable: %v %+v", pe, w)
	}
	if pe := h.call(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: created.SID, Enabled: false, Marker: marker}, &w); pe != nil || w.Enabled {
		t.Fatalf("disable: %v %+v", pe, w)
	}
	if pe := h.call(provapi.OpUserMove, &provapi.UserMoveParams{SID: created.SID, ToOU: quarantine, Marker: marker}, &w); pe != nil {
		t.Fatalf("move to quarantine: %v", pe)
	}
	if e = read(); !disabled(e) || !escape.EqualDN(parentOf(t, e.DN), quarantine) {
		t.Fatalf("quarantined account: %s disabled=%v", e.DN, disabled(e))
	}
	// Back: re-enable and move to the scope OU.
	if pe := h.call(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: created.SID, Enabled: true, Marker: marker}, nil); pe != nil {
		t.Fatalf("re-enable: %v", pe)
	}
	if pe := h.call(provapi.OpUserMove, &provapi.UserMoveParams{SID: created.SID, ToOU: ls.scope, Marker: marker}, nil); pe != nil {
		t.Fatalf("move back: %v", pe)
	}
	if e = read(); disabled(e) || !escape.EqualDN(parentOf(t, e.DN), ls.scope) {
		t.Fatalf("restored account: %s disabled=%v", e.DN, disabled(e))
	}
	// Another marker is refused.
	if pe := h.call(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: created.SID, Enabled: false,
		Marker: provapi.Marker(id + "0")}, nil); pe == nil || pe.Code != provapi.CodeMarkerMismatch {
		t.Fatalf("marker mismatch: %v", pe)
	}

	// Privileged accounts: the seeded administrators (out of scope first),
	// and the new account once an administrator adds it to Domain Admins.
	for _, name := range []string{"lab.admin", "helpdesk.user"} {
		u, err := admin.FindUser(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var r provapi.UserResult
		if pe := h.call(provapi.OpUserCheck, &provapi.UserCheckParams{SID: u.SID.String()}, &r); pe != nil {
			t.Fatalf("%s: %v", name, pe)
		}
		want := provapi.CodeOutOfScope
		if r.InScope {
			want = provapi.CodePrivileged
		}
		if pe := h.call(provapi.OpUserSetEnabled, &provapi.UserSetEnabledParams{SID: u.SID.String(), Enabled: false, Marker: marker}, nil); pe == nil || pe.Code != want {
			t.Errorf("%s: user.set_enabled: %v, want %s", name, pe, want)
		}
	}
	da, err := admin.FindGroup(ctx, "Domain Admins")
	if err != nil {
		t.Fatal(err)
	}
	dn := read().DN
	add, err := ad.AddGroupMember(da.DN, dn)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Apply(ctx, add); err != nil {
		t.Fatal(err)
	}
	removed := false
	removeDA := func() {
		if removed {
			return
		}
		if rm, err := ad.RemoveGroupMember(da.DN, dn); err == nil {
			if err := admin.Apply(context.Background(), rm); err == nil {
				removed = true
			}
		}
	}
	t.Cleanup(removeDA)
	for op, p := range map[provapi.Op]provapi.Params{
		provapi.OpUserSetEnabled: &provapi.UserSetEnabledParams{SID: created.SID, Enabled: false, Marker: marker},
		provapi.OpUserMove:       &provapi.UserMoveParams{SID: created.SID, ToOU: quarantine, Marker: marker},
		provapi.OpUserUpdate: &provapi.UserUpdateParams{SID: created.SID, Marker: marker,
			Changes: []provapi.UserChange{{Attr: "sn", Before: "Lab Updated", After: "Lab"}}},
	} {
		if pe := h.call(op, p, nil); pe == nil || pe.Code != provapi.CodePrivileged {
			t.Errorf("%s on a Domain Admins member: %v, want privileged", op, pe)
		}
	}
	if e = read(); disabled(e) || e.GetAttributeValue("sn") != "Lab Updated" {
		t.Fatal("a privileged account was changed")
	}
	removeDA()
	if res, err := ls.st.VerifyAudit(ctx); err != nil || res.BrokenAt != 0 {
		t.Fatalf("audit %+v %v", res, err)
	}
}

// parentOf returns the parent DN of dn.
func parentOf(t *testing.T, dn string) string {
	t.Helper()
	parent, _, err := escape.ParentDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	return parent
}
