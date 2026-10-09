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
// The test creates a disabled account in the scope OU with the
// administrator, then issues an invitation, sets the password and
// completes it through the service with the delegated account, signs in
// with the new password, and deletes the account.
package labtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
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
		RootCAs: pool}
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

func TestLabInvitation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
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
`, realm, env(t, "AD_LAB_CA", ""), tomlList(strings.Split(env(t, "AD_LAB_DNS", ""), ",")),
		env(t, "PROV_LAB_ACCOUNT", "svc-conductor-prov"), scope, filepath.Join(dir, "p.db"))
	cfg, err := config.Parse(cfgText)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := secret.Seal([]byte(accountPassword), []byte(cfg.Account.Username))
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	d, err := directory.NewAD(cfg, sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st, err := store.Open(ctx, cfg.State.Database, store.AuditKey(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc, err := server.NewService(server.Options{Config: cfg, Store: st, Directory: d, Version: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, svc: svc}

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
			pe := h.call(provapi.OpTokenIssue, &provapi.TokenIssueParams{SID: u.SID.String(), Purpose: "reset"}, nil)
			if pe == nil || pe.Code != provapi.CodePrivileged {
				t.Errorf("%s: token.issue: %v", sam, pe)
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
