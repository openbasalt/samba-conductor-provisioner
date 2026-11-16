package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// TestProtectedSetMatchesConductor: the index gets conductor's protected
// set on top of the privilege package's own (Enterprise Read-only DCs,
// Key Admins, Enterprise Key Admins, Replicator, this domain's DnsAdmins
// by name, the configured extra groups), and members of each are refused.
func TestProtectedSetMatchesConductor(t *testing.T) {
	e := newEnv(t, `
[privileged]
extra_group_sids = ["S-1-5-21-1-2-3-4000"]
`)
	dns := e.dir.addUser("CN=DnsAdmins,CN=Users,DC=example,DC=com", "DnsAdmins", "", false, "top", "group")
	if _, err := e.svc.index(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"S-1-5-21-1-2-3-4000", "S-1-5-21-1-2-3-498", "S-1-5-21-1-2-3-526", "S-1-5-21-1-2-3-527", "S-1-5-32-552",
		dns.entry.SID.String()}
	got := map[string]bool{}
	for _, g := range e.dir.extraGroups {
		got[g.String()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s not in the index's extra groups %v", w, e.dir.extraGroups)
		}
	}
	if len(e.dir.extraGroups) != len(want) {
		t.Errorf("extra groups %v", e.dir.extraGroups)
	}
	for i, g := range []sid.SID{mustSID("S-1-5-21-1-2-3-498"), mustSID("S-1-5-21-1-2-3-526"), mustSID("S-1-5-21-1-2-3-527"),
		mustSID("S-1-5-32-552"), dns.entry.SID} {
		u := e.dir.addUser("CN=M"+string(rune('a'+i))+","+people, "m"+string(rune('a'+i)), "", false)
		u.groups = append(u.groups, g)
		e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: "reset"}, provapi.CodePrivileged)
	}
}

// TestDNSAdminsOtherDomain: an object named DnsAdmins with another
// domain's SID is not this domain's DnsAdmins.
func TestDNSAdminsOtherDomain(t *testing.T) {
	e := newEnv(t, "")
	o := e.dir.addUser("CN=DnsAdmins,CN=Users,DC=example,DC=com", "DnsAdmins", "", false, "top", "group")
	o.entry.SID = mustSID("S-1-5-21-9-9-9-1101")
	groups, err := protectedGroupSIDs(context.Background(), e.cfg, e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Equal(o.entry.SID) {
			t.Fatal("another domain's DnsAdmins taken")
		}
	}
}

// TestProtectedLookupFailsClosed: when the protected set or the scope
// sweep cannot be read, the operation is refused.
func TestProtectedLookupFailsClosed(t *testing.T) {
	e := newEnv(t, "")
	u := e.dir.addUser("CN=Plain,"+people, "plain", "", false)
	e.dir.usersBelowErr = errors.New("LDAP down")
	e.refused(provapi.OpTokenIssue, admin, &provapi.TokenIssueParams{SID: u.entry.SID.String(), Purpose: "reset"}, provapi.CodeDirectory)
	e.dir.usersBelowErr = nil
	e.dir.readErr = errors.New("LDAP down")
	if _, err := protectedGroupSIDs(context.Background(), e.cfg, e.dir); err == nil {
		t.Fatal("protected set built without the directory")
	}
}

// TestPrivilegedInScope: privileged accounts below a scope OU are listed
// (by group, nested through the index, and by adminCount), plain ones and
// those outside the scope are not; the service logs them on every index
// rebuild and audits each change of the list once.
func TestPrivilegedInScope(t *testing.T) {
	e := newEnv(t, "")
	admins := e.dir.addUser("CN=Domain Admins,CN=Users,DC=example,DC=com", "Domain Admins", "", false, "top", "group")
	e.dir.priv[admins.entry.SID.String()] = []privilege.Reason{{Kind: privilege.KindGroup, Detail: "S-1-5-21-1-2-3-512"}}
	lead := e.dir.addUser("CN=Lead,OU=Helpdesk,"+people, "lead", "", false)
	lead.groups = append(lead.groups, admins.entry.SID)
	marked := e.dir.addUser("CN=Marked,"+people, "marked", "", false)
	marked.entry.AdminCount = true
	e.dir.addUser("CN=Plain,"+people, "plain", "", false)
	out := e.dir.addUser("CN=Admin,CN=Users,DC=example,DC=com", "admin", "", false)
	out.groups = append(out.groups, admins.entry.SID)

	m, err := PrivilegedInScope(context.Background(), e.cfg, e.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m[0].SAM != "lead" || m[0].Kinds[0] != privilege.KindGroup || m[1].SAM != "marked" || m[1].Kinds[0] != privilege.KindAdminCount {
		t.Fatalf("misplaced %+v", m)
	}
	if m, err := PrivilegedInScope(context.Background(), e.cfg, e.dir, []string{"CN=Users,DC=example,DC=com"}); err != nil || len(m) != 1 || m[0].SAM != "admin" {
		t.Fatalf("explicit OU: %+v %v", m, err)
	}

	// The running service: an operation on a plain account still works,
	// the misplaced accounts are logged and audited once.
	plain := e.dir.addUser("CN=Plain2,"+people, "plain2", "", false)
	var r provapi.UserResult
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: plain.entry.SID.String()}, &r)
	builds := e.dir.builds
	e.clk.add(time.Hour) // past index_cache_seconds: rebuilt
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: plain.entry.SID.String()}, &r)
	if e.dir.builds != builds+1 {
		t.Fatal("index not rebuilt")
	}
	if !strings.Contains(e.logs.String(), "privileged account below a scope OU") {
		t.Fatalf("not logged:\n%s", e.logs.String())
	}
	if n := strings.Count(e.auditText(), "scope.check"); n != 1 {
		t.Fatalf("scope.check audited %d times:\n%s", n, e.auditText())
	}
	// Moved out: the next change is audited too.
	marked.entry.AdminCount = false
	lead.groups = nil
	e.clk.add(time.Hour)
	e.ok(provapi.OpUserCheck, &provapi.UserCheckParams{SID: plain.entry.SID.String()}, &r)
	if n := strings.Count(e.auditText(), "scope.check"); n != 1 {
		t.Fatalf("an empty list audited:\n%s", e.auditText())
	}
	if !strings.Contains(e.logs.String(), "no privileged account below the scope OUs any more") {
		t.Fatal("recovery not logged")
	}
}
