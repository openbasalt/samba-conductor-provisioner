package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `
[domain]
realm = "EXAMPLE.COM"
ca_file = "/etc/conductor-provisioner/domain-ca.pem"
[account]
username = "svc-conductor-prov"
[scope]
ous = ["OU=People,OU=Lab,DC=example,DC=com"]
`

func TestDefaults(t *testing.T) {
	c, err := Parse(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tokens.InviteHours != 72 || c.Tokens.ResetMinutes != 30 || c.Limits.EnablesPerHour != 200 ||
		c.Privileged.IndexCacheSeconds != 60 || c.API.Socket != "/run/conductor-provisioner/api.sock" ||
		c.API.AllowedUsers[0] != "conductor" || c.Domain.SimpleBindFallback {
		t.Fatalf("%+v", c)
	}
	if c.Limits.CreatesPerHour != 200 || c.Limits.UpdatesPerHour != 200 || c.Limits.MovesPerHour != 200 || c.Limits.DisablesPerHour != 200 {
		t.Fatalf("plan ceilings %+v", c.Limits)
	}
	if got := c.ScopesOf("OU=Q,OU=People,OU=Lab,DC=example,DC=com"); len(got) != 1 || len(c.ScopesOf("ou=people, ou=lab,dc=example,dc=com")) != 1 ||
		len(c.ScopesOf("OU=Lab,DC=example,DC=com")) != 0 || len(c.ScopesOf("not a dn")) != 0 {
		t.Fatal("ScopesOf")
	}
	if c.Scope.OUs[0] != "ou=people,ou=lab,dc=example,dc=com" {
		t.Fatalf("not normalized: %q", c.Scope.OUs[0])
	}
	if !c.InScope("CN=x,OU=People,OU=Lab,DC=Example,DC=COM") || c.InScope("OU=People,OU=Lab,DC=example,DC=com") {
		t.Fatal("InScope")
	}
}

func TestExampleFileLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "provisioner.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Account.Username != "svc-conductor-prov" {
		t.Fatal(c.Account.Username)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":          minimal + "\n[tokens]\ninvite_days = 3\n",
		"unknown section":      minimal + "\n[extra]\nx = 1\n",
		"domain head":          strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "DC=example,DC=com", 1),
		"users container":      strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "CN=Users,DC=example,DC=com", 1),
		"builtin":              strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "CN=Builtin,DC=example,DC=com", 1),
		"system":               strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "CN=System,DC=example,DC=com", 1),
		"below system":         strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "OU=X,CN=System,DC=example,DC=com", 1),
		"domain controllers":   strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "OU=Domain Controllers,DC=example,DC=com", 1),
		"dc ou case":           strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "ou=domain controllers,dc=EXAMPLE,dc=com", 1),
		"below dc ou":          strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "OU=Sub,OU=Domain Controllers,DC=example,DC=com", 1),
		"other domain":         strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "OU=People,DC=other,DC=com", 1),
		"not a DN":             strings.Replace(minimal, "OU=People,OU=Lab,DC=example,DC=com", "People", 1),
		"duplicate":            strings.Replace(minimal, `"OU=People,OU=Lab,DC=example,DC=com"`, `"OU=People,OU=Lab,DC=example,DC=com", "ou=people, ou=lab,dc=example,dc=com"`, 1),
		"relative ca":          strings.Replace(minimal, "/etc/conductor-provisioner/domain-ca.pem", "domain-ca.pem", 1),
		"bad realm":            strings.Replace(minimal, "EXAMPLE.COM", "EXAMPLE", 1),
		"bad username":         strings.Replace(minimal, "svc-conductor-prov", "svc conductor", 1),
		"invite range":         minimal + "\n[tokens]\ninvite_hours = 169\n",
		"reset range":          minimal + "\n[tokens]\nreset_minutes = 4\n",
		"cache range":          minimal + "\n[privileged]\nindex_cache_seconds = 301\n",
		"bad extra sid":        minimal + "\n[privileged]\nextra_group_sids = [\"admins\"]\n",
		"negative limit":       minimal + "\n[limits]\nenables_per_hour = -1\n",
		"negative creates":     minimal + "\n[limits]\ncreates_per_hour = -1\n",
		"huge updates":         minimal + "\n[limits]\nupdates_per_hour = 100001\n",
		"negative moves":       minimal + "\n[limits]\nmoves_per_hour = -5\n",
		"negative disables":    minimal + "\n[limits]\ndisables_per_hour = -1\n",
		"relative db":          minimal + "\n[state]\ndatabase = \"p.db\"\n",
		"relative socket":      minimal + "\n[api]\nsocket = \"api.sock\"\n",
		"no allowed users":     minimal + "\n[api]\nallowed_users = []\n",
		"root uid":             minimal + "\n[api]\nallowed_uids = [0]\n",
		"bad dns server":       minimal + "\n[domain.x]\n",
		"bad dc host":          strings.Replace(minimal, "[account]", "preferred = [\"dc 1\"]\n[account]", 1),
		"bad dns server value": strings.Replace(minimal, "[account]", "dns_servers = [\"dns.example.com\"]\n[account]", 1),
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Zero ceilings and an empty scope are valid (they refuse everything).
	ok := strings.Replace(minimal, `ous = ["OU=People,OU=Lab,DC=example,DC=com"]`, "ous = []", 1) + "\n[limits]\ntoken_issues_per_hour = 0\n"
	if _, err := Parse(ok); err != nil {
		t.Fatal(err)
	}
}

func TestLoadUnknownKeysFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.toml")
	if err := os.WriteFile(p, []byte(minimal+"\n[scope]\n"), 0o600); err == nil {
		if _, err := Load(p); err == nil {
			t.Fatal("duplicate table accepted")
		}
	}
}
