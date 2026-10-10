package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
)

func writeConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := `
[domain]
realm = "EXAMPLE.COM"
ca_file = "/etc/conductor-provisioner/domain-ca.pem"
[account]
username = "svc-conductor-prov"
[scope]
ous = ["OU=People,OU=Lab,DC=example,DC=com"]
[state]
database = "` + db + `"
[api]
socket = "` + filepath.Join(dir, "api.sock") + `"
allowed_uids = [1001]
`
	p := filepath.Join(dir, "provisioner.toml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, dir
}

func runCmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCmd("version"); code != exitOK || !strings.Contains(out, "conductor-provisioner") {
		t.Fatal(code, out)
	}
	if code, _, _ := runCmd(); code != exitUsage {
		t.Fatal(code)
	}
	if code, _, _ := runCmd("delegation", "apply", "--ou", "x"); code != exitUsage {
		t.Fatal(code)
	}
}

func TestDelegationPreview(t *testing.T) {
	cfg, _ := writeConfig(t)
	code, out, errOut := runCmd("delegation", "preview", "--config", cfg, "--ou", "OU=People,OU=Lab,DC=example,DC=com",
		"--account-sid", "S-1-5-21-1-2-3-1234")
	if code != exitOK {
		t.Fatal(code, errOut)
	}
	for _, want := range []string{
		`samba-tool dsacl set --objectdn='OU=People,OU=Lab,DC=example,DC=com' --sddl='(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)'`,
		`(OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;bf967a0a-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;bf967a68-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`samba-tool dsacl get`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "not in [scope]") {
		t.Error("configured OU reported out of scope")
	}
	if strings.Contains(out, ";CC;") || strings.Contains(out, ";SD;") || strings.Count(out, "samba-tool dsacl set") != 4 {
		t.Errorf("without --google-first only the four invitation and reset entries:\n%s", out)
	}
	// --google-first adds the plan operations' rights.
	code, out, errOut = runCmd("delegation", "preview", "--config", cfg, "--ou", "OU=People,OU=Lab,DC=example,DC=com",
		"--account-sid", "S-1-5-21-1-2-3-1234", "--google-first")
	if code != exitOK {
		t.Fatal(code, errOut)
	}
	for _, want := range []string{
		`(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;SD;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;bf96793f-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;bf967a06-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`(OA;CIIO;WP;9709eaaf-49da-4db2-908a-0446e5eab844;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-1-2-3-1234)`,
		`# Verify: the 19 entries above`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--google-first: missing %q", want)
		}
	}
	if strings.Count(out, "samba-tool dsacl set") != 19 {
		t.Errorf("--google-first: %d entries", strings.Count(out, "samba-tool dsacl set"))
	}
	// A forbidden OU is refused like a scope OU.
	if code, _, _ := runCmd("delegation", "preview", "--config", cfg, "--ou", "OU=Domain Controllers,DC=example,DC=com",
		"--account-sid", "S-1-5-21-1-2-3-1234"); code != exitUsage {
		t.Fatal(code)
	}
	// Quoting survives a quote in the DN.
	if got := shellQuote("OU=O'Brien"); got != `'OU=O'\''Brien'` {
		t.Fatal(got)
	}
}

func TestAuditVerifyAndStatus(t *testing.T) {
	cfg, dir := writeConfig(t)
	creds := filepath.Join(dir, "creds")
	if err := os.Mkdir(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(filepath.Join(creds, "state-key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "p.db"), store.AuditKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := st.AppendAudit(ctx, store.AuditEvent{Actor: "a", Op: "token.issue", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, errOut := runCmd("audit", "verify", "--config", cfg); code != exitOK || !strings.Contains(out, "intact: 3 rows") {
		t.Fatal(code, out, errOut)
	}
	if code, out, _ := runCmd("status", "--config", cfg); code != exitOK || !strings.Contains(out, "3 rows, chain intact") {
		t.Fatal(code, out)
	}
	if err := st.TamperForTest(ctx, 2, "x"); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if code, out, _ := runCmd("audit", "verify", "--config", cfg); code != exitBroken || !strings.Contains(out, "BROKEN at row 2") {
		t.Fatal(code, out)
	}
	if code, out, _ := runCmd("audit", "export", "--config", cfg); code != exitOK || strings.Count(out, "\n") != 3 {
		t.Fatal(code, out)
	}
	// Without the state key, status still reports and verify refuses.
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Join(dir, "none"))
	if code, out, _ := runCmd("status", "--config", cfg); code != exitOK || !strings.Contains(out, "state key not readable") {
		t.Fatal(code, out)
	}
	if code, _, _ := runCmd("audit", "verify", "--config", cfg); code != exitError {
		t.Fatal(code)
	}
}

func TestHealthcheck(t *testing.T) {
	cfg, _ := writeConfig(t)
	if code, _, _ := runCmd("healthcheck", "--config", cfg); code != exitError {
		t.Fatal(code)
	}
}
