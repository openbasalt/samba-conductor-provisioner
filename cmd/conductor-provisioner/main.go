// Command conductor-provisioner holds a least-privilege AD account
// delegated on the managed OUs and executes typed operations for conductor
// over a Unix socket (one-time invitation and reset tokens, password set,
// lockout clear, account enable), with its own invariants and audit log.
//
//	conductor-provisioner serve       [--config FILE]
//	conductor-provisioner status      [--config FILE]
//	conductor-provisioner audit       verify | export [--config FILE]
//	conductor-provisioner delegation  preview --ou DN [--account-sid SID] [--google-first] [--config FILE]
//	conductor-provisioner healthcheck [--config FILE]
//	conductor-provisioner version
//
// --config defaults to /etc/conductor-provisioner/provisioner.toml.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/secret"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
)

var version = "dev"

// Exit codes (docs/usage.md).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	// exitBroken: audit verify found a broken chain.
	exitBroken = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: conductor-provisioner <command> [flags]

commands:
  serve         run the API for conductor (systemd socket activation or api.socket)
  status        configuration summary, tokens by state, audit rows
  audit         verify | export the hash-chained audit log (needs the state key)
  delegation    preview --ou DN [--google-first]: the samba-tool commands that
                delegate the OU to the configured account (--google-first adds
                the rights of the Google-first plan operations)
  healthcheck   exit 0 when the configuration loads and the API socket exists
  version
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "conductor-provisioner", version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	}
	sub := ""
	if (cmd == "audit" || cmd == "delegation") && len(rest) > 0 && rest[0] != "" && rest[0][0] != '-' {
		sub, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	ou := fs.String("ou", "", "the OU to delegate (delegation preview)")
	accountSID := fs.String("account-sid", "", "the account's SID, instead of resolving it in AD (delegation preview)")
	googleFirst := fs.Bool("google-first", false, "add the rights of the Google-first plan operations (delegation preview)")
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	switch cmd {
	case "serve":
		return serve(*cfgPath, stderr)
	case "healthcheck":
		return healthcheck(*cfgPath, stdout, stderr)
	case "status":
		return status(*cfgPath, stdout, stderr)
	case "audit":
		return audit(*cfgPath, sub, stdout, stderr)
	case "delegation":
		if sub != "preview" || *ou == "" {
			fmt.Fprintln(stderr, "usage: conductor-provisioner delegation preview --ou DN [--account-sid SID] [--google-first]")
			return exitUsage
		}
		return delegationPreview(*cfgPath, *ou, *accountSID, *googleFirst, stdout, stderr)
	}
	usage(stderr)
	return exitUsage
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// openStore opens the state database. With needKey the state key is
// loaded (a missing key is an error); otherwise it is used when readable.
func openStore(ctx context.Context, cfg *config.Config, needKey bool) (*store.Store, bool, error) {
	var auditKey []byte
	raw, err := secret.Load(config.CredentialStateKey)
	if err == nil {
		k, perr := secret.ParseKey(raw)
		clear(raw)
		if perr != nil {
			return nil, false, perr
		}
		auditKey = store.AuditKey(k)
		clear(k)
	} else if needKey {
		return nil, false, fmt.Errorf("the state key: %w", err)
	}
	fi, err := os.Stat(cfg.State.Database)
	if err != nil {
		return nil, false, fmt.Errorf("state database: %w", err)
	}
	st, err := store.Open(ctx, cfg.State.Database, auditKey)
	if err == nil {
		keepOwner(cfg.State.Database, fi)
	}
	return st, auditKey != nil, err
}

// keepOwner gives the database's WAL and shared-memory files, which a
// command run by root may have just created, back to the database's owner
// (the service user), so the service can still open them.
func keepOwner(db string, fi os.FileInfo) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return
	}
	for _, f := range []string{db + "-wal", db + "-shm"} {
		_ = os.Lchown(f, int(st.Uid), int(st.Gid))
	}
}

func status(cfgPath string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	fmt.Fprintf(stdout, "account      %s@%s\n", cfg.Account.Username, cfg.Domain.Realm)
	if len(cfg.Scope.OUs) == 0 {
		fmt.Fprintln(stdout, "scope        (none: every operation is refused)")
	}
	for _, ou := range cfg.Scope.OUs {
		fmt.Fprintf(stdout, "scope        %s\n", ou)
	}
	fmt.Fprintf(stdout, "ceilings     token issues %d/h, password sets %d/h, enables %d/h\n",
		cfg.Limits.TokenIssuesPerHour, cfg.Limits.PasswordSetsPerHour, cfg.Limits.EnablesPerHour)
	fmt.Fprintf(stdout, "             creates %d/h, updates %d/h, moves %d/h, disables %d/h\n",
		cfg.Limits.CreatesPerHour, cfg.Limits.UpdatesPerHour, cfg.Limits.MovesPerHour, cfg.Limits.DisablesPerHour)
	fmt.Fprintf(stdout, "tokens       invite %d h, reset %d min, complete %d min, %d per account per day\n",
		cfg.Tokens.InviteHours, cfg.Tokens.ResetMinutes, cfg.Tokens.CompleteMinutes, cfg.Tokens.PerUserPerDay)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, keyed, err := openStore(ctx, cfg, false)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	defer func() { _ = st.Close() }()
	counts, err := st.CountByState(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	fmt.Fprintf(stdout, "token state  open %d, password_set %d, used %d, revoked %d, expired %d\n",
		counts[store.StateOpen], counts[store.StatePasswordSet], counts[store.StateUsed], counts[store.StateRevoked], counts[store.StateExpired])
	n, err := st.AuditRows(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if !keyed {
		fmt.Fprintf(stdout, "audit        %d rows (state key not readable: run audit verify with it)\n", n)
		return exitOK
	}
	res, err := st.VerifyAudit(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if res.BrokenAt != 0 {
		fmt.Fprintf(stdout, "audit        %d rows, BROKEN at %d: %s\n", n, res.BrokenAt, res.Reason)
		return exitBroken
	}
	fmt.Fprintf(stdout, "audit        %d rows, chain intact\n", n)
	return exitOK
}

func audit(cfgPath, sub string, stdout, stderr io.Writer) int {
	if sub != "verify" && sub != "export" {
		fmt.Fprintln(stderr, "usage: conductor-provisioner audit verify | export")
		return exitUsage
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, _, err := openStore(ctx, cfg, sub == "verify")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	defer func() { _ = st.Close() }()
	if sub == "export" {
		if _, err := st.ExportAudit(ctx, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		return exitOK
	}
	res, err := st.VerifyAudit(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if res.BrokenAt != 0 {
		fmt.Fprintf(stdout, "audit chain BROKEN at row %d: %s (%d rows verified before it)\n", res.BrokenAt, res.Reason, res.Rows)
		return exitBroken
	}
	fmt.Fprintf(stdout, "audit chain intact: %d rows, last hash %s\n", res.Rows, res.LastHash)
	return exitOK
}

func healthcheck(cfgPath string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	st, err := os.Stat(cfg.API.Socket)
	if err != nil {
		fmt.Fprintln(stderr, "API socket:", err)
		return exitError
	}
	if st.Mode()&os.ModeSocket == 0 {
		fmt.Fprintf(stderr, "API socket: %s is not a socket\n", cfg.API.Socket)
		return exitError
	}
	fmt.Fprintln(stdout, "ok")
	return exitOK
}

func newLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
