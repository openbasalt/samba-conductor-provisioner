package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
)

// Schema GUIDs of the delegation (docs/delegation.md).
const (
	guidUserClass     = "bf967aba-0de6-11d0-a285-00aa003049e2" // user objects (inherited object type)
	guidResetPassword = "00299570-246d-11d0-a768-00aa006e0529" // User-Force-Change-Password (Reset Password)
	guidLockoutTime   = "28630ebf-41d5-11d1-a9c1-0000f80367c1"
	guidPwdLastSet    = "bf967a0a-0de6-11d0-a285-00aa003049e2"
	guidUAC           = "bf967a68-0de6-11d0-a285-00aa003049e2"
)

// delegationEntry is one access entry of the delegation.
type delegationEntry struct {
	what   string
	rights string // CR (control access) or WP (write property)
	object string
}

var delegationEntries = []delegationEntry{
	{"Reset Password on user objects", "CR", guidResetPassword},
	{"write lockoutTime on user objects (clear a lockout)", "WP", guidLockoutTime},
	{"write pwdLastSet on user objects", "WP", guidPwdLastSet},
	{"write userAccountControl on user objects (enable an invited account)", "WP", guidUAC},
}

// DelegationSDDL returns the access entries for the account's SID: object
// entries inherited only by user objects below the OU (CIIO), never on
// the OU itself.
func DelegationSDDL(account sid.SID) []string {
	out := make([]string, 0, len(delegationEntries))
	for _, e := range delegationEntries {
		out = append(out, fmt.Sprintf("(OA;CIIO;%s;%s;%s;%s)", e.rights, e.object, guidUserClass, account))
	}
	return out
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func delegationPreview(cfgPath, ou, accountSID string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	// The OU passes the same checks as a scope OU.
	probe := *cfg
	probe.Scope.OUs = []string{ou}
	if err := probe.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	inScope := false
	for _, s := range cfg.Scope.OUs {
		if s == probe.Scope.OUs[0] {
			inScope = true
		}
	}
	var account sid.SID
	if accountSID != "" {
		if account, err = sid.Parse(accountSID); err != nil {
			fmt.Fprintln(stderr, "--account-sid:", err)
			return exitUsage
		}
	} else {
		sealed, err := loadAccountPassword(cfg)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n(run as the service with its credentials, or pass --account-sid)\n", err)
			return exitError
		}
		defer sealed.Close()
		dir, err := directory.NewAD(cfg, sealed, newLogger(stderr))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		defer dir.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if account, err = dir.AccountSID(ctx); err != nil {
			fmt.Fprintf(stderr, "resolving %s: %v (or pass --account-sid)\n", cfg.Account.Username, err)
			return exitError
		}
	}
	fmt.Fprintf(stdout, "# Delegation of %s\n# to %s (%s).\n", ou, cfg.Account.Username, account)
	if !inScope {
		fmt.Fprintln(stdout, "# Note: this OU is not in [scope] ous yet; the service refuses accounts below it until it is.")
	}
	fmt.Fprintln(stdout, "# Each entry is inherited by the user objects below the OU only (CIIO) and grants one right.")
	fmt.Fprintln(stdout, "# Run on a domain controller as a domain administrator (add -H and credentials as usual):")
	fmt.Fprintln(stdout)
	for i, sddl := range DelegationSDDL(account) {
		fmt.Fprintf(stdout, "# %s\n", delegationEntries[i].what)
		fmt.Fprintf(stdout, "samba-tool dsacl set --objectdn=%s --sddl=%s\n", shellQuote(ou), shellQuote(sddl))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "# Verify: the four entries above, and no other entry for the account's SID.")
	fmt.Fprintf(stdout, "samba-tool dsacl get --objectdn=%s | grep %s\n", shellQuote(ou), shellQuote(account.String()))
	return exitOK
}
