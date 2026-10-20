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

	// Attributes the Google-first plan operations write (schemaIDGUID).
	guidGivenName       = "f0f8ff8e-1191-11d0-a060-00aa006c33ed"
	guidSn              = "bf967a41-0de6-11d0-a285-00aa003049e2"
	guidDisplayName     = "bf967953-0de6-11d0-a285-00aa003049e2"
	guidMail            = "bf967961-0de6-11d0-a285-00aa003049e2"
	guidProxyAddresses  = "bf967a06-0de6-11d0-a285-00aa003049e2"
	guidTitle           = "bf967a55-0de6-11d0-a285-00aa003049e2"
	guidDepartment      = "bf96794f-0de6-11d0-a285-00aa003049e2"
	guidEmployeeID      = "bf967962-0de6-11d0-a285-00aa003049e2"
	guidTelephoneNumber = "bf967a49-0de6-11d0-a285-00aa003049e2"
	guidMobile          = "f0f8ffa3-1191-11d0-a060-00aa006c33ed"
	guidCloudExtension1 = "9709eaaf-49da-4db2-908a-0446e5eab844" // msDS-cloudExtensionAttribute1, the marker
	guidCN              = "bf96793f-0de6-11d0-a285-00aa003049e2"
	guidName            = "bf967a0e-0de6-11d0-a285-00aa003049e2"
)

// delegationEntry is one access entry of the delegation: an object entry
// (OA) for the account.
type delegationEntry struct {
	what string
	// flags: CIIO (inherited by the objects below the OU, not on the OU
	// itself) or CI (on the OU and inherited by the OUs below it).
	flags string
	// rights: CR (control access), WP (write property), CC (create
	// child), SD (delete).
	rights string
	// object is the object type (a right or attribute, or the class of
	// the children CC allows); inherited the class the entry is inherited
	// by ("" for every class).
	object    string
	inherited string
}

// delegationEntries are the rights of the invitation and reset
// operations: on user objects only.
var delegationEntries = []delegationEntry{
	{"Reset Password on user objects", "CIIO", "CR", guidResetPassword, guidUserClass},
	{"write lockoutTime on user objects (clear a lockout)", "CIIO", "WP", guidLockoutTime, guidUserClass},
	{"write pwdLastSet on user objects", "CIIO", "WP", guidPwdLastSet, guidUserClass},
	{"write userAccountControl on user objects (enable an invited account)", "CIIO", "WP", guidUAC, guidUserClass},
}

// googleFirstEntries are the extra rights of the Google-first plan
// operations (user.create, user.update, user.move; user.set_enabled uses
// userAccountControl above).
var googleFirstEntries = []delegationEntry{
	{"create user objects in the OU and the OUs below it (user.create; the target of a move)", "CI", "CC", guidUserClass, ""},
	{"delete user objects (needed by a move; the service never deletes)", "CIIO", "SD", "", guidUserClass},
	{"write cn on user objects (needed by a move)", "CIIO", "WP", guidCN, guidUserClass},
	{"write name on user objects (needed by a move)", "CIIO", "WP", guidName, guidUserClass},
	{"write givenName on user objects", "CIIO", "WP", guidGivenName, guidUserClass},
	{"write sn on user objects", "CIIO", "WP", guidSn, guidUserClass},
	{"write displayName on user objects", "CIIO", "WP", guidDisplayName, guidUserClass},
	{"write mail on user objects", "CIIO", "WP", guidMail, guidUserClass},
	{"write proxyAddresses on user objects", "CIIO", "WP", guidProxyAddresses, guidUserClass},
	{"write title on user objects", "CIIO", "WP", guidTitle, guidUserClass},
	{"write department on user objects", "CIIO", "WP", guidDepartment, guidUserClass},
	{"write employeeID on user objects", "CIIO", "WP", guidEmployeeID, guidUserClass},
	{"write telephoneNumber on user objects", "CIIO", "WP", guidTelephoneNumber, guidUserClass},
	{"write mobile on user objects", "CIIO", "WP", guidMobile, guidUserClass},
	{"write msDS-cloudExtensionAttribute1 (the Google-first marker) on user objects", "CIIO", "WP", guidCloudExtension1, guidUserClass},
}

// entriesFor returns the delegation entries, with the Google-first ones
// when googleFirst is set.
func entriesFor(googleFirst bool) []delegationEntry {
	out := append([]delegationEntry{}, delegationEntries...)
	if googleFirst {
		out = append(out, googleFirstEntries...)
	}
	return out
}

// DelegationSDDL returns the access entries for the account's SID. The
// entries of the invitation and reset operations are inherited only by
// user objects below the OU (CIIO); with googleFirst the plan operations
// add create-child of user objects on the OU, delete of user objects and
// the writes of their Google-owned attributes, cn and name.
func DelegationSDDL(account sid.SID, googleFirst bool) []string {
	entries := entriesFor(googleFirst)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, fmt.Sprintf("(OA;%s;%s;%s;%s;%s)", e.flags, e.rights, e.object, e.inherited, account))
	}
	return out
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func delegationPreview(cfgPath, ou, accountSID string, googleFirst bool, stdout, stderr io.Writer) int {
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
	if googleFirst {
		fmt.Fprintln(stdout, "# With the Google-first plan operations (--google-first): create user objects (CI, on the OU and")
		fmt.Fprintln(stdout, "# the OUs below it) and, on user objects below the OU (CIIO), delete, cn, name and the Google-owned")
		fmt.Fprintln(stdout, "# attributes. Without --google-first only the invitation and reset rights are printed.")
	} else {
		fmt.Fprintln(stdout, "# Each entry is inherited by the user objects below the OU only (CIIO) and grants one right.")
	}
	fmt.Fprintln(stdout, "# Run on a domain controller as a domain administrator (add -H and credentials as usual):")
	fmt.Fprintln(stdout)
	entries := entriesFor(googleFirst)
	for i, sddl := range DelegationSDDL(account, googleFirst) {
		fmt.Fprintf(stdout, "# %s\n", entries[i].what)
		fmt.Fprintf(stdout, "samba-tool dsacl set --objectdn=%s --sddl=%s\n", shellQuote(ou), shellQuote(sddl))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "# Verify: the %d entries above, and no other entry for the account's SID.\n", len(entries))
	fmt.Fprintf(stdout, "samba-tool dsacl get --objectdn=%s | grep %s\n", shellQuote(ou), shellQuote(account.String()))
	return exitOK
}
