package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
)

// The privilege index of the ad module covers Domain Admins, Enterprise
// Admins, Schema Admins, Group Policy Creator Owners, Domain Controllers,
// Read-only Domain Controllers and the BUILTIN Administrators, Account,
// Server, Print and Backup Operators, with nested and primary-group
// members, adminCount=1 and rights on protected objects. The service adds
// the rest of conductor's protected set, so both refuse the same
// accounts:
var (
	// extraProtectedRIDs are domain groups (RIDs on the domain SID).
	extraProtectedRIDs = []uint32{
		498, // Enterprise Read-only Domain Controllers
		526, // Key Admins (may write msDS-KeyCredentialLink: shadow credentials)
		527, // Enterprise Key Admins
	}
	// extraProtectedBuiltin are BUILTIN groups.
	extraProtectedBuiltin = []sid.SID{
		sid.MustParse("S-1-5-32-552"), // Replicator
	}
)

// dnsAdminsName is the sAMAccountName of DnsAdmins: a domain-local group
// whose RID differs per domain, so it is resolved by name, then matched
// by SID like the others.
const dnsAdminsName = "DnsAdmins"

// protectedGroupSIDs returns the groups the service hands the privilege
// index on top of its own: the configured extra_group_sids and the groups
// above. A failed read fails the whole list (the index is never built
// without them).
func protectedGroupSIDs(ctx context.Context, cfg *config.Config, dir directory.Directory) ([]sid.SID, error) {
	dom, err := dir.DomainSID(ctx)
	if err != nil {
		return nil, fmt.Errorf("domain SID: %w", err)
	}
	out := cfg.ExtraGroupSIDs()
	for _, rid := range extraProtectedRIDs {
		g, err := dom.WithRID(rid)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	out = append(out, extraProtectedBuiltin...)
	dns, err := dir.FindGroupSID(ctx, dnsAdminsName)
	switch {
	case errors.Is(err, ad.ErrNotFound):
		// A domain without DnsAdmins (no DNS role ever provisioned).
	case err != nil:
		return nil, fmt.Errorf("%s: %w", dnsAdminsName, err)
	default:
		// Only this domain's group: an object of that name carrying
		// another domain's SID is not it.
		if d, ok := dns.Domain(); ok && d.Equal(dom) {
			out = append(out, dns)
		}
	}
	var uniq []sid.SID
	for _, s := range out {
		if !slices.ContainsFunc(uniq, s.Equal) {
			uniq = append(uniq, s)
		}
	}
	return uniq, nil
}

// buildIndex builds the privilege index with the service's protected set.
func buildIndex(ctx context.Context, cfg *config.Config, dir directory.Directory) (directory.Index, error) {
	groups, err := protectedGroupSIDs(ctx, cfg, dir)
	if err != nil {
		return nil, err
	}
	return dir.BuildIndex(ctx, privilege.Options{ExtraGroupSIDs: groups})
}

// Misplaced is a privileged account below a scope OU. The delegation
// grants its rights on every user object below a scope OU, so the
// delegated account could reset such an account's password directly over
// LDAP (the service itself refuses it): administrators must live outside
// the scope OUs.
type Misplaced struct {
	DN    string
	SAM   string
	SID   string
	Kinds []string
}

// findMisplaced lists the privileged accounts below the OUs, by the index
// and their own adminCount.
func findMisplaced(ctx context.Context, dir directory.Directory, x directory.Index, ous []string) ([]Misplaced, error) {
	var out []Misplaced
	seen := map[string]bool{}
	for _, ou := range ous {
		users, err := dir.UsersBelow(ctx, ou)
		if err != nil {
			return nil, fmt.Errorf("accounts below %s: %w", ou, err)
		}
		for _, u := range users {
			var kinds []string
			if !u.SID.IsZero() {
				for _, r := range x.PrivilegedSID(u.SID) {
					if !slices.Contains(kinds, r.Kind) {
						kinds = append(kinds, r.Kind)
					}
				}
			}
			if u.AdminCount && !slices.Contains(kinds, privilege.KindAdminCount) {
				kinds = append(kinds, privilege.KindAdminCount)
			}
			key := strings.ToLower(u.DN)
			if len(kinds) == 0 || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Misplaced{DN: u.DN, SAM: u.SAMAccountName, SID: u.SID.String(), Kinds: kinds})
		}
	}
	slices.SortFunc(out, func(a, b Misplaced) int { return strings.Compare(strings.ToLower(a.DN), strings.ToLower(b.DN)) })
	return out, nil
}

// PrivilegedInScope builds the index and lists the privileged accounts
// below the OUs (the configured scope OUs when ous is nil). serve refuses
// to start while there are any; status and delegation preview show them.
func PrivilegedInScope(ctx context.Context, cfg *config.Config, dir directory.Directory, ous []string) ([]Misplaced, error) {
	if ous == nil {
		ous = cfg.Scope.OUs
	}
	x, err := buildIndex(ctx, cfg, dir)
	if err != nil {
		return nil, err
	}
	return findMisplaced(ctx, dir, x, ous)
}

// DescribeMisplaced is one line per account, for logs and the CLI.
func DescribeMisplaced(m []Misplaced) []string {
	out := make([]string, 0, len(m))
	for _, a := range m {
		out = append(out, fmt.Sprintf("%s (%s, %s): %s", a.DN, a.SAM, a.SID, strings.Join(a.Kinds, ", ")))
	}
	return out
}

// checkScope runs after every index rebuild: privileged accounts below a
// scope OU are an error in the log and, once per change of the list, an
// audit entry. The service keeps refusing those accounts one by one
// (invariant 2); a read failure fails the operation that rebuilt the
// index.
func (s *Service) checkScope(ctx context.Context, x directory.Index) error {
	m, err := findMisplaced(ctx, s.dir, x, s.cfg.Scope.OUs)
	if err != nil {
		return err
	}
	lines := DescribeMisplaced(m)
	key := strings.Join(lines, "\n")
	s.scopeMu.Lock()
	changed := key != s.misplacedKey
	s.misplacedKey = key
	s.scopeMu.Unlock()
	if len(m) == 0 {
		if changed {
			s.log.Info("no privileged account below the scope OUs any more")
		}
		return nil
	}
	for _, l := range lines {
		s.log.Error("privileged account below a scope OU: move it out of the scope OUs", "account", l)
	}
	if changed {
		_, err := s.st.AppendAudit(context.WithoutCancel(ctx), store.AuditEvent{Actor: "conductor-provisioner", Op: "scope.check",
			Result: "privileged", Detail: fmt.Sprintf("%d privileged account(s) below the scope OUs: %s", len(m), strings.Join(lines, "; "))})
		if err != nil {
			s.log.Error("writing the audit log failed", "op", "scope.check", "err", err)
		}
	}
	return nil
}
