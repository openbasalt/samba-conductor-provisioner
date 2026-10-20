// Package directory is the small set of directory reads and writes the
// service uses, as an interface (Directory) so the server is tested
// against an in-memory fake, and its implementation over the ad module
// (AD) with the delegated account.
package directory

import (
	"context"
	"slices"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// Entry is one object as read for an operation: the user model plus what
// the invariants need (object classes, adminCount).
type Entry struct {
	ad.User
	Classes    []string
	AdminCount bool
}

// IsUser reports whether the entry is a user account: object class user
// and not computer (computers are users in the schema).
func (e Entry) IsUser() bool {
	has := func(c string) bool {
		return slices.ContainsFunc(e.Classes, func(x string) bool { return strings.EqualFold(x, c) })
	}
	return has("user") && !has("computer")
}

// Index answers which SIDs are privileged (privilege.Index implements it).
type Index interface {
	PrivilegedSID(s sid.SID) []privilege.Reason
	BuiltAt() time.Time
}

// Directory is what the service reads and writes. Every method reads the
// directory fresh; nothing is cached here.
type Directory interface {
	// FindBySID returns the DN of the object with that SID
	// (ad.ErrNotFound when there is none). No referral is chased.
	FindBySID(ctx context.Context, s sid.SID) (string, error)
	// FindUsers returns the DNs of the user accounts whose
	// sAMAccountName or mail equals v (at most two: enough to tell one
	// match from several).
	FindUsers(ctx context.Context, v string) ([]string, error)
	// Get reads one object (ad.ErrNotFound).
	Get(ctx context.Context, dn string) (Entry, error)
	// TokenGroups returns the SIDs of every group the object belongs to,
	// transitively, as computed by the DC.
	TokenGroups(ctx context.Context, dn string) ([]sid.SID, error)
	// BuildIndex builds the privilege index.
	BuildIndex(ctx context.Context, opt privilege.Options) (Index, error)
	// Apply sends one write built with the ad package's constructors.
	Apply(ctx context.Context, op *ad.Operation) error
}

// EntryAttributes are read by Get.
var EntryAttributes = append(slices.Clone(ad.UserAttributes), "objectClass", "adminCount")
