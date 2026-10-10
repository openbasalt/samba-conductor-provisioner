// Package directory is the small set of directory reads and writes the
// service uses, as an interface (Directory) so the server is tested
// against an in-memory fake, and its implementation over the ad module
// (AD) with the delegated account.
package directory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Entry is one object as read for an operation: the user model plus what
// the invariants need (object classes, adminCount) and the attributes of
// the plan operations the user model lacks.
type Entry struct {
	ad.User
	Classes    []string
	AdminCount bool
	// Marker is the value of provapi.MarkerAttribute ("" when absent).
	Marker         string
	ProxyAddresses []string
	EmployeeID     string
}

// IsOU reports whether the entry is an organizational unit.
func (e Entry) IsOU() bool {
	return slices.ContainsFunc(e.Classes, func(x string) bool { return strings.EqualFold(x, "organizationalUnit") })
}

// Values returns the current values of a plan attribute
// (provapi.UpdateAttributes), nil when it has none.
func (e Entry) Values(attr string) []string {
	var v string
	switch attr {
	case "proxyAddresses":
		return slices.Clone(e.ProxyAddresses)
	case "givenName":
		v = e.GivenName
	case "sn":
		v = e.Surname
	case "displayName":
		v = e.DisplayName
	case "mail":
		v = e.Mail
	case "title":
		v = e.Title
	case "department":
		v = e.Department
	case "employeeID":
		v = e.EmployeeID
	case "telephoneNumber":
		v = e.TelephoneNumber
	case "mobile":
		v = e.Mobile
	}
	if v == "" {
		return nil
	}
	return []string{v}
}

// NewUser is an account to create: the ad module's user plus the marker.
// Attrs holds the optional attributes by LDAP name (givenName, sn,
// displayName and provapi.CreateFields), empty values left out.
type NewUser struct {
	ParentDN string
	CN       string
	SAM      string
	UPN      string
	Mail     string
	Attrs    map[string]string
	Marker   string
	// Password is set in the add itself; the account is created disabled
	// with pwdLastSet 0. Never logged.
	Password string
}

// AttrChange replaces one attribute: Before are the values the caller
// compared (a write may assert them), After the new ones (none removes
// the attribute).
type AttrChange struct {
	Name   string
	Before []string
	After  []string
}

// ConflictQuery names the values user.create must find nowhere in the
// domain; empty fields are not searched.
type ConflictQuery struct {
	SAM    string
	UPN    string
	Mail   string
	Marker string
}

// Match is one object holding a value of a ConflictQuery; Kinds says
// which (sam, upn, mail, marker; mail also matches an SMTP proxy address
// and a userPrincipalName equal to the address).
type Match struct {
	DN    string
	SID   sid.SID
	Kinds []string
}

// ErrUnsupported is returned by a write the directory implementation
// cannot express.
var ErrUnsupported = errors.New("directory: write not supported by this directory implementation")

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
	// SchemaHasAttribute reports whether the schema defines an attribute
	// with that lDAPDisplayName.
	SchemaHasAttribute(ctx context.Context, name string) (bool, error)
	// FindConflicts returns the objects anywhere in the domain (any
	// class) holding one of the query's values.
	FindConflicts(ctx context.Context, q ConflictQuery) ([]Match, error)
	// CreateUser adds the account in one request (password, disabled,
	// pwdLastSet 0, marker); ad.ErrAlreadyExists when the DN is taken.
	CreateUser(ctx context.Context, u NewUser) error
	// ModifyUser replaces the attributes of one account in one request.
	ModifyUser(ctx context.Context, dn string, changes []AttrChange) error
}

// EntryAttributes are read by Get.
var EntryAttributes = append(slices.Clone(ad.UserAttributes), "objectClass", "adminCount",
	provapi.MarkerAttribute, "proxyAddresses", "employeeID")
