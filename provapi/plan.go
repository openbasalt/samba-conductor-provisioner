package provapi

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// The Google-first plan operations: user.create, user.update,
// user.set_enabled and user.move. conductor applies a plan computed by
// conductor-sync through them; the service checks every one against its
// own invariants (scope, privileged accounts, ceilings) and against the
// Google-first marker the account carries.

// MarkerAttribute holds the Google-first marker of an account: the value
// MarkerPrefix followed by the Google user ID. It is written once, by
// user.create, and every other plan operation requires it to match.
const (
	MarkerAttribute = "msDS-cloudExtensionAttribute1"
	MarkerPrefix    = "google-first:"
)

// Marker returns the marker value of a Google user ID.
func Marker(googleID string) string { return MarkerPrefix + googleID }

var markerRE = regexp.MustCompile(`^google-first:[A-Za-z0-9_-]{1,64}$`)

// ValidMarker reports whether s is a well-formed marker value.
func ValidMarker(s string) bool { return markerRE.MatchString(s) }

func validMarker(s string) error {
	if !ValidMarker(s) {
		return errors.New(`marker: "google-first:" and a Google user ID (1 to 64 letters, digits, "_" or "-")`)
	}
	return nil
}

// CreateFields are the optional attributes user.create accepts in Fields.
var CreateFields = []string{"title", "department", "employeeID", "telephoneNumber", "mobile"}

// UpdateAttributes are the attributes user.update may change (the
// Google-owned attributes). Every other attribute is refused.
var UpdateAttributes = []string{"givenName", "sn", "displayName", "mail", "proxyAddresses",
	"title", "department", "employeeID", "telephoneNumber", "mobile"}

// maxChars is the schema's upper bound (characters) of each attribute
// value the plan operations write.
var maxChars = map[string]int{
	"cn": 64, "givenName": 64, "sn": 64, "displayName": 256, "mail": 256,
	"userPrincipalName": 1024, "title": 128, "department": 64, "employeeID": 16,
	"telephoneNumber": 64, "mobile": 64, "proxyAddresses": 1123,
}

// MaxProxyAddresses bounds the values of proxyAddresses in user.update.
const MaxProxyAddresses = 100

// MultiValued reports whether a plan attribute holds several values. Its
// values travel as one string, sorted and joined with "\n" (the form of
// conductor-sync's plan); SplitValues and JoinValues convert.
func MultiValued(attr string) bool { return attr == "proxyAddresses" }

// SplitValues splits the "\n"-joined form of a multi-valued attribute
// ("" is no value).
func SplitValues(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// JoinValues is the "\n"-joined form of values, sorted.
func JoinValues(values []string) string {
	v := slices.Clone(values)
	slices.Sort(v)
	return strings.Join(v, "\n")
}

// validValue checks one attribute value: one line, within the schema's
// bound, no leading or trailing space.
func validValue(attr, v string) error {
	n, ok := maxChars[attr]
	if !ok {
		return fmt.Errorf("%s: not an attribute of the plan operations", attr)
	}
	if !oneLine(v, 4*n) || utf8.RuneCountInString(v) > n || strings.TrimSpace(v) != v {
		return fmt.Errorf("%s: one line, at most %d characters, no leading or trailing space", attr, n)
	}
	return nil
}

// validAddress checks a mail address or userPrincipalName shape: one
// "@" with something on each side, no space.
func validAddress(attr, v string) error {
	if err := validValue(attr, v); err != nil {
		return err
	}
	at := strings.IndexByte(v, '@')
	if at <= 0 || at == len(v)-1 || strings.Count(v, "@") != 1 || strings.ContainsAny(v, " \t") {
		return fmt.Errorf("%s: name@domain without spaces", attr)
	}
	return nil
}

// ValidSAM reports whether s is a valid sAMAccountName for a user: 1 to
// 20 characters, none of "/\[]:;|=,+*?<>@ or a control character, not
// ending with "." and not padded with spaces.
func ValidSAM(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 20 || !oneLine(s, 80) || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsAny(s, "\"/\\[]:;|=,+*?<>@") && !strings.HasSuffix(s, ".")
}

func validReference(r string) error {
	if !oneLine(r, 128) {
		return errors.New("reference: one line, at most 128 bytes")
	}
	return nil
}

// ---- user.create ----

// UserCreateParams creates a Google-first account in ScopeOU: disabled,
// with a random 32-character password the service generates and never
// returns, pwdLastSet 0 and the marker. conductor then issues an
// invitation (token.issue) for the SID of the result.
type UserCreateParams struct {
	// ScopeOU is the OU the account is created in; it must be a scope OU
	// of the service or an OU below one.
	ScopeOU     string `json:"scope_ou"`
	SAM         string `json:"sam"`
	UPN         string `json:"upn"`
	CN          string `json:"cn"`
	Mail        string `json:"mail"`
	GivenName   string `json:"given_name,omitempty"`
	Sn          string `json:"sn,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	// Fields are optional attributes by LDAP name (CreateFields); an empty
	// value is not written.
	Fields map[string]string `json:"fields,omitempty"`
	Marker string            `json:"marker"`
	// Reference is the caller's correlation value (the plan run), kept in
	// the audit log.
	Reference string `json:"reference,omitempty"`
}

// Validate implements Params.
func (p UserCreateParams) Validate() error {
	if p.ScopeOU == "" || !oneLine(p.ScopeOU, 2048) {
		return errors.New("scope_ou: one line, 1 to 2048 bytes")
	}
	if !ValidSAM(p.SAM) {
		return errors.New("sam: not a valid sAMAccountName")
	}
	if err := validAddress("userPrincipalName", p.UPN); err != nil {
		return errors.New("upn: name@suffix without spaces")
	}
	if p.CN == "" {
		return errors.New("cn: required")
	}
	if err := validValue("cn", p.CN); err != nil {
		return err
	}
	if err := validAddress("mail", p.Mail); err != nil {
		return err
	}
	for attr, v := range map[string]string{"givenName": p.GivenName, "sn": p.Sn, "displayName": p.DisplayName} {
		if err := validValue(attr, v); err != nil {
			return err
		}
	}
	if len(p.Fields) > len(CreateFields) {
		return errors.New("fields: too many")
	}
	for attr, v := range p.Fields {
		if !slices.Contains(CreateFields, attr) {
			return fmt.Errorf("fields: %q is not allowed (%s)", clip(attr, 64), strings.Join(CreateFields, ", "))
		}
		if err := validValue(attr, v); err != nil {
			return err
		}
	}
	if err := validMarker(p.Marker); err != nil {
		return err
	}
	return validReference(p.Reference)
}

// UserCreateResult names the created account. SID and ObjectGUID are empty
// only when the account was created but could not be read back (find it
// with user.find).
type UserCreateResult struct {
	SID        string `json:"sid"`
	ObjectGUID string `json:"object_guid"`
	SAM        string `json:"sam"`
	DN         string `json:"dn"`
}

// ---- user.update ----

// UserChange is one attribute change of user.update. Before is the value
// the caller expects now and After the value to write; "" is no value
// (After "" removes the attribute, except mail). A multi-valued attribute
// uses the "\n"-joined form (JoinValues) and is compared as a set.
type UserChange struct {
	Attr   string `json:"attr"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func (c UserChange) validate() error {
	if !slices.Contains(UpdateAttributes, c.Attr) {
		return fmt.Errorf("changes: %q is not allowed (%s)", clip(c.Attr, 64), strings.Join(UpdateAttributes, ", "))
	}
	if c.Before == c.After {
		return fmt.Errorf("changes: %s: before and after are equal", c.Attr)
	}
	for _, v := range []string{c.Before, c.After} {
		if !MultiValued(c.Attr) {
			if err := validValue(c.Attr, v); err != nil {
				return err
			}
			continue
		}
		vals := SplitValues(v)
		if len(vals) > MaxProxyAddresses {
			return fmt.Errorf("%s: at most %d values", c.Attr, MaxProxyAddresses)
		}
		seen := map[string]bool{}
		for _, x := range vals {
			if x == "" {
				return fmt.Errorf("%s: empty value", c.Attr)
			}
			if err := validValue(c.Attr, x); err != nil {
				return err
			}
			if seen[strings.ToLower(x)] {
				return fmt.Errorf("%s: duplicate value", c.Attr)
			}
			seen[strings.ToLower(x)] = true
		}
	}
	if c.Attr == "mail" {
		if err := validAddress("mail", c.After); err != nil {
			return errors.New("changes: mail: the new address must be name@domain (mail is never removed)")
		}
	}
	return nil
}

// UserUpdateParams changes Google-owned attributes of a Google-first
// account. Every change applies only if the current value equals its
// Before (else conflict, nothing written).
type UserUpdateParams struct {
	SID       string       `json:"sid"`
	Changes   []UserChange `json:"changes"`
	Marker    string       `json:"marker"`
	Reference string       `json:"reference,omitempty"`
}

// Validate implements Params.
func (p UserUpdateParams) Validate() error {
	if err := validSID(p.SID); err != nil {
		return err
	}
	if len(p.Changes) == 0 || len(p.Changes) > len(UpdateAttributes) {
		return fmt.Errorf("changes: 1 to %d", len(UpdateAttributes))
	}
	seen := map[string]bool{}
	for _, c := range p.Changes {
		if err := c.validate(); err != nil {
			return err
		}
		if seen[c.Attr] {
			return fmt.Errorf("changes: %s listed twice", c.Attr)
		}
		seen[c.Attr] = true
	}
	if err := validMarker(p.Marker); err != nil {
		return err
	}
	return validReference(p.Reference)
}

// UserWriteResult is the result of user.update, user.set_enabled and
// user.move: the account as it is after the operation. Changed is false
// when nothing had to be written (already enabled or disabled, already
// in the OU).
type UserWriteResult struct {
	SID     string `json:"sid"`
	SAM     string `json:"sam"`
	DN      string `json:"dn"`
	Enabled bool   `json:"enabled"`
	Changed bool   `json:"changed"`
}

// ---- user.set_enabled ----

// UserSetEnabledParams enables or disables a Google-first account.
// Disabling also revokes the account's open tokens.
type UserSetEnabledParams struct {
	SID       string `json:"sid"`
	Enabled   bool   `json:"enabled"`
	Marker    string `json:"marker"`
	Reference string `json:"reference,omitempty"`
}

// Validate implements Params.
func (p UserSetEnabledParams) Validate() error {
	if err := validSID(p.SID); err != nil {
		return err
	}
	if err := validMarker(p.Marker); err != nil {
		return err
	}
	return validReference(p.Reference)
}

// ---- user.move ----

// UserMoveParams moves a Google-first account to ToOU (for example to and
// from the quarantine OU). The account's current parent and ToOU must be
// below the same scope OU.
type UserMoveParams struct {
	SID       string `json:"sid"`
	ToOU      string `json:"to_ou"`
	Marker    string `json:"marker"`
	Reference string `json:"reference,omitempty"`
}

// Validate implements Params.
func (p UserMoveParams) Validate() error {
	if err := validSID(p.SID); err != nil {
		return err
	}
	if p.ToOU == "" || !oneLine(p.ToOU, 2048) {
		return errors.New("to_ou: one line, 1 to 2048 bytes")
	}
	if err := validMarker(p.Marker); err != nil {
		return err
	}
	return validReference(p.Reference)
}
