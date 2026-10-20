// Package config loads /etc/conductor-provisioner/provisioner.toml. The
// file holds no secret: the delegated account's password and the state
// key are systemd credentials ("account-password" and "state-key").
// Unknown keys are rejected and every value is checked at load, so a typo
// never silently widens what the service may do.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

// DefaultPath is the configuration file of the systemd unit.
const DefaultPath = "/etc/conductor-provisioner/provisioner.toml"

// Credential names (systemd LoadCredential= of the unit).
const (
	CredentialAccountPassword = "account-password"
	CredentialStateKey        = "state-key"
)

// Domain is the [domain] section: how to reach the domain controllers.
type Domain struct {
	Realm      string   `toml:"realm"`
	CAFile     string   `toml:"ca_file"`
	Preferred  []string `toml:"preferred"`
	DCs        []string `toml:"dcs"`
	DNSServers []string `toml:"dns_servers"`
	// SimpleBindFallback allows an LDAP simple bind over LDAPS when no
	// KDC answers (off by default).
	SimpleBindFallback bool `toml:"simple_bind_fallback"`
}

// Account is the [account] section: the delegated account.
type Account struct {
	Username string `toml:"username"`
}

// Scope is the [scope] section: the OUs the account is delegated on.
type Scope struct {
	OUs []string `toml:"ous"`
}

// Privileged is the [privileged] section.
type Privileged struct {
	ExtraGroupSIDs    []string `toml:"extra_group_sids"`
	IndexCacheSeconds int      `toml:"index_cache_seconds"`
}

// Tokens is the [tokens] section.
type Tokens struct {
	InviteHours     int `toml:"invite_hours"`
	ResetMinutes    int `toml:"reset_minutes"`
	CompleteMinutes int `toml:"complete_minutes"`
	PerUserPerDay   int `toml:"per_user_per_day"`
}

// Limits is the [limits] section: hourly ceilings (0 refuses everything).
type Limits struct {
	TokenIssuesPerHour  int `toml:"token_issues_per_hour"`
	PasswordSetsPerHour int `toml:"password_sets_per_hour"`
	EnablesPerHour      int `toml:"enables_per_hour"`
}

// State is the [state] section.
type State struct {
	Database string `toml:"database"`
}

// API is the [api] section.
type API struct {
	Socket string `toml:"socket"`
	// SocketGroup is the group of a socket the service creates itself
	// (without socket activation).
	SocketGroup  string   `toml:"socket_group"`
	AllowedUsers []string `toml:"allowed_users"`
	AllowedUIDs  []int    `toml:"allowed_uids"`
}

// Config is the whole file.
type Config struct {
	Domain     Domain     `toml:"domain"`
	Account    Account    `toml:"account"`
	Scope      Scope      `toml:"scope"`
	Privileged Privileged `toml:"privileged"`
	Tokens     Tokens     `toml:"tokens"`
	Limits     Limits     `toml:"limits"`
	State      State      `toml:"state"`
	API        API        `toml:"api"`

	// Filled in by Validate.
	scopeDNs  []*ldap.DN
	extraSIDs []sid.SID
}

// Defaults returns a configuration with every default filled in; Load
// decodes the file over it, so a missing key keeps its default.
func Defaults() Config {
	return Config{
		Privileged: Privileged{IndexCacheSeconds: 60},
		Tokens:     Tokens{InviteHours: 72, ResetMinutes: 30, CompleteMinutes: 30, PerUserPerDay: 3},
		Limits:     Limits{TokenIssuesPerHour: 200, PasswordSetsPerHour: 200, EnablesPerHour: 200},
		State:      State{Database: "/var/lib/conductor-provisioner/provisioner.db"},
		API:        API{Socket: "/run/conductor-provisioner/api.sock", AllowedUsers: []string{"conductor"}},
	}
}

// Load reads, decodes (unknown keys rejected) and validates the file.
func Load(path string) (*Config, error) {
	c := Defaults()
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Parse decodes a configuration from a string (tests and examples).
func Parse(text string) (*Config, error) {
	c := Defaults()
	md, err := toml.Decode(text, &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("config: unknown keys: %v", und)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

var (
	realmRE    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$`)
	hostRE     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$`)
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)
)

func rangeErr(key string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("config: %s = %d: must be %d to %d", key, v, lo, hi)
	}
	return nil
}

// Validate checks every value and normalizes the scope OUs.
func (c *Config) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	d := &c.Domain
	if !realmRE.MatchString(d.Realm) {
		add(fmt.Errorf("config: domain.realm %q is not a DNS domain name", d.Realm))
	}
	if !filepath.IsAbs(d.CAFile) {
		add(errors.New("config: domain.ca_file must be an absolute path (the domain CA is pinned)"))
	}
	for _, h := range append(slices.Clone(d.Preferred), d.DCs...) {
		if !hostRE.MatchString(h) {
			add(fmt.Errorf("config: domain controller host name %q is invalid", h))
		}
	}
	for _, s := range d.DNSServers {
		if _, err := netip.ParseAddr(s); err != nil {
			if _, err := netip.ParseAddrPort(s); err != nil {
				add(fmt.Errorf("config: domain.dns_servers: %q is not an address or address:port", s))
			}
		}
	}
	if !usernameRE.MatchString(c.Account.Username) {
		add(fmt.Errorf("config: account.username %q is not a sAMAccountName", c.Account.Username))
	}
	if realmRE.MatchString(d.Realm) {
		add(c.validateScope())
	}
	c.extraSIDs = nil
	for _, s := range c.Privileged.ExtraGroupSIDs {
		v, err := sid.Parse(s)
		if err != nil {
			add(fmt.Errorf("config: privileged.extra_group_sids: %q is not a SID", s))
			continue
		}
		c.extraSIDs = append(c.extraSIDs, v)
	}
	add(rangeErr("privileged.index_cache_seconds", c.Privileged.IndexCacheSeconds, 0, 300))
	add(rangeErr("tokens.invite_hours", c.Tokens.InviteHours, 1, 168))
	add(rangeErr("tokens.reset_minutes", c.Tokens.ResetMinutes, 5, 120))
	add(rangeErr("tokens.complete_minutes", c.Tokens.CompleteMinutes, 5, 240))
	add(rangeErr("tokens.per_user_per_day", c.Tokens.PerUserPerDay, 1, 50))
	add(rangeErr("limits.token_issues_per_hour", c.Limits.TokenIssuesPerHour, 0, 100000))
	add(rangeErr("limits.password_sets_per_hour", c.Limits.PasswordSetsPerHour, 0, 100000))
	add(rangeErr("limits.enables_per_hour", c.Limits.EnablesPerHour, 0, 100000))
	if !filepath.IsAbs(c.State.Database) {
		add(errors.New("config: state.database must be an absolute path"))
	}
	if !filepath.IsAbs(c.API.Socket) {
		add(errors.New("config: api.socket must be an absolute path"))
	}
	if len(c.API.AllowedUsers) == 0 && len(c.API.AllowedUIDs) == 0 {
		add(errors.New("config: api.allowed_users (or api.allowed_uids) must name conductor's user"))
	}
	for _, u := range c.API.AllowedUIDs {
		if u <= 0 {
			add(errors.New("config: api.allowed_uids: root (0) and negative UIDs are not allowed"))
		}
	}
	return errors.Join(errs...)
}

// BaseDN returns the domain head's DN derived from the realm
// ("EXAMPLE.COM" is "dc=example,dc=com").
func (c *Config) BaseDN() string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(c.Domain.Realm, ".")), ".")
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}

// forbiddenScopes are containers that may never be a scope OU, nor
// contain one: they hold built-in, system or domain controller objects.
var forbiddenScopes = []string{"cn=users", "cn=builtin", "cn=system", "ou=domain controllers",
	"cn=configuration", "cn=schema,cn=configuration", "cn=computers", "cn=foreignsecurityprincipals"}

func (c *Config) validateScope() error {
	base, err := ldap.ParseDN(c.BaseDN())
	if err != nil {
		return fmt.Errorf("config: domain.realm: %w", err)
	}
	c.scopeDNs = nil
	normalized := make([]string, 0, len(c.Scope.OUs))
	for _, raw := range c.Scope.OUs {
		dn, err := escape.ParseDN(raw)
		if err != nil || len(dn.RDNs) == 0 {
			return fmt.Errorf("config: scope.ous: %q is not a DN", raw)
		}
		first := dn.RDNs[0]
		if len(first.Attributes) != 1 || !strings.EqualFold(first.Attributes[0].Type, "ou") {
			return fmt.Errorf("config: scope.ous: %q is not an organizational unit (OU=...)", raw)
		}
		if dn.EqualFold(base) || !base.AncestorOfFold(dn) {
			return fmt.Errorf("config: scope.ous: %q is not an OU below the domain head %s", raw, c.BaseDN())
		}
		for _, f := range forbiddenScopes {
			fdn, _ := ldap.ParseDN(f + "," + c.BaseDN())
			if fdn.EqualFold(dn) || fdn.AncestorOfFold(dn) {
				return fmt.Errorf("config: scope.ous: %q is or is below a built-in container (%s)", raw, f)
			}
		}
		n := escape.NormalizeDN(raw)
		if slices.Contains(normalized, n) {
			return fmt.Errorf("config: scope.ous: %q is listed twice", raw)
		}
		normalized = append(normalized, n)
		c.scopeDNs = append(c.scopeDNs, dn)
	}
	c.Scope.OUs = normalized
	return nil
}

// InScope reports whether dn is strictly below one of the scope OUs. The
// comparison is on parsed DNs (RFC 4514), case-insensitive, so escaping,
// spacing or case tricks neither widen nor narrow the scope.
func (c *Config) InScope(dn string) bool {
	parsed, err := escape.ParseDN(dn)
	if err != nil {
		return false
	}
	for _, s := range c.scopeDNs {
		if s.AncestorOfFold(parsed) {
			return true
		}
	}
	return false
}

// ExtraGroupSIDs returns the parsed privileged.extra_group_sids.
func (c *Config) ExtraGroupSIDs() []sid.SID { return slices.Clone(c.extraSIDs) }
