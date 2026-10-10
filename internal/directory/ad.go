package directory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/secret"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Connection lifetimes: a Kerberos session is renewed before it is this
// close to its end, and a connection is reopened after maxConnAge so a DC
// that came back (or a preferred one) is picked up.
const (
	renewBefore = 10 * time.Minute
	maxConnAge  = 15 * time.Minute
)

// AD is the Directory over LDAPS with the delegated account: Kerberos
// (ad.SignIn with the password from the "account-password" credential,
// kept sealed in memory), or a simple bind when simple_bind_fallback is
// on and no KDC answers. One connection is shared and used by one call at
// a time.
type AD struct {
	cfg      ad.Config
	username string
	password *secret.Sealed
	fallback bool
	log      *slog.Logger

	mu     sync.Mutex
	sess   *ad.Session
	conn   *ad.Conn
	connAt time.Time
	mech   string
}

// NewAD prepares the directory (nothing is dialled yet). password stays
// owned by the caller until Close.
func NewAD(c *config.Config, password *secret.Sealed, log *slog.Logger) (*AD, error) {
	pemData, err := os.ReadFile(c.Domain.CAFile)
	if err != nil {
		return nil, fmt.Errorf("domain.ca_file: %w", err)
	}
	pool, err := ad.CertPoolFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("domain.ca_file: %w", err)
	}
	cfg := ad.Config{Realm: c.Domain.Realm, DCs: c.Domain.DCs, Preferred: c.Domain.Preferred, RootCAs: pool}
	if len(c.Domain.DNSServers) > 0 {
		cfg.Resolver = ad.NewDNSResolver(c.Domain.DNSServers...)
	}
	if log == nil {
		log = slog.Default()
	}
	return &AD{cfg: cfg, username: c.Account.Username, password: password, fallback: c.Domain.SimpleBindFallback, log: log}, nil
}

// Close drops the connection and the Kerberos session.
func (d *AD) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dropLocked()
	if d.sess != nil {
		d.sess.Close()
		d.sess = nil
	}
}

func (d *AD) dropLocked() {
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}

// Mechanism returns "kerberos" or "simple" once connected.
func (d *AD) Mechanism() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mech
}

// connectLocked opens a connection bound as the delegated account.
func (d *AD) connectLocked(ctx context.Context) error {
	pw, err := d.password.Open()
	if err != nil {
		return err
	}
	defer clear(pw)
	if d.sess == nil || time.Until(d.sess.Expires()) < renewBefore {
		if d.sess != nil {
			d.sess.Close()
			d.sess = nil
		}
		s, err := ad.SignIn(ctx, d.cfg, d.username, string(pw))
		if err != nil {
			var ae *ad.AuthError
			if errors.As(err, &ae) || !d.fallback {
				return fmt.Errorf("signing in as %s: %w", d.username, err)
			}
			d.log.Warn("no KDC answered; using the LDAP simple bind fallback", "err", err)
			conn, berr := ad.Connect(ctx, d.cfg, ad.SimpleAuth(d.username, string(pw)))
			if berr != nil {
				return fmt.Errorf("simple bind as %s: %w", d.username, berr)
			}
			d.conn, d.connAt, d.mech = conn, time.Now(), "simple"
			return nil
		}
		d.sess = s
	}
	conn, err := ad.Connect(ctx, d.cfg, ad.KerberosAuth(d.sess))
	if err != nil {
		return err
	}
	d.conn, d.connAt, d.mech = conn, time.Now(), "kerberos"
	return nil
}

// retryable reports a broken connection worth one reconnect.
func retryable(err error) bool {
	var fe *ad.FailoverError
	if errors.As(err, &fe) {
		return false
	}
	return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || errors.Is(err, ad.ErrSessionClosed) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultServerDown)
}

// do runs fn on the shared connection, reconnecting once when the
// connection broke.
func (d *AD) do(ctx context.Context, fn func(c *ad.Conn) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if d.conn != nil && (time.Since(d.connAt) > maxConnAge || (d.sess != nil && time.Until(d.sess.Expires()) < renewBefore)) {
			d.dropLocked()
		}
		if d.conn == nil {
			if err := d.connectLocked(ctx); err != nil {
				return err
			}
		}
		err := fn(d.conn)
		if err != nil && attempt == 0 && retryable(err) {
			d.log.Info("directory connection lost; reconnecting", "err", err)
			d.dropLocked()
			continue
		}
		return err
	}
}

// Ping connects (if needed) and returns the bound identity.
func (d *AD) Ping(ctx context.Context) (string, error) {
	var who string
	err := d.do(ctx, func(c *ad.Conn) error {
		var err error
		who, err = c.WhoAmI(ctx)
		return err
	})
	return who, err
}

// FindBySID implements Directory.
func (d *AD) FindBySID(ctx context.Context, s sid.SID) (string, error) {
	var dn string
	err := d.do(ctx, func(c *ad.Conn) error {
		var err error
		dn, err = c.FindBySID(ctx, s)
		return err
	})
	return dn, err
}

// FindUsers implements Directory.
func (d *AD) FindUsers(ctx context.Context, v string) ([]string, error) {
	var out []string
	err := d.do(ctx, func(c *ad.Conn) error {
		out = nil
		f := escape.And(escape.Eq("objectCategory", "person"), escape.Eq("objectClass", "user"),
			escape.Or(escape.Eq("sAMAccountName", v), escape.Eq("mail", v)))
		entries, err := c.SearchAll(ctx, ad.SearchRequest{Filter: f, Attributes: []string{"1.1"}, Limit: 2})
		if err != nil {
			return err
		}
		for _, e := range entries {
			out = append(out, e.DN)
		}
		return nil
	})
	return out, err
}

// Get implements Directory.
func (d *AD) Get(ctx context.Context, dn string) (Entry, error) {
	var out Entry
	err := d.do(ctx, func(c *ad.Conn) error {
		e, err := c.Get(ctx, dn, EntryAttributes...)
		if err != nil {
			return err
		}
		out = Entry{User: ad.UserFromEntry(e), Classes: e.GetAttributeValues("objectClass"),
			AdminCount: strings.TrimSpace(e.GetAttributeValue("adminCount")) == "1",
			Marker:     e.GetAttributeValue(provapi.MarkerAttribute), ProxyAddresses: e.GetAttributeValues("proxyAddresses"),
			EmployeeID: e.GetAttributeValue("employeeID")}
		if out.DN == "" {
			out.DN = e.DN
		}
		return nil
	})
	return out, err
}

// TokenGroups implements Directory.
func (d *AD) TokenGroups(ctx context.Context, dn string) ([]sid.SID, error) {
	var out []sid.SID
	err := d.do(ctx, func(c *ad.Conn) error {
		var err error
		out, err = c.TokenGroups(ctx, dn)
		return err
	})
	return out, err
}

// BuildIndex implements Directory.
func (d *AD) BuildIndex(ctx context.Context, opt privilege.Options) (Index, error) {
	var x *privilege.Index
	err := d.do(ctx, func(c *ad.Conn) error {
		var err error
		x, err = privilege.Build(ctx, c, opt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return x, nil
}

// Apply implements Directory.
func (d *AD) Apply(ctx context.Context, op *ad.Operation) error {
	return d.do(ctx, func(c *ad.Conn) error { return c.Apply(ctx, op) })
}

// SchemaHasAttribute implements Directory: an attributeSchema object with
// that lDAPDisplayName in the schema naming context.
func (d *AD) SchemaHasAttribute(ctx context.Context, name string) (bool, error) {
	var found bool
	err := d.do(ctx, func(c *ad.Conn) error {
		entries, err := c.SearchAll(ctx, ad.SearchRequest{BaseDN: "CN=Schema," + c.ConfigurationDN(), Scope: ad.ScopeOneLevel,
			Filter:     escape.And(escape.Eq("objectClass", "attributeSchema"), escape.Eq("lDAPDisplayName", name)),
			Attributes: []string{"1.1"}, Limit: 1})
		if err != nil {
			return err
		}
		found = len(entries) > 0
		return nil
	})
	return found, err
}

// maxConflicts bounds a FindConflicts result: one match is enough to
// refuse, a few name every kind that collided.
const maxConflicts = 10

// FindConflicts implements Directory over the whole domain, any object
// class.
func (d *AD) FindConflicts(ctx context.Context, q ConflictQuery) ([]Match, error) {
	var parts []escape.Filter
	if q.SAM != "" {
		parts = append(parts, escape.Eq("sAMAccountName", q.SAM))
	}
	if q.UPN != "" {
		parts = append(parts, escape.Eq("userPrincipalName", q.UPN))
	}
	if q.Mail != "" {
		parts = append(parts, escape.Eq("mail", q.Mail), escape.Eq("userPrincipalName", q.Mail),
			escape.Eq("proxyAddresses", "smtp:"+q.Mail), escape.Eq("proxyAddresses", "SMTP:"+q.Mail))
	}
	if q.Marker != "" {
		parts = append(parts, escape.Eq(provapi.MarkerAttribute, q.Marker))
	}
	if len(parts) == 0 {
		return nil, nil
	}
	var out []Match
	err := d.do(ctx, func(c *ad.Conn) error {
		out = nil
		entries, err := c.SearchAll(ctx, ad.SearchRequest{Filter: escape.Or(parts...), Limit: maxConflicts,
			Attributes: []string{"objectSid", "sAMAccountName", "userPrincipalName", "mail", "proxyAddresses", provapi.MarkerAttribute}})
		if err != nil {
			return err
		}
		for _, e := range entries {
			u := ad.UserFromEntry(e)
			out = append(out, Match{DN: e.DN, SID: u.SID, Kinds: MatchKinds(q, u.SAMAccountName, u.UserPrincipalName, u.Mail,
				e.GetAttributeValue(provapi.MarkerAttribute), e.GetAttributeValues("proxyAddresses"))})
		}
		return nil
	})
	return out, err
}

// MatchKinds says which values of q an object's attributes hold
// (case-insensitive, as the directory compares them).
func MatchKinds(q ConflictQuery, sam, upn, mail, marker string, proxies []string) []string {
	var kinds []string
	eq := func(a, b string) bool { return a != "" && strings.EqualFold(a, b) }
	if eq(q.SAM, sam) {
		kinds = append(kinds, "sam")
	}
	if eq(q.UPN, upn) {
		kinds = append(kinds, "upn")
	}
	mailHit := eq(q.Mail, mail) || eq(q.Mail, upn)
	for _, p := range proxies {
		if len(p) > 5 && strings.EqualFold(p[:5], "smtp:") && eq(q.Mail, p[5:]) {
			mailHit = true
		}
	}
	if mailHit {
		kinds = append(kinds, "mail")
	}
	if eq(q.Marker, marker) {
		kinds = append(kinds, "marker")
	}
	return kinds
}

// CreateUser implements Directory. The samba-conductor-ad version this
// module pins has no constructor that writes provapi.MarkerAttribute, and
// an account must never exist without its marker (it would look like an
// unmanaged account in the scope), so the create is refused before any
// write until the ad module can express it.
func (d *AD) CreateUser(_ context.Context, _ NewUser) error {
	return fmt.Errorf("%w: creating an account with %s needs a samba-conductor-ad version that can write it",
		ErrUnsupported, provapi.MarkerAttribute)
}

// updateField returns the field of the ad module's UserUpdate that writes
// a plan attribute (nil when UserUpdate has none).
func updateField(u *ad.UserUpdate, attr string) **string {
	switch attr {
	case "givenName":
		return &u.GivenName
	case "sn":
		return &u.Surname
	case "displayName":
		return &u.DisplayName
	case "mail":
		return &u.Mail
	case "title":
		return &u.Title
	case "department":
		return &u.Department
	case "telephoneNumber":
		return &u.TelephoneNumber
	case "mobile":
		return &u.Mobile
	}
	return nil
}

// ModifyUser implements Directory with the ad module's UserUpdate (one
// modify request). Attributes UserUpdate cannot write (employeeID,
// proxyAddresses) are refused before any write.
func (d *AD) ModifyUser(ctx context.Context, dn string, changes []AttrChange) error {
	var u ad.UserUpdate
	for _, ch := range changes {
		f := updateField(&u, ch.Name)
		if f == nil || len(ch.After) > 1 {
			return fmt.Errorf("%w: writing %s needs a samba-conductor-ad version that can write it", ErrUnsupported, ch.Name)
		}
		v := ""
		if len(ch.After) == 1 {
			v = ch.After[0]
		}
		*f = &v
	}
	op, err := ad.UpdateUser(dn, u)
	if err != nil {
		return err
	}
	return d.Apply(ctx, op)
}

// AccountSID resolves the delegated account's own SID.
func (d *AD) AccountSID(ctx context.Context) (sid.SID, error) {
	var out sid.SID
	err := d.do(ctx, func(c *ad.Conn) error {
		u, err := c.FindUser(ctx, d.username)
		if err != nil {
			return err
		}
		out = u.SID
		return nil
	})
	return out, err
}
