package server

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"slices"
	"strings"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// The Google-first plan operations. Each one names its target by SID
// (user.create: by the OU it creates in) and goes through the invariants
// of invariants.go, then through the marker: user.update,
// user.set_enabled and user.move act only on an account whose marker
// equals the one the request names, so they never touch an account the
// plan does not own. user.create writes the marker once; no operation
// changes it afterwards.

// passwordLength is the length of the random password of a new account.
const passwordLength = 32

// Password alphabet: four classes, so any password with one character of
// each satisfies the directory's complexity rule.
var passwordClasses = []string{
	"ABCDEFGHJKLMNPQRSTUVWXYZ",
	"abcdefghijkmnopqrstuvwxyz",
	"23456789",
	"!#%+-.:=_",
}

// randomPassword returns a password of passwordLength characters with
// every class present that contains none of avoid (case-insensitive;
// the directory refuses a password containing the account's name or a
// part of its full name). It is never logged, stored or returned.
func randomPassword(avoid []string) (string, error) {
	alphabet := strings.Join(passwordClasses, "")
	size := big.NewInt(int64(len(alphabet)))
	for range 64 {
		b := make([]byte, passwordLength)
		for i := range b {
			n, err := rand.Int(rand.Reader, size)
			if err != nil {
				return "", err
			}
			b[i] = alphabet[n.Int64()]
		}
		pw := string(b)
		ok := true
		for _, class := range passwordClasses {
			if !strings.ContainsAny(pw, class) {
				ok = false
			}
		}
		lower := strings.ToLower(pw)
		for _, a := range avoid {
			if len(a) >= 3 && strings.Contains(lower, strings.ToLower(a)) {
				ok = false
			}
		}
		if ok {
			return pw, nil
		}
	}
	return "", errors.New("no acceptable random password")
}

// nameParts are the parts of the names the password must not contain: the
// sAMAccountName and every token of the names, split as the directory
// splits them.
func nameParts(values ...string) []string {
	var out []string
	for _, v := range values {
		out = append(out, strings.FieldsFunc(v, func(r rune) bool {
			return strings.ContainsRune(" ,.-_#\t", r)
		})...)
	}
	return append(out, values...)
}

// requireMarker refuses an account that does not carry the marker.
func requireMarker(c *call, e directory.Entry, marker string) *provapi.Error {
	if e.Marker == marker {
		return nil
	}
	if e.Marker == "" {
		c.note("the account has no marker")
	} else {
		c.note("the account carries another marker")
	}
	return fail(provapi.CodeMarkerMismatch, "the account does not carry the marker of the request")
}

// requireOU reads an OU named by the caller: it must parse with an OU=
// first component and exist as an organizational unit.
func (s *Service) requireOU(ctx context.Context, c *call, dn, what string) *provapi.Error {
	parsed, err := escape.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) != 1 ||
		!strings.EqualFold(parsed.RDNs[0].Attributes[0].Type, "ou") {
		return fail(provapi.CodeInvalidParams, "%s: not an organizational unit (OU=...)", what)
	}
	e, err := s.dir.Get(ctx, dn)
	if errors.Is(err, ad.ErrNotFound) {
		return fail(provapi.CodeNotFound, "%s: no such OU", what)
	}
	if err != nil {
		return s.directoryError(c, what, err)
	}
	if !e.IsOU() {
		return fail(provapi.CodeInvalidParams, "%s: not an organizational unit", what)
	}
	return nil
}

// existsError builds the exists refusal with the kinds that collided.
func existsError(c *call, kinds []string) *provapi.Error {
	slices.Sort(kinds)
	kinds = slices.Compact(kinds)
	c.note("exists: %s", strings.Join(kinds, ","))
	pe := fail(provapi.CodeExists, "an object with the same %s already exists in the domain", strings.Join(kinds, ", "))
	pe.Kinds = kinds
	return pe
}

// writeResult re-reads the account after a write (by SID, so a move is
// followed) for the result.
func (s *Service) writeResult(ctx context.Context, c *call, e directory.Entry, changed bool) provapi.UserWriteResult {
	if dn, err := s.dir.FindBySID(ctx, e.SID); err == nil {
		if after, err := s.dir.Get(ctx, dn); err == nil {
			e = after
		}
	} else {
		c.note("re-read failed: %v", err)
	}
	return provapi.UserWriteResult{SID: e.SID.String(), SAM: e.SAMAccountName, DN: e.DN, Enabled: e.Enabled(), Changed: changed}
}

// ---- user.create ----

func opUserCreate(ctx context.Context, s *Service, c *call, p *provapi.UserCreateParams) (any, *provapi.Error) {
	c.reference, c.targetSAM = p.Reference, p.SAM
	c.note("marker %s", p.Marker)
	if len(s.cfg.Scope.OUs) == 0 {
		return nil, fail(provapi.CodeOutOfScope, "no scope OU is configured")
	}
	c.note("parent %s", escape.NormalizeDN(p.ScopeOU))
	if len(s.cfg.ScopesOf(p.ScopeOU)) == 0 {
		return nil, fail(provapi.CodeOutOfScope, "scope_ou is not a scope OU or below one")
	}
	if pe := s.requireOU(ctx, c, p.ScopeOU, "scope_ou"); pe != nil {
		return nil, pe
	}
	dn, err := escape.ChildDN("CN", p.CN, p.ScopeOU)
	if err != nil {
		return nil, fail(provapi.CodeInvalidParams, "cn: cannot form a DN")
	}
	if !s.cfg.InScope(dn) {
		return nil, fail(provapi.CodeOutOfScope, "the new account would not be below a scope OU")
	}
	has, err := s.dir.SchemaHasAttribute(ctx, provapi.MarkerAttribute)
	if err != nil {
		return nil, s.directoryError(c, "schema", err)
	}
	if !has {
		return nil, fail(provapi.CodeSchemaMissing, "the directory schema has no %s; Google-first accounts cannot be created",
			provapi.MarkerAttribute)
	}
	if _, err := s.dir.Get(ctx, dn); err == nil {
		return nil, existsError(c, []string{"dn"})
	} else if !errors.Is(err, ad.ErrNotFound) {
		return nil, s.directoryError(c, "read the new DN", err)
	}
	matches, err := s.dir.FindConflicts(ctx, directory.ConflictQuery{SAM: p.SAM, UPN: p.UPN, Mail: p.Mail, Marker: p.Marker})
	if err != nil {
		return nil, s.directoryError(c, "find conflicts", err)
	}
	if len(matches) > 0 {
		var kinds []string
		for _, m := range matches {
			kinds = append(kinds, m.Kinds...)
		}
		if len(kinds) == 0 {
			kinds = []string{"mail"}
		}
		return nil, existsError(c, kinds)
	}
	if !s.limits.allow(limitCreates, s.now()) {
		return nil, s.refuseRate(c, limitCreates)
	}
	attrs := map[string]string{}
	for k, v := range map[string]string{"givenName": p.GivenName, "sn": p.Sn, "displayName": p.DisplayName} {
		if v != "" {
			attrs[k] = v
		}
	}
	for k, v := range p.Fields {
		if v != "" {
			attrs[k] = v
		}
	}
	pw, err := randomPassword(nameParts(p.SAM, p.CN, p.GivenName, p.Sn, p.DisplayName))
	if err != nil {
		return nil, fail(provapi.CodeInternal, "no randomness")
	}
	err = s.dir.CreateUser(ctx, directory.NewUser{ParentDN: p.ScopeOU, CN: p.CN, SAM: p.SAM, UPN: p.UPN, Mail: p.Mail,
		Attrs: attrs, Marker: p.Marker, Password: pw})
	if err != nil {
		return nil, s.writeError(c, "create the account", err)
	}
	c.note("created disabled with a random password and pwdLastSet 0")
	r := provapi.UserCreateResult{SAM: p.SAM, DN: dn}
	e, err := s.dir.Get(ctx, dn)
	if err != nil {
		s.log.Warn("reading a created account failed", "sam", p.SAM, "err", err)
		c.note("read back failed: %v", err)
		return r, nil
	}
	c.targetSID = e.SID.String()
	r.SID, r.ObjectGUID, r.DN = e.SID.String(), e.GUID.String(), e.DN
	return r, nil
}

// ---- user.update ----

// sameValues compares current values with the caller's before values:
// exactly, as a set for a multi-valued attribute.
func sameValues(cur, want []string) bool {
	a, b := slices.Clone(cur), slices.Clone(want)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// planValues turns the protocol form of a value into values.
func planValues(attr, v string) []string {
	if provapi.MultiValued(attr) {
		return provapi.SplitValues(v)
	}
	if v == "" {
		return nil
	}
	return []string{v}
}

func opUserUpdate(ctx context.Context, s *Service, c *call, p *provapi.UserUpdateParams) (any, *provapi.Error) {
	c.reference = p.Reference
	e, pe := s.readTarget(ctx, c, p.SID)
	if pe != nil {
		return nil, pe
	}
	if pe := s.requireEligible(ctx, c, e); pe != nil {
		return nil, pe
	}
	if pe := requireMarker(c, e, p.Marker); pe != nil {
		return nil, pe
	}
	var conflicts, names []string
	changes := make([]directory.AttrChange, 0, len(p.Changes))
	newMail := ""
	for _, ch := range p.Changes {
		before, after := planValues(ch.Attr, ch.Before), planValues(ch.Attr, ch.After)
		if !sameValues(e.Values(ch.Attr), before) {
			conflicts = append(conflicts, ch.Attr)
		}
		if ch.Attr == "mail" {
			newMail = ch.After
		}
		names = append(names, ch.Attr)
		changes = append(changes, directory.AttrChange{Name: ch.Attr, Before: before, After: after})
	}
	if len(conflicts) > 0 {
		c.note("conflict: %s", strings.Join(conflicts, ","))
		pe := fail(provapi.CodeConflict, "the current value of %s is not the expected one", strings.Join(conflicts, ", "))
		pe.Kinds = conflicts
		return nil, pe
	}
	if newMail != "" {
		// A new primary address used by another object would make the
		// address ambiguous (invitations and resets go to it).
		matches, err := s.dir.FindConflicts(ctx, directory.ConflictQuery{Mail: newMail})
		if err != nil {
			return nil, s.directoryError(c, "find conflicts", err)
		}
		for _, m := range matches {
			if !m.SID.Equal(e.SID) && !escape.EqualDN(m.DN, e.DN) {
				return nil, existsError(c, []string{"mail"})
			}
		}
	}
	if !s.limits.allow(limitUpdates, s.now()) {
		return nil, s.refuseRate(c, limitUpdates)
	}
	if err := s.dir.ModifyUser(ctx, e.DN, changes); err != nil {
		return nil, s.writeError(c, "update the account", err)
	}
	c.note("changed %s", strings.Join(names, ","))
	return s.writeResult(ctx, c, e, true), nil
}

// ---- user.set_enabled ----

func opUserSetEnabled(ctx context.Context, s *Service, c *call, p *provapi.UserSetEnabledParams) (any, *provapi.Error) {
	c.reference = p.Reference
	verb := "disable"
	if p.Enabled {
		verb = "enable"
	}
	c.note("%s", verb)
	e, pe := s.readTarget(ctx, c, p.SID)
	if pe != nil {
		return nil, pe
	}
	if pe := s.requireEligible(ctx, c, e); pe != nil {
		return nil, pe
	}
	if pe := requireMarker(c, e, p.Marker); pe != nil {
		return nil, pe
	}
	changed := false
	if e.Enabled() != p.Enabled {
		kind := limitDisables
		if p.Enabled {
			kind = limitEnables
		}
		if !s.limits.allow(kind, s.now()) {
			return nil, s.refuseRate(c, kind)
		}
		op, err := ad.SetUserEnabled(e.User, p.Enabled)
		if err != nil {
			return nil, fail(provapi.CodeInternal, "building the %s failed", verb)
		}
		if err := s.dir.Apply(ctx, op); err != nil {
			return nil, s.writeError(c, verb+" the account", err)
		}
		changed = true
		c.note("account %sd", verb)
	} else {
		c.note("already %sd", verb)
	}
	if !p.Enabled {
		// An open invitation would enable the account again
		// (invite.complete): a disabled account keeps no token.
		n, err := s.st.RevokeTokens(ctx, e.SID.String(), "", "disabled-by-plan")
		if err != nil {
			return nil, s.storeError(c, err)
		}
		if n > 0 {
			c.note("revoked %d open token(s)", n)
		}
	}
	return s.writeResult(ctx, c, e, changed), nil
}

// ---- user.move ----

func opUserMove(ctx context.Context, s *Service, c *call, p *provapi.UserMoveParams) (any, *provapi.Error) {
	c.reference = p.Reference
	e, pe := s.readTarget(ctx, c, p.SID)
	if pe != nil {
		return nil, pe
	}
	if pe := s.requireEligible(ctx, c, e); pe != nil {
		return nil, pe
	}
	if pe := requireMarker(c, e, p.Marker); pe != nil {
		return nil, pe
	}
	parent, _, err := escape.ParentDN(e.DN)
	if err != nil {
		return nil, s.directoryError(c, "parent of the account", err)
	}
	c.note("from %s to %s", escape.NormalizeDN(parent), escape.NormalizeDN(p.ToOU))
	from, to := s.cfg.ScopesOf(parent), s.cfg.ScopesOf(p.ToOU)
	same := slices.ContainsFunc(from, func(i int) bool { return slices.Contains(to, i) })
	if !same {
		return nil, fail(provapi.CodeOutOfScope, "to_ou is not below the scope OU of the account")
	}
	if escape.EqualDN(parent, p.ToOU) {
		c.note("already there")
		return s.writeResult(ctx, c, e, false), nil
	}
	if pe := s.requireOU(ctx, c, p.ToOU, "to_ou"); pe != nil {
		return nil, pe
	}
	if !s.limits.allow(limitMoves, s.now()) {
		return nil, s.refuseRate(c, limitMoves)
	}
	op, err := ad.MoveObject(e.DN, p.ToOU)
	if err != nil {
		return nil, fail(provapi.CodeInvalidParams, "to_ou: cannot move there")
	}
	if err := s.dir.Apply(ctx, op); err != nil {
		return nil, s.writeError(c, "move the account", err)
	}
	c.note("moved")
	return s.writeResult(ctx, c, e, true), nil
}
