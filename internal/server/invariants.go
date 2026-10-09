package server

import (
	"context"
	"errors"
	"slices"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// directoryError turns a read failure into the protocol error (details in
// the log only).
func (s *Service) directoryError(c *call, what string, err error) *provapi.Error {
	s.log.Warn("directory read failed", "op", c.op, "what", what, "err", err)
	c.note("%s: %v", what, err)
	return fail(provapi.CodeDirectory, "reading the directory failed (%s)", what)
}

// readTarget reads the account with that SID fresh from the directory
// (invariants 1 and 3: by SID, a user account).
func (s *Service) readTarget(ctx context.Context, c *call, sidText string) (directory.Entry, *provapi.Error) {
	c.targetSID = sidText
	want, err := sid.Parse(sidText)
	if err != nil {
		return directory.Entry{}, fail(provapi.CodeInvalidParams, "sid: not a valid SID")
	}
	dn, err := s.dir.FindBySID(ctx, want)
	if errors.Is(err, ad.ErrNotFound) {
		return directory.Entry{}, fail(provapi.CodeNotFound, "no user account with that SID")
	}
	if err != nil {
		return directory.Entry{}, s.directoryError(c, "find by SID", err)
	}
	return s.readEntry(ctx, c, dn, &want)
}

// readEntry reads one object by DN and checks it is a user account (and,
// when want is set, that it still has that SID).
func (s *Service) readEntry(ctx context.Context, c *call, dn string, want *sid.SID) (directory.Entry, *provapi.Error) {
	e, err := s.dir.Get(ctx, dn)
	if errors.Is(err, ad.ErrNotFound) {
		return directory.Entry{}, fail(provapi.CodeNotFound, "no user account with that SID")
	}
	if err != nil {
		return directory.Entry{}, s.directoryError(c, "read account", err)
	}
	c.targetSAM = e.SAMAccountName
	if c.targetSID == "" && !e.SID.IsZero() {
		c.targetSID = e.SID.String()
	}
	if want != nil && !e.SID.Equal(*want) {
		c.note("the object found by SID carries another SID")
		return directory.Entry{}, fail(provapi.CodeNotFound, "no user account with that SID")
	}
	if !e.IsUser() {
		c.note("not a user account: %v", e.Classes)
		return directory.Entry{}, fail(provapi.CodeNotFound, "no user account with that SID")
	}
	return e, nil
}

// index returns the privilege index, rebuilt when older than
// index_cache_seconds (0: rebuilt for every operation). A failed build is
// a refusal: the service never acts without an index.
func (s *Service) index(ctx context.Context) (directory.Index, error) {
	s.idxMu.Lock()
	defer s.idxMu.Unlock()
	maxAge := time.Duration(s.cfg.Privileged.IndexCacheSeconds) * time.Second
	if s.idx != nil && maxAge > 0 && s.now().Sub(s.idx.BuiltAt()) < maxAge {
		return s.idx, nil
	}
	x, err := s.dir.BuildIndex(ctx, privilege.Options{ExtraGroupSIDs: s.cfg.ExtraGroupSIDs()})
	if err != nil {
		return nil, err
	}
	s.idx = x
	return x, nil
}

// indexBuiltAt is the build time of the index in use (zero before one).
func (s *Service) indexBuiltAt() time.Time {
	s.idxMu.Lock()
	defer s.idxMu.Unlock()
	if s.idx == nil {
		return time.Time{}
	}
	return s.idx.BuiltAt()
}

// assessment is what the invariants say about one account.
type assessment struct {
	inScope bool
	reasons []privilege.Reason
}

func (a assessment) kinds() []string {
	out := []string{}
	for _, r := range a.reasons {
		if !slices.Contains(out, r.Kind) {
			out = append(out, r.Kind)
		}
	}
	return out
}

// assess applies invariants 1 and 2 to an account read by readTarget:
// scope from its DN, privilege from the index plus its own adminCount and
// tokenGroups read now.
func (s *Service) assess(ctx context.Context, c *call, e directory.Entry) (assessment, *provapi.Error) {
	a := assessment{inScope: s.cfg.InScope(e.DN)}
	x, err := s.index(ctx)
	if err != nil {
		return a, s.directoryError(c, "privilege index", err)
	}
	if !e.SID.IsZero() {
		a.reasons = append(a.reasons, x.PrivilegedSID(e.SID)...)
	}
	if e.AdminCount {
		a.reasons = append(a.reasons, privilege.Reason{Kind: privilege.KindAdminCount, Detail: e.DN})
	}
	groups, err := s.dir.TokenGroups(ctx, e.DN)
	if err != nil {
		return a, s.directoryError(c, "token groups", err)
	}
	for _, g := range groups {
		a.reasons = append(a.reasons, x.PrivilegedSID(g)...)
	}
	return a, nil
}

// requireEligible refuses an account out of scope or privileged; the
// privilege reasons go to the audit entry, only their kinds to the caller.
func (s *Service) requireEligible(ctx context.Context, c *call, e directory.Entry) *provapi.Error {
	if len(s.cfg.Scope.OUs) == 0 {
		return fail(provapi.CodeOutOfScope, "no scope OU is configured")
	}
	a, pe := s.assess(ctx, c, e)
	if pe != nil {
		return pe
	}
	if !a.inScope {
		c.note("dn %s", e.DN)
		return fail(provapi.CodeOutOfScope, "the account is not below a scope OU")
	}
	if len(a.reasons) > 0 {
		for _, r := range a.reasons {
			c.note("privileged: %s %s", r.Kind, r.Detail)
		}
		pe := fail(provapi.CodePrivileged, "the account holds privileged rights; act on it directly in AD")
		pe.Kinds = a.kinds()
		return pe
	}
	return nil
}
