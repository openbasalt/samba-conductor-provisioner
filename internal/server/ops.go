package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

func (s *Service) storeError(c *call, err error) *provapi.Error {
	s.log.Error("state database failed", "op", c.op, "err", err)
	return fail(provapi.CodeInternal, "the state database failed")
}

// ---- status ----

func opStatus(ctx context.Context, s *Service, c *call, _ *provapi.NoParams) (any, *provapi.Error) {
	if _, err := s.st.ExpireDue(ctx); err != nil {
		return nil, s.storeError(c, err)
	}
	counts, err := s.st.CountByState(ctx)
	if err != nil {
		return nil, s.storeError(c, err)
	}
	now := s.now()
	use := func(kind string) provapi.LimitUse {
		u, ceil := s.limits.use(kind, now)
		return provapi.LimitUse{Used: u, Ceiling: ceil}
	}
	return provapi.StatusResult{
		Version:      s.version,
		Account:      s.cfg.Account.Username,
		ScopeOUs:     append([]string{}, s.cfg.Scope.OUs...),
		IndexBuiltAt: s.indexBuiltAt().UTC(),
		Limits: provapi.Limits{TokenIssues: use(limitTokenIssues), PasswordSets: use(limitPasswordSets),
			Enables: use(limitEnables)},
		TokenCounts: provapi.TokenCounts{Open: counts[store.StateOpen], PasswordSet: counts[store.StatePasswordSet],
			Used: counts[store.StateUsed], Revoked: counts[store.StateRevoked], Expired: counts[store.StateExpired]},
	}, nil
}

// ---- user.check, user.find ----

// userResult builds the user.check shape for an account read by
// readTarget or readEntry.
func (s *Service) userResult(ctx context.Context, c *call, e directory.Entry) (provapi.UserResult, *provapi.Error) {
	a, pe := s.assess(ctx, c, e)
	if pe != nil {
		return provapi.UserResult{}, pe
	}
	if _, err := s.st.ExpireDue(ctx); err != nil {
		return provapi.UserResult{}, s.storeError(c, err)
	}
	pending, err := s.st.ListTokens(ctx, e.SID.String(), provapi.MaxTokenList, true)
	if err != nil {
		return provapi.UserResult{}, s.storeError(c, err)
	}
	r := provapi.UserResult{SID: e.SID.String(), SAM: e.SAMAccountName, DN: e.DN, Mail: e.Mail, Enabled: e.Enabled(),
		Locked: e.Locked(), InScope: a.inScope && len(s.cfg.Scope.OUs) > 0, Privileged: len(a.reasons) > 0,
		PrivilegedReasons: a.kinds(), PendingTokens: []provapi.PendingToken{}}
	for _, t := range pending {
		r.PendingTokens = append(r.PendingTokens, provapi.PendingToken{Purpose: t.Purpose, IssuedAt: t.IssuedAt,
			ExpiresAt: t.ExpiresAt, State: t.State})
	}
	return r, nil
}

func opUserCheck(ctx context.Context, s *Service, c *call, p *provapi.UserCheckParams) (any, *provapi.Error) {
	e, pe := s.readTarget(ctx, c, p.SID)
	if pe != nil {
		return nil, pe
	}
	r, pe := s.userResult(ctx, c, e)
	if pe != nil {
		return nil, pe
	}
	return r, nil
}

func opUserFind(ctx context.Context, s *Service, c *call, p *provapi.UserFindParams) (any, *provapi.Error) {
	c.note("identifier %s", identifierDigest(p.UsernameOrMail))
	dns, err := s.dir.FindUsers(ctx, p.UsernameOrMail)
	if err != nil {
		return nil, s.directoryError(c, "find user", err)
	}
	if len(dns) != 1 {
		if len(dns) > 1 {
			c.note("several accounts match")
		}
		return nil, fail(provapi.CodeNotFound, "no single user account matches")
	}
	e, pe := s.readEntry(ctx, c, dns[0], nil)
	if pe != nil {
		return nil, pe
	}
	// The match must hold on the account as read now.
	if !strings.EqualFold(e.SAMAccountName, p.UsernameOrMail) && !strings.EqualFold(e.Mail, p.UsernameOrMail) {
		return nil, fail(provapi.CodeNotFound, "no single user account matches")
	}
	r, pe := s.userResult(ctx, c, e)
	if pe != nil {
		return nil, pe
	}
	return r, nil
}

// ---- token.issue ----

func randomToken() (raw, id string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), hex.EncodeToString(idb), nil
}

// refuseRate builds a rate_limited refusal and logs it at warning at most
// once a minute per kind.
func (s *Service) refuseRate(c *call, kind string) *provapi.Error {
	if s.limits.shouldWarn(kind, s.now()) {
		s.log.Warn("hourly ceiling reached; refusing", "ceiling", kind, "op", c.op)
	}
	return fail(provapi.CodeRateLimited, "the hourly ceiling of %s is reached", kind)
}

func opTokenIssue(ctx context.Context, s *Service, c *call, p *provapi.TokenIssueParams) (any, *provapi.Error) {
	c.reference = p.Reference
	c.note("purpose %s", p.Purpose)
	e, pe := s.readTarget(ctx, c, p.SID)
	if pe != nil {
		return nil, pe
	}
	if pe := s.requireEligible(ctx, c, e); pe != nil {
		return nil, pe
	}
	if !e.Enabled() && p.Purpose == provapi.PurposeReset {
		return nil, fail(provapi.CodeInvalidParams, "a disabled account cannot be reset by link")
	}
	now := s.now().UTC()
	n, err := s.st.CountIssuedSince(ctx, p.SID, now.Add(-24*time.Hour))
	if err != nil {
		return nil, s.storeError(c, err)
	}
	if n >= s.cfg.Tokens.PerUserPerDay {
		return nil, fail(provapi.CodeRateLimited, "the daily limit of tokens for this account is reached")
	}
	if !s.limits.allow(limitTokenIssues, now) {
		return nil, s.refuseRate(c, limitTokenIssues)
	}
	raw, id, err := randomToken()
	if err != nil {
		return nil, fail(provapi.CodeInternal, "no randomness")
	}
	ttl := time.Duration(s.cfg.Tokens.ResetMinutes) * time.Minute
	if p.Purpose == provapi.PurposeInvite {
		ttl = time.Duration(s.cfg.Tokens.InviteHours) * time.Hour
	}
	t := store.Token{ID: id, Hash: hashToken(raw), Purpose: p.Purpose, SID: p.SID, GUID: e.GUID.String(), SAM: e.SAMAccountName,
		PwdLastSet: int64(e.PwdLastSet), WasDisabled: !e.Enabled(), IssuedBy: c.actor, Reference: p.Reference,
		IssuedAt: now, ExpiresAt: now.Add(ttl)}
	revoked, err := s.st.IssueToken(ctx, t)
	if err != nil {
		return nil, s.storeError(c, err)
	}
	c.tokenID = id
	c.note("expires %s", t.ExpiresAt.Format(time.RFC3339))
	if revoked > 0 {
		c.note("superseded %d open token(s)", revoked)
	}
	return provapi.TokenIssueResult{Token: raw, TokenID: id, ExpiresAt: t.ExpiresAt, SAM: e.SAMAccountName, DN: e.DN, Mail: e.Mail}, nil
}

// ---- token resolution (token.check, password.set, invite.complete) ----

// closeToken moves a token to a final state; a concurrent change is not
// an error here (the token is closed either way).
func (s *Service) closeToken(ctx context.Context, c *call, t store.Token, state, reason string) {
	if err := s.st.CloseToken(ctx, t.ID, t.State, state, reason); err != nil && !errors.Is(err, store.ErrConflict) {
		s.log.Error("closing a token failed", "token_id", t.ID, "err", err)
	}
	c.note("token %s (%s)", state, reason)
}

// resolveToken applies the token checks of token.check: known, not used,
// not revoked, not expired, same account (SID and objectGUID) with the
// same pwdLastSet, still in scope and not privileged.
func (s *Service) resolveToken(ctx context.Context, c *call, raw string) (store.Token, directory.Entry, *provapi.Error) {
	t, err := s.st.TokenByHash(ctx, hashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return t, directory.Entry{}, fail(provapi.CodeNotFound, "unknown token")
	}
	if err != nil {
		return t, directory.Entry{}, s.storeError(c, err)
	}
	c.tokenID, c.targetSID, c.targetSAM, c.reference = t.ID, t.SID, t.SAM, t.Reference
	switch t.State {
	case store.StateUsed:
		return t, directory.Entry{}, fail(provapi.CodeUsed, "the token was used")
	case store.StateRevoked:
		return t, directory.Entry{}, fail(provapi.CodeRevoked, "the token was revoked")
	case store.StateExpired:
		return t, directory.Entry{}, fail(provapi.CodeExpired, "the token expired")
	}
	if !s.now().Before(t.ExpiresAt) {
		s.closeToken(ctx, c, t, store.StateExpired, "expired")
		return t, directory.Entry{}, fail(provapi.CodeExpired, "the token expired")
	}
	e, pe := s.readTarget(ctx, c, t.SID)
	if pe != nil {
		if pe.Code == provapi.CodeNotFound {
			s.closeToken(ctx, c, t, store.StateRevoked, "account-gone")
		}
		return t, e, pe
	}
	if e.GUID.String() != t.GUID {
		s.closeToken(ctx, c, t, store.StateRevoked, "account-replaced")
		return t, e, fail(provapi.CodeStale, "the account changed since the token was issued")
	}
	if int64(e.PwdLastSet) != t.PwdLastSet {
		s.closeToken(ctx, c, t, store.StateRevoked, "stale")
		return t, e, fail(provapi.CodeStale, "the account's password changed since the token was issued")
	}
	if pe := s.requireEligible(ctx, c, e); pe != nil {
		return t, e, pe
	}
	return t, e, nil
}

func opTokenCheck(ctx context.Context, s *Service, c *call, p *provapi.TokenCheckParams) (any, *provapi.Error) {
	t, e, pe := s.resolveToken(ctx, c, p.Token)
	if pe != nil {
		return nil, pe
	}
	return provapi.TokenCheckResult{TokenID: t.ID, Purpose: t.Purpose, SAM: e.SAMAccountName, DN: e.DN, Mail: e.Mail,
		SID: t.SID, ExpiresAt: t.ExpiresAt, PasswordSet: t.State == store.StatePasswordSet}, nil
}

// ---- password.set ----

// policyReason maps the directory's password refusal to a reason.
func policyReason(err error) string {
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "too short"):
		return provapi.ReasonTooShort
	case strings.Contains(m, "complex"):
		return provapi.ReasonComplexity
	case strings.Contains(m, "history"), strings.Contains(m, "already used"), strings.Contains(m, "already been used"):
		return provapi.ReasonHistory
	case strings.Contains(m, "too young"), strings.Contains(m, "minimum password age"):
		return provapi.ReasonTooYoung
	}
	return provapi.ReasonOther
}

// writeError turns a refused write into the protocol error (details in
// the log and the audit entry, which never contain a password: the ad
// package redacts it and LDAP diagnostics do not echo it).
func (s *Service) writeError(c *call, what string, err error) *provapi.Error {
	s.log.Warn("directory write failed", "op", c.op, "what", what, "err", err)
	c.note("%s: %v", what, err)
	switch {
	case errors.Is(err, ad.ErrPasswordPolicy):
		pe := fail(provapi.CodePasswordPolicy, "the password does not satisfy the password policy")
		pe.Reason = policyReason(err)
		return pe
	case errors.Is(err, ad.ErrAccessDenied):
		return fail(provapi.CodeDirectory, "the delegated account may not %s (check its delegation)", what)
	case errors.Is(err, ad.ErrConflict):
		return fail(provapi.CodeDirectory, "the account changed while it was being written")
	}
	return fail(provapi.CodeDirectory, "the directory refused to %s", what)
}

func opPasswordSet(ctx context.Context, s *Service, c *call, p *provapi.PasswordSetParams) (any, *provapi.Error) {
	t, e, pe := s.resolveToken(ctx, c, p.Token)
	if pe != nil {
		return nil, pe
	}
	c.note("purpose %s", t.Purpose)
	if t.State != store.StateOpen {
		return nil, fail(provapi.CodeUsed, "the password of this invitation is already set")
	}
	if !s.limits.allow(limitPasswordSets, s.now()) {
		return nil, s.refuseRate(c, limitPasswordSets)
	}
	op, err := ad.ResetPassword(e.DN, p.NewPassword, false)
	if err != nil {
		return nil, fail(provapi.CodeInternal, "building the password reset failed")
	}
	if err := s.dir.Apply(ctx, op); err != nil {
		return nil, s.writeError(c, "set the password", err)
	}
	c.note("password set")
	if t.Purpose == provapi.PurposeReset && p.Unlock && e.LockoutTime != 0 {
		if op, err := ad.UnlockUser(e.DN); err == nil {
			if err := s.dir.Apply(ctx, op); err != nil {
				s.log.Warn("clearing the lockout failed", "sam", e.SAMAccountName, "err", err)
				c.note("unlock failed: %v", err)
			} else {
				c.note("lockout cleared")
			}
		}
	}
	after, rerr := s.dir.Get(ctx, e.DN)
	switch {
	case t.Purpose == provapi.PurposeReset:
		if err := s.st.CloseToken(ctx, t.ID, store.StateOpen, store.StateUsed, "password-set"); err != nil {
			return nil, s.storeError(c, err)
		}
	case rerr != nil:
		// Without the new pwdLastSet the invitation cannot be completed
		// safely: revoke it (a new invitation is needed).
		s.closeToken(ctx, c, t, store.StateRevoked, "reread-failed")
		return nil, s.directoryError(c, "re-read after the password step", rerr)
	default:
		expires := s.now().UTC().Add(time.Duration(s.cfg.Tokens.CompleteMinutes) * time.Minute)
		if t.ExpiresAt.Before(expires) {
			expires = t.ExpiresAt
		}
		if err := s.st.MarkPasswordSet(ctx, t.ID, expires, int64(after.PwdLastSet)); err != nil {
			return nil, s.storeError(c, err)
		}
	}
	return provapi.PasswordSetResult{SAM: e.SAMAccountName, DN: e.DN, Mail: e.Mail, Purpose: t.Purpose}, nil
}

// ---- invite.complete ----

func opInviteComplete(ctx context.Context, s *Service, c *call, p *provapi.InviteCompleteParams) (any, *provapi.Error) {
	t, e, pe := s.resolveToken(ctx, c, p.Token)
	if pe != nil {
		return nil, pe
	}
	if t.Purpose != provapi.PurposeInvite {
		return nil, fail(provapi.CodeInvalidParams, "the token is not an invitation")
	}
	if t.State != store.StatePasswordSet {
		return nil, fail(provapi.CodeInvalidParams, "the password step of the invitation is not done")
	}
	if !e.Enabled() {
		if !t.WasDisabled {
			// Enabled at issue, disabled since: an administrator's
			// decision the invitation never undoes.
			s.closeToken(ctx, c, t, store.StateRevoked, "disabled-since-issue")
			return nil, fail(provapi.CodeStale, "the account was disabled after the invitation was issued")
		}
		if !s.limits.allow(limitEnables, s.now()) {
			return nil, s.refuseRate(c, limitEnables)
		}
		op, err := ad.SetUserEnabled(e.User, true)
		if err != nil {
			return nil, fail(provapi.CodeInternal, "building the enable failed")
		}
		if err := s.dir.Apply(ctx, op); err != nil {
			return nil, s.writeError(c, "enable the account", err)
		}
		c.note("account enabled")
	} else {
		c.note("account already enabled")
	}
	if err := s.st.CloseToken(ctx, t.ID, store.StatePasswordSet, store.StateUsed, "completed"); err != nil {
		return nil, s.storeError(c, err)
	}
	return provapi.InviteCompleteResult{SAM: e.SAMAccountName, DN: e.DN}, nil
}

// ---- token.revoke, token.list ----

func opTokenRevoke(ctx context.Context, s *Service, c *call, p *provapi.TokenRevokeParams) (any, *provapi.Error) {
	c.targetSID = p.SID
	c.note("reason %s", p.Reason)
	if p.Purpose != "" {
		c.note("purpose %s", p.Purpose)
	}
	n, err := s.st.RevokeTokens(ctx, p.SID, p.Purpose, p.Reason)
	if err != nil {
		return nil, s.storeError(c, err)
	}
	c.note("revoked %d", n)
	return provapi.TokenRevokeResult{Revoked: n}, nil
}

func opTokenList(ctx context.Context, s *Service, c *call, p *provapi.TokenListParams) (any, *provapi.Error) {
	c.targetSID = p.SID
	if _, err := s.st.ExpireDue(ctx); err != nil {
		return nil, s.storeError(c, err)
	}
	ts, err := s.st.ListTokens(ctx, p.SID, provapi.MaxTokenList, false)
	if err != nil {
		return nil, s.storeError(c, err)
	}
	out := make([]provapi.TokenInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, provapi.TokenInfo{TokenID: t.ID, Purpose: t.Purpose, IssuedAt: t.IssuedAt, IssuedBy: t.IssuedBy,
			ExpiresAt: t.ExpiresAt, State: t.State, Reference: t.Reference})
	}
	return out, nil
}
