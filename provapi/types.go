package provapi

import (
	"errors"
	"time"
)

// Token purposes.
const (
	PurposeInvite = "invite"
	PurposeReset  = "reset"
)

// Token states.
const (
	StateOpen        = "open"
	StatePasswordSet = "password_set"
	StateUsed        = "used"
	StateRevoked     = "revoked"
	StateExpired     = "expired"
)

// MaxPasswordBytes bounds a new password in password.set.
const MaxPasswordBytes = 1024

func validSID(s string) error {
	if !sidRE.MatchString(s) {
		return errors.New("sid: not a valid SID")
	}
	return nil
}

func validToken(t string) error {
	if !tokenRE.MatchString(t) {
		return errors.New("token: not a valid token")
	}
	return nil
}

func validPurpose(p string) error {
	if p != PurposeInvite && p != PurposeReset {
		return errors.New(`purpose: "invite" or "reset"`)
	}
	return nil
}

// ValidTokenID reports whether s has the shape of a token ID.
func ValidTokenID(s string) bool { return tokenIDRE.MatchString(s) }

// ---- status ----

// NoParams is used by operations without parameters.
type NoParams struct{}

// Validate implements Params.
func (NoParams) Validate() error { return nil }

// LimitUse is one hourly ceiling and its use in the last hour.
type LimitUse struct {
	Used    int `json:"used"`
	Ceiling int `json:"ceiling"`
}

// Limits are the hourly ceilings of the service's own configuration.
type Limits struct {
	TokenIssues  LimitUse `json:"token_issues"`
	PasswordSets LimitUse `json:"password_sets"`
	Enables      LimitUse `json:"enables"`
	// The ceilings of the plan operations: user.create, user.update,
	// user.move, and user.set_enabled with enabled=false (an enable by
	// user.set_enabled counts under Enables).
	Creates  LimitUse `json:"creates"`
	Updates  LimitUse `json:"updates"`
	Moves    LimitUse `json:"moves"`
	Disables LimitUse `json:"disables"`
}

// TokenCounts counts the stored tokens by state.
type TokenCounts struct {
	Open        int `json:"open"`
	PasswordSet int `json:"password_set"`
	Used        int `json:"used"`
	Revoked     int `json:"revoked"`
	Expired     int `json:"expired"`
}

// StatusResult is the result of status.
type StatusResult struct {
	// Version is the service's build version.
	Version string `json:"version"`
	// Account is the delegated account's name.
	Account string `json:"account"`
	// ScopeOUs are the normalized scope OUs (empty: every operation
	// that names a target is refused).
	ScopeOUs []string `json:"scope_ous"`
	// IndexBuiltAt is when the privilege index in use was built (zero
	// before the first build).
	IndexBuiltAt time.Time   `json:"index_built_at,omitzero"`
	Limits       Limits      `json:"limits"`
	TokenCounts  TokenCounts `json:"token_counts"`
}

// ---- user.check and user.find ----

// UserCheckParams reads one account by SID.
type UserCheckParams struct {
	SID string `json:"sid"`
}

// Validate implements Params.
func (p UserCheckParams) Validate() error { return validSID(p.SID) }

// UserFindParams resolves one account by sAMAccountName or mail. Exactly
// one user account must match; none or several is not_found.
type UserFindParams struct {
	UsernameOrMail string `json:"username_or_mail"`
}

// Validate implements Params.
func (p UserFindParams) Validate() error {
	if p.UsernameOrMail == "" || !oneLine(p.UsernameOrMail, 256) {
		return errors.New("username_or_mail: one line, 1 to 256 bytes")
	}
	return nil
}

// PendingToken is an open token of the account (no hash, no token).
type PendingToken struct {
	Purpose   string    `json:"purpose"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	State     string    `json:"state"`
}

// UserResult is the result of user.check and user.find: everything
// conductor needs before issuing a token or to show on the user page.
type UserResult struct {
	SID     string `json:"sid"`
	SAM     string `json:"sam"`
	DN      string `json:"dn"`
	Mail    string `json:"mail"`
	Enabled bool   `json:"enabled"`
	Locked  bool   `json:"locked"`
	// InScope: below one of the configured scope OUs.
	InScope bool `json:"in_scope"`
	// Privileged with the reason kinds (group, adminCount, acl, owner);
	// the details are in the service's audit and logs only.
	Privileged        bool           `json:"privileged"`
	PrivilegedReasons []string       `json:"privileged_reasons"`
	PendingTokens     []PendingToken `json:"pending_tokens"`
}

// ---- token.issue ----

// TokenIssueParams issues a one-time token for an account. Reference is
// the caller's own correlation value (for example a mail queue ID), kept
// with the token and in the audit log.
type TokenIssueParams struct {
	SID       string `json:"sid"`
	Purpose   string `json:"purpose"`
	Reference string `json:"reference,omitempty"`
}

// Validate implements Params.
func (p TokenIssueParams) Validate() error {
	if err := validSID(p.SID); err != nil {
		return err
	}
	if err := validPurpose(p.Purpose); err != nil {
		return err
	}
	if !oneLine(p.Reference, 128) {
		return errors.New("reference: one line, at most 128 bytes")
	}
	return nil
}

// TokenIssueResult carries the raw token, returned once.
type TokenIssueResult struct {
	Token     string    `json:"token"`
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
	SAM       string    `json:"sam"`
	DN        string    `json:"dn"`
	Mail      string    `json:"mail"`
}

// ---- token.check ----

// TokenCheckParams validates a token without consuming it.
type TokenCheckParams struct {
	Token string `json:"token"`
}

// Validate implements Params.
func (p TokenCheckParams) Validate() error { return validToken(p.Token) }

// TokenCheckResult describes a valid token and its account.
type TokenCheckResult struct {
	TokenID   string    `json:"token_id"`
	Purpose   string    `json:"purpose"`
	SAM       string    `json:"sam"`
	DN        string    `json:"dn"`
	Mail      string    `json:"mail"`
	SID       string    `json:"sid"`
	ExpiresAt time.Time `json:"expires_at"`
	// PasswordSet: an invitation whose password step is done (only
	// invite.complete is left).
	PasswordSet bool `json:"password_set"`
}

// ---- password.set ----

// PasswordSetParams sets the account's password with a token. Unlock
// clears a lockout on a reset token.
type PasswordSetParams struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
	Unlock      bool   `json:"unlock,omitempty"`
}

// Validate implements Params. The error never contains the password.
func (p PasswordSetParams) Validate() error {
	if err := validToken(p.Token); err != nil {
		return err
	}
	if p.NewPassword == "" || len(p.NewPassword) > MaxPasswordBytes {
		return errors.New("new_password: 1 to 1024 bytes")
	}
	for i := 0; i < len(p.NewPassword); i++ {
		if p.NewPassword[i] == 0 {
			return errors.New("new_password: NUL is not allowed")
		}
	}
	return nil
}

// PasswordSetResult names the account whose password was set.
type PasswordSetResult struct {
	SAM     string `json:"sam"`
	DN      string `json:"dn"`
	Mail    string `json:"mail"`
	Purpose string `json:"purpose"`
}

// ---- invite.complete ----

// InviteCompleteParams finishes an invitation after its password step.
type InviteCompleteParams struct {
	Token string `json:"token"`
}

// Validate implements Params.
func (p InviteCompleteParams) Validate() error { return validToken(p.Token) }

// InviteCompleteResult names the account that was enabled.
type InviteCompleteResult struct {
	SAM string `json:"sam"`
	DN  string `json:"dn"`
}

// ---- token.revoke ----

// TokenRevokeParams revokes the account's open tokens, of one purpose or
// all of them. Reason is a short label kept with the tokens and audited
// (for example "admin" or "mfa-failed").
type TokenRevokeParams struct {
	SID     string `json:"sid"`
	Purpose string `json:"purpose,omitempty"`
	Reason  string `json:"reason"`
}

// Validate implements Params.
func (p TokenRevokeParams) Validate() error {
	if err := validSID(p.SID); err != nil {
		return err
	}
	if p.Purpose != "" {
		if err := validPurpose(p.Purpose); err != nil {
			return err
		}
	}
	if p.Reason == "" || !oneLine(p.Reason, 64) {
		return errors.New("reason: one line, 1 to 64 bytes")
	}
	return nil
}

// TokenRevokeResult counts the revoked tokens.
type TokenRevokeResult struct {
	Revoked int `json:"revoked"`
}

// ---- token.list ----

// TokenListParams lists the account's tokens, newest first (at most
// MaxTokenList).
type TokenListParams struct {
	SID string `json:"sid"`
}

// Validate implements Params.
func (p TokenListParams) Validate() error { return validSID(p.SID) }

// MaxTokenList bounds a token.list result.
const MaxTokenList = 50

// TokenInfo is one token in token.list: never a hash or a token. The
// result of token.list is a JSON array of TokenInfo.
type TokenInfo struct {
	TokenID   string    `json:"token_id"`
	Purpose   string    `json:"purpose"`
	IssuedAt  time.Time `json:"issued_at"`
	IssuedBy  string    `json:"issued_by"`
	ExpiresAt time.Time `json:"expires_at"`
	State     string    `json:"state"`
	Reference string    `json:"reference"`
}
