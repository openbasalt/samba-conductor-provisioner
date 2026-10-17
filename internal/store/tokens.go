package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Token states (the same strings as provapi).
const (
	StateOpen        = "open"
	StatePasswordSet = "password_set"
	StateUsed        = "used"
	StateRevoked     = "revoked"
	StateExpired     = "expired"
)

// ErrNotFound: no such token.
var ErrNotFound = errors.New("store: not found")

// ErrConflict: the token's state changed concurrently.
var ErrConflict = errors.New("store: token state changed")

// Token is one stored token. Hash is the domain-separated SHA-256 of the
// raw token; the raw token is never stored.
type Token struct {
	ID      string
	Hash    []byte
	Purpose string
	SID     string
	GUID    string
	SAM     string
	// PwdLastSet is the account's pwdLastSet when the token was issued,
	// and after an invitation's password step the value that step wrote.
	PwdLastSet int64
	// WasDisabled: the account was disabled at issue (only then does
	// invite.complete enable it).
	WasDisabled   bool
	IssuedBy      string
	Reference     string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	State         string
	StateReason   string
	PasswordSetAt time.Time
	ClosedAt      time.Time
}

// Open reports whether the token can still be used.
func (t Token) Open() bool { return t.State == StateOpen || t.State == StatePasswordSet }

const tokenCols = `id, hash, purpose, sid, guid, sam, pwd_last_set, was_disabled, issued_by, reference,
	issued_at, expires_at, state, state_reason, password_set_at, closed_at`

func scanToken(sc interface{ Scan(...any) error }) (Token, error) {
	var t Token
	var issued, expires, pwSet, closed string
	var wasDisabled int
	err := sc.Scan(&t.ID, &t.Hash, &t.Purpose, &t.SID, &t.GUID, &t.SAM, &t.PwdLastSet, &wasDisabled, &t.IssuedBy,
		&t.Reference, &issued, &expires, &t.State, &t.StateReason, &pwSet, &closed)
	t.WasDisabled = wasDisabled != 0
	t.IssuedAt, t.ExpiresAt, t.PasswordSetAt, t.ClosedAt = parseTS(issued), parseTS(expires), parseTS(pwSet), parseTS(closed)
	return t, err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IssueToken stores a new open token and, in the same transaction,
// revokes the account's open tokens of the same purpose (reason
// "superseded"). It returns how many were revoked.
func (s *Store) IssueToken(ctx context.Context, t Token) (int, error) {
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE tokens SET state = ?, state_reason = 'superseded', closed_at = ?
		WHERE sid = ? AND purpose = ? AND state IN (?, ?)`, StateRevoked, ts(now), t.SID, t.Purpose, StateOpen, StatePasswordSet)
	if err != nil {
		return 0, err
	}
	revoked, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `INSERT INTO tokens(`+tokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, t.Purpose, t.SID, t.GUID, clip(t.SAM, 256), t.PwdLastSet, boolInt(t.WasDisabled), clip(t.IssuedBy, 256),
		clip(t.Reference, 128), ts(t.IssuedAt), ts(t.ExpiresAt), StateOpen, "", "", ""); err != nil {
		return 0, err
	}
	return int(revoked), tx.Commit()
}

// TokenByHash finds a token by its hash (ErrNotFound).
func (s *Store) TokenByHash(ctx context.Context, hash []byte) (Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return t, err
}

// CloseToken moves an open token (state open or password_set) to a final
// state (used, revoked or expired) with a reason. ErrConflict when the
// token was no longer in the expected state.
func (s *Store) CloseToken(ctx context.Context, id, from, state, reason string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET state = ?, state_reason = ?, closed_at = ? WHERE id = ? AND state = ?`,
		state, clip(reason, 64), ts(s.now()), id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}

// MarkPasswordSet records an invitation's password step: the state
// becomes password_set, the expiry is shortened to expiresAt and
// pwdLastSet is the value the step wrote.
func (s *Store) MarkPasswordSet(ctx context.Context, id string, expiresAt time.Time, pwdLastSet int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET state = ?, password_set_at = ?, expires_at = ?, pwd_last_set = ?
		WHERE id = ? AND state = ?`, StatePasswordSet, ts(s.now()), ts(expiresAt), pwdLastSet, id, StateOpen)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}

// RevokeTokens revokes the account's open tokens (of one purpose, or all
// when purpose is empty) and returns how many.
func (s *Store) RevokeTokens(ctx context.Context, sid, purpose, reason string) (int, error) {
	q := `UPDATE tokens SET state = ?, state_reason = ?, closed_at = ? WHERE sid = ? AND state IN (?, ?)`
	args := []any{StateRevoked, clip(reason, 64), ts(s.now()), sid, StateOpen, StatePasswordSet}
	if purpose != "" {
		q += ` AND purpose = ?`
		args = append(args, purpose)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ExpireDue marks open tokens past their expiry as expired.
func (s *Store) ExpireDue(ctx context.Context) (int, error) {
	now := ts(s.now())
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET state = ?, state_reason = 'expired', closed_at = ?
		WHERE state IN (?, ?) AND expires_at <= ?`, StateExpired, now, StateOpen, StatePasswordSet, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Prune deletes closed tokens issued before the cutoff.
func (s *Store) Prune(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE state NOT IN (?, ?) AND issued_at < ?`,
		StateOpen, StatePasswordSet, ts(before))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListTokens returns the account's tokens, newest first.
func (s *Store) ListTokens(ctx context.Context, sid string, limit int, openOnly bool) ([]Token, error) {
	q := `SELECT ` + tokenCols + ` FROM tokens WHERE sid = ?`
	args := []any{sid}
	if openOnly {
		q += ` AND state IN (?, ?)`
		args = append(args, StateOpen, StatePasswordSet)
	}
	q += ` ORDER BY issued_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountIssuedSince counts the tokens issued for the account since t.
func (s *Store) CountIssuedSince(ctx context.Context, sid string, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens WHERE sid = ? AND issued_at >= ?`, sid, ts(t)).Scan(&n)
	return n, err
}

// CountByState counts every stored token by state.
func (s *Store) CountByState(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM tokens GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
