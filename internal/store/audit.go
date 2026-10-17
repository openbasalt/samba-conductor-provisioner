package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// GenesisHash is the prev_hash of the first audit row.
var GenesisHash = strings.Repeat("0", 64)

// AuditResultOK is the result of a successful operation; a refused one
// carries its provapi error code.
const AuditResultOK = "ok"

// AuditEvent is one audit row. Detail never holds a password or a token.
type AuditEvent struct {
	Seq       int64     `json:"seq"`
	At        time.Time `json:"at"`
	Actor     string    `json:"actor"`
	Op        string    `json:"op"`
	TargetSID string    `json:"target_sid"`
	TargetSAM string    `json:"target_sam"`
	TokenID   string    `json:"token_id"`
	Reference string    `json:"reference"`
	Result    string    `json:"result"`
	Detail    string    `json:"detail"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// chainHash is HMAC-SHA-256, keyed with the audit key, over the previous
// hash and the canonical JSON of every other field. Without the key a row
// cannot be rewritten with a valid chain, even by someone who can write
// the database file.
func (s *Store) chainHash(e AuditEvent) string {
	b, _ := json.Marshal(struct {
		Seq       int64  `json:"seq"`
		At        string `json:"at"`
		Actor     string `json:"actor"`
		Op        string `json:"op"`
		TargetSID string `json:"target_sid"`
		TargetSAM string `json:"target_sam"`
		TokenID   string `json:"token_id"`
		Reference string `json:"reference"`
		Result    string `json:"result"`
		Detail    string `json:"detail"`
	}{e.Seq, ts(e.At), e.Actor, e.Op, e.TargetSID, e.TargetSAM, e.TokenID, e.Reference, e.Result, e.Detail})
	h := hmac.New(sha256.New, s.auditKey)
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{'\n'})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendAudit adds an event at the end of the chain.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) (AuditEvent, error) {
	if s.auditKey == nil {
		return e, ErrNoAuditKey
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	e.At = s.now().Truncate(time.Microsecond)
	e.Actor, e.Op, e.Result = clip(e.Actor, 256), clip(e.Op, 64), clip(e.Result, 32)
	e.TargetSID, e.TargetSAM, e.TokenID, e.Reference = clip(e.TargetSID, 200), clip(e.TargetSAM, 256), clip(e.TokenID, 64), clip(e.Reference, 128)
	e.Detail = clip(e.Detail, 16<<10)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer func() { _ = tx.Rollback() }()
	var last int64
	var lastHash string
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&last, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		last, lastHash = 0, GenesisHash
	case err != nil:
		return e, err
	}
	e.Seq, e.PrevHash = last+1, lastHash
	e.Hash = s.chainHash(e)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(`+auditCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, ts(e.At), e.Actor, e.Op, e.TargetSID, e.TargetSAM, e.TokenID, e.Reference, e.Result, e.Detail, e.PrevHash, e.Hash); err != nil {
		return e, err
	}
	return e, tx.Commit()
}

const auditCols = `seq, at, actor, op, target_sid, target_sam, token_id, reference, result, detail, prev_hash, hash`

func scanAudit(sc interface{ Scan(...any) error }) (AuditEvent, error) {
	var e AuditEvent
	var at string
	err := sc.Scan(&e.Seq, &at, &e.Actor, &e.Op, &e.TargetSID, &e.TargetSAM, &e.TokenID, &e.Reference, &e.Result,
		&e.Detail, &e.PrevHash, &e.Hash)
	e.At = parseTS(at)
	return e, err
}

// ListAudit returns the newest events first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExportAudit writes every event as JSON lines, oldest first.
func (s *Store) ExportAudit(ctx context.Context, w io.Writer) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(w)
	n := 0
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return n, err
		}
		if err := enc.Encode(e); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// VerifyResult is the outcome of a chain check.
type VerifyResult struct {
	Rows     int
	LastHash string
	BrokenAt int64
	Reason   string
}

// ErrNoAuditKey: the store was opened without the audit key.
var ErrNoAuditKey = errors.New("store: opened without the audit key (state key)")

// AuditRows counts the audit rows.
func (s *Store) AuditRows(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&n)
	return n, err
}

// VerifyAudit walks the chain from the genesis hash.
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	if s.auditKey == nil {
		return VerifyResult{}, ErrNoAuditKey
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer func() { _ = rows.Close() }()
	res := VerifyResult{LastHash: GenesisHash}
	var expect int64 = 1
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return res, err
		}
		switch {
		case e.Seq != expect:
			res.BrokenAt, res.Reason = expect, fmt.Sprintf("row %d missing (found %d)", expect, e.Seq)
		case e.PrevHash != res.LastHash:
			res.BrokenAt, res.Reason = e.Seq, "prev_hash does not match the previous row"
		case !hmac.Equal([]byte(s.chainHash(e)), []byte(e.Hash)):
			res.BrokenAt, res.Reason = e.Seq, "row content does not match its hash (or another state key)"
		}
		if res.BrokenAt != 0 {
			return res, nil
		}
		res.Rows++
		res.LastHash = e.Hash
		expect++
	}
	return res, rows.Err()
}

// TamperForTest rewrites one audit row's detail without fixing the chain
// (tests of VerifyAudit only).
func (s *Store) TamperForTest(ctx context.Context, seq int64, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE audit SET detail = ? WHERE seq = ?`, detail, seq)
	return err
}

// AuditKey derives the audit chain key from the state key, so the state
// key itself is never used for two purposes.
func AuditKey(stateKey []byte) []byte {
	h := hmac.New(sha256.New, stateKey)
	h.Write([]byte("conductor-provisioner audit chain v1"))
	return h.Sum(nil)
}
