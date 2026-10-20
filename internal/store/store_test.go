package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "p.db")
	s, err := Open(ctx, p, AuditKey(key(1)))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := s.AppendAudit(ctx, AuditEvent{Actor: "conductor:a", Op: "token.issue", Result: "ok", Detail: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.VerifyAudit(ctx)
	if err != nil || res.Rows != 5 || res.BrokenAt != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	_ = s.Close()

	// Another key cannot verify (nor extend) the chain.
	other, err := Open(ctx, p, AuditKey(key(2)))
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := other.VerifyAudit(ctx); res.BrokenAt != 1 {
		t.Fatalf("wrong key verified: %+v", res)
	}
	_ = other.Close()

	s, _ = Open(ctx, p, AuditKey(key(1)))
	defer func() { _ = s.Close() }()
	if err := s.TamperForTest(ctx, 3, "changed"); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.VerifyAudit(ctx); res.BrokenAt != 3 {
		t.Fatalf("tamper not detected: %+v", res)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.VerifyAudit(ctx); res.BrokenAt != 2 {
		t.Fatalf("gap not detected: %+v", res)
	}
}

func TestOpenRefusesShortKey(t *testing.T) {
	if _, err := Open(context.Background(), ":memory:", []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:", AuditKey(key(1)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	tok := Token{ID: "a1", Hash: []byte("h1"), Purpose: "invite", SID: "S-1-5-21-1", GUID: "g", SAM: "u", PwdLastSet: 7,
		WasDisabled: true, IssuedBy: "x", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if n, err := s.IssueToken(ctx, tok); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	tok2 := tok
	tok2.ID, tok2.Hash = "a2", []byte("h2")
	if n, err := s.IssueToken(ctx, tok2); err != nil || n != 1 {
		t.Fatalf("supersede: %d %v", n, err)
	}
	got, err := s.TokenByHash(ctx, []byte("h1"))
	if err != nil || got.State != StateRevoked || got.StateReason != "superseded" {
		t.Fatalf("%+v %v", got, err)
	}
	got, _ = s.TokenByHash(ctx, []byte("h2"))
	if !got.WasDisabled || got.PwdLastSet != 7 || !got.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Fatalf("%+v", got)
	}
	if err := s.MarkPasswordSet(ctx, "a2", now.Add(10*time.Minute), 9); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPasswordSet(ctx, "a2", now, 9); err != ErrConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	now = now.Add(11 * time.Minute)
	if n, _ := s.ExpireDue(ctx); n != 1 {
		t.Fatalf("expired %d", n)
	}
	counts, _ := s.CountByState(ctx)
	if counts[StateExpired] != 1 || counts[StateRevoked] != 1 {
		t.Fatalf("%v", counts)
	}
	if n, _ := s.CountIssuedSince(ctx, "S-1-5-21-1", now.Add(-time.Hour)); n != 2 {
		t.Fatalf("issued %d", n)
	}
	if n, _ := s.Prune(ctx, now.Add(time.Second)); n != 2 {
		t.Fatalf("pruned %d", n)
	}
	if _, err := s.TokenByHash(ctx, []byte("h1")); err != ErrNotFound {
		t.Fatal(err)
	}
}
