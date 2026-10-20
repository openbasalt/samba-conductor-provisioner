// Package server is `conductor-provisioner serve`: the service that
// executes typed operations for conductor (protocol in the public provapi
// package) with the delegated account, and the Unix socket it listens on.
//
// Every operation is a typed entry of a registry (registry.go). The
// invariants (invariants.go) are checked by the service itself on every
// operation that names a target, whatever the caller says:
//
//  1. the target is read fresh from the directory by SID, and its DN,
//     parsed and compared case-insensitively, is strictly below a scope
//     OU (no referrals, no DN tricks);
//  2. the target is not privileged (privilege index, rebuilt when older
//     than index_cache_seconds, plus the target's own adminCount and
//     tokenGroups read at operation time);
//  3. the target is a user account (not a computer, not a group);
//  4. hourly ceilings per operation kind from the service's own
//     configuration;
//  5. tokens are bound to the account's SID, objectGUID and pwdLastSet;
//  6. password material is never logged, audited, stored or returned.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
	"github.com/openbasalt/samba-conductor-provisioner/internal/store"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Service executes operations. It is safe for concurrent use; mutating
// operations run one at a time.
type Service struct {
	cfg     *config.Config
	st      *store.Store
	dir     directory.Directory
	log     *slog.Logger
	version string
	now     func() time.Time
	limits  *limiter

	// opMu serializes mutating operations, so a token cannot be used
	// twice by concurrent requests.
	opMu sync.Mutex

	idxMu sync.Mutex
	idx   directory.Index
}

// Options configure a Service.
type Options struct {
	Config    *config.Config
	Store     *store.Store
	Directory directory.Directory
	Logger    *slog.Logger
	Version   string
	// Now replaces the clock (tests).
	Now func() time.Time
}

// NewService builds a service.
func NewService(opt Options) (*Service, error) {
	if opt.Config == nil || opt.Store == nil || opt.Directory == nil {
		return nil, errors.New("server: config, store and directory are required")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	l := opt.Config.Limits
	return &Service{cfg: opt.Config, st: opt.Store, dir: opt.Directory, log: opt.Logger, version: opt.Version, now: opt.Now,
		limits: newLimiter(map[string]int{
			limitTokenIssues:  l.TokenIssuesPerHour,
			limitPasswordSets: l.PasswordSetsPerHour,
			limitEnables:      l.EnablesPerHour,
		})}, nil
}

// call collects what the audit entry of one request records. Handlers
// fill it as they learn the target; it never holds a password or a token.
type call struct {
	op        provapi.Op
	actor     string
	targetSID string
	targetSAM string
	tokenID   string
	reference string
	detail    []string
}

func (c *call) note(format string, a ...any) { c.detail = append(c.detail, fmt.Sprintf(format, a...)) }

// fail builds an error of the protocol.
func fail(code provapi.ErrorCode, format string, a ...any) *provapi.Error {
	return &provapi.Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Handle answers one request: decode, dispatch through the registry,
// audit. It never panics on input and never returns a password.
func (s *Service) Handle(ctx context.Context, req provapi.Request) provapi.Response {
	c := &call{op: req.Op, actor: "unknown"}
	if req.Actor.Validate() == nil {
		c.actor = req.Actor.String()
	}
	p, err := req.Decode()
	if err != nil {
		var pe *provapi.Error
		if !errors.As(err, &pe) {
			pe = fail(provapi.CodeInvalidParams, "%s", err)
		}
		c.note("%s", pe.Message)
		s.audit(ctx, c, pe)
		return provapi.ErrorResponse(req.ID, pe)
	}
	h, ok := registry[req.Op]
	if !ok {
		pe := fail(provapi.CodeInternal, "operation %q has no handler", req.Op)
		s.audit(ctx, c, pe)
		return provapi.ErrorResponse(req.ID, pe)
	}
	if h.mutating {
		s.opMu.Lock()
		defer s.opMu.Unlock()
	}
	result, pe := h.run(ctx, s, c, p)
	if pe != nil || h.mutating {
		s.audit(ctx, c, pe)
	}
	if pe != nil {
		return provapi.ErrorResponse(req.ID, pe)
	}
	resp, err := provapi.OKResponse(req.ID, result)
	if err != nil {
		s.log.Error("encoding a result failed", "op", req.Op, "err", err)
		return provapi.ErrorResponse(req.ID, fail(provapi.CodeInternal, "encoding the result"))
	}
	return resp
}

// audit writes the entry of one call: result "ok" or the error code.
func (s *Service) audit(ctx context.Context, c *call, pe *provapi.Error) {
	result := store.AuditResultOK
	detail := slicesJoin(c.detail)
	if pe != nil {
		result = string(pe.Code)
		if detail == "" {
			detail = pe.Message
		}
	}
	op := string(c.op)
	if _, ok := provapi.Allowlist[c.op]; !ok {
		op = "invalid"
	}
	_, err := s.st.AppendAudit(context.WithoutCancel(ctx), store.AuditEvent{Actor: c.actor, Op: op, TargetSID: c.targetSID,
		TargetSAM: c.targetSAM, TokenID: c.tokenID, Reference: c.reference, Result: result, Detail: detail})
	if err != nil {
		s.log.Error("writing the audit log failed", "op", op, "result", result, "err", err)
	}
}

func slicesJoin(parts []string) string { return strings.Join(parts, "; ") }

// hashToken is the stored form of a raw token: SHA-256 with a domain
// separator, so the hash is useless for anything else.
func hashToken(raw string) []byte {
	h := sha256.New()
	h.Write([]byte("conductor-provisioner-token\x00"))
	h.Write([]byte(raw))
	return h.Sum(nil)
}

// identifierDigest is a short digest of a lookup identifier for the
// audit log (a refused user.find), so repeated attempts correlate without
// storing the name or address.
func identifierDigest(v string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(v)))
	return hex.EncodeToString(sum[:])[:16]
}
