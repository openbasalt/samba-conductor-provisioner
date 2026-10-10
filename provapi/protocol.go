// Package provapi is the local API of conductor-provisioner: the protocol
// between conductor (the only client) and `conductor-provisioner serve`.
// It holds only types, validation, framing and a client, and imports only
// the standard library, so conductor can import it without the service.
//
// Transport: a Unix stream socket (DefaultSocketPath), handed over by
// systemd socket activation (conductor-provisioner-api.socket: owned by
// the conductor-provisioner user and the conductor group, mode 0660) or
// created by the service. The server checks the peer with SO_PEERCRED on
// every connection and admits only the configured UIDs.
//
// Framing: one request and one response per connection, each one JSON
// object on one line, at most MaxMessageSize bytes. Requests name an
// allowlisted operation; parameters are decoded strictly (unknown fields
// rejected) and validated. Every request carries the actor conductor acts
// for, which the server writes to its hash-chained audit log.
//
// Secrets: a raw token is returned once, in the result of token.issue, and
// is stored by the server only as a hash. A new password crosses the
// socket once, in password.set; it is never returned, stored, logged or
// audited.
package provapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ProtocolVersion is bumped on incompatible changes. Results are decoded
// strictly, so conductor and conductor-provisioner are upgraded together.
//
// Versioning rules: a new operation is additive and keeps the version (an
// older server answers invalid_params "not allowlisted"); changing the
// parameters or the result of an existing operation, including adding a
// field to a result (clients decode strictly), bumps it.
const ProtocolVersion = 1

// DefaultSocketPath is where `conductor-provisioner serve` listens.
const DefaultSocketPath = "/run/conductor-provisioner/api.sock"

// MaxMessageSize bounds one framed message, the newline included.
const MaxMessageSize = 256 << 10

// Op names an allowlisted operation.
type Op string

// Operations.
const (
	OpStatus         Op = "status"
	OpUserCheck      Op = "user.check"
	OpUserFind       Op = "user.find"
	OpTokenIssue     Op = "token.issue"
	OpTokenCheck     Op = "token.check"
	OpPasswordSet    Op = "password.set"
	OpInviteComplete Op = "invite.complete"
	OpTokenRevoke    Op = "token.revoke"
	OpTokenList      Op = "token.list"
	// The Google-first plan operations (plan.go).
	OpUserCreate     Op = "user.create"
	OpUserUpdate     Op = "user.update"
	OpUserSetEnabled Op = "user.set_enabled"
	OpUserMove       Op = "user.move"
)

// Mutating reports whether the operation changes state (tokens or the
// directory). Mutations are always audited; other operations are audited
// when they are refused.
func (o Op) Mutating() bool {
	switch o {
	case OpTokenIssue, OpPasswordSet, OpInviteComplete, OpTokenRevoke,
		OpUserCreate, OpUserUpdate, OpUserSetEnabled, OpUserMove:
		return true
	}
	return false
}

// PublicUser is the Actor.User of requests made for an anonymous visitor
// of a public page (an invitation or reset link, the reset form). Such
// requests carry no SID; Session identifies conductor's link record and IP
// the client address.
const PublicUser = "-public-"

// Actor is the person a request is made for: a signed-in conductor user,
// or PublicUser for the public link and reset pages.
type Actor struct {
	// User is the AD sAMAccountName, or PublicUser.
	User string `json:"user"`
	// SID is the user's SID; empty only for PublicUser.
	SID string `json:"sid,omitempty"`
	// Session is an opaque identifier of the web session or link record
	// (never a cookie value or a token).
	Session string `json:"session"`
	IP      string `json:"ip,omitempty"`
}

var (
	idRE      = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	sidRE     = regexp.MustCompile(`^S-1-[0-9]{1,15}(-[0-9]{1,10}){1,15}$`)
	tokenRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	tokenIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// oneLine reports whether s is valid UTF-8 without control characters and
// at most maxLen bytes.
func oneLine(s string, maxLen int) bool {
	if len(s) > maxLen || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Validate checks the actor's shape.
func (a Actor) Validate() error {
	if a.User == "" || !oneLine(a.User, 256) {
		return errors.New("actor: user is required (one line, at most 256 bytes)")
	}
	if a.Session == "" || !oneLine(a.Session, 128) {
		return errors.New("actor: session is required (one line, at most 128 bytes)")
	}
	if !oneLine(a.IP, 64) {
		return errors.New("actor: ip: one line, at most 64 bytes")
	}
	switch {
	case a.User == PublicUser && a.SID != "":
		return errors.New("actor: a public actor has no SID")
	case a.User != PublicUser && !sidRE.MatchString(a.SID):
		return errors.New("actor: the SID is invalid")
	}
	return nil
}

// String renders the actor for the audit log.
func (a Actor) String() string {
	s := "conductor:" + a.User
	if a.User == PublicUser {
		s = "conductor:public"
	}
	if a.IP != "" {
		s += "@" + a.IP
	}
	return s
}

// Request is one call.
type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Op      Op              `json:"op"`
	Actor   Actor           `json:"actor"`
	Params  json.RawMessage `json:"params,omitempty"`
	SentAt  time.Time       `json:"sent_at"`
}

// ErrorCode classifies a failed call.
type ErrorCode string

// Error codes. Every code but CodeUnavailable is sent by the server.
const (
	// CodeInvalidParams: unreadable or oversized message, wrong protocol
	// version, operation not allowlisted, unknown field, bad actor, a
	// parameter that does not validate, or a token in the wrong step.
	CodeInvalidParams ErrorCode = "invalid_params"
	// CodeNotFound: no user account with that SID or name, or an unknown
	// token.
	CodeNotFound ErrorCode = "not_found"
	// CodeOutOfScope: the account is not below a configured scope OU.
	CodeOutOfScope ErrorCode = "out_of_scope"
	// CodePrivileged: the account holds privileged rights; Error.Kinds
	// lists the reason kinds.
	CodePrivileged ErrorCode = "privileged"
	// CodeRateLimited: an hourly ceiling or the per-user daily limit.
	CodeRateLimited ErrorCode = "rate_limited"
	// CodeExpired, CodeUsed, CodeRevoked: the token's state.
	CodeExpired ErrorCode = "expired"
	CodeUsed    ErrorCode = "used"
	CodeRevoked ErrorCode = "revoked"
	// CodeStale: the account changed since the token was issued (its
	// password, its objectGUID, or an administrator disabled it); the
	// token is revoked.
	CodeStale ErrorCode = "stale"
	// CodePasswordPolicy: the directory refused the new password;
	// Error.Reason says why.
	CodePasswordPolicy ErrorCode = "password_policy"
	// CodeExists: user.create or user.move would collide with an object
	// that already exists (the DN, or a sAMAccountName, userPrincipalName,
	// address or marker used anywhere in the domain); Error.Kinds lists
	// what collided (dn, sam, upn, mail, marker).
	CodeExists ErrorCode = "exists"
	// CodeConflict: user.update found a current value other than the
	// change's before value; Error.Kinds lists the attributes.
	CodeConflict ErrorCode = "conflict"
	// CodeMarkerMismatch: the account does not carry the marker the
	// request names (another Google ID, or none).
	CodeMarkerMismatch ErrorCode = "marker_mismatch"
	// CodeSchemaMissing: the directory schema has no MarkerAttribute, so
	// no account can be created for Google-first.
	CodeSchemaMissing ErrorCode = "schema_missing"
	// CodeDirectory: the directory could not be read or refused a write.
	CodeDirectory ErrorCode = "directory"
	// CodeInternal: a failure inside the service.
	CodeInternal ErrorCode = "internal"
	// CodeUnavailable is returned by Call when the service cannot be
	// reached or answered nothing; the server never sends it.
	CodeUnavailable ErrorCode = "unavailable"
)

// Password policy reasons (Error.Reason with CodePasswordPolicy).
const (
	ReasonTooShort   = "too_short"
	ReasonComplexity = "complexity"
	ReasonHistory    = "history"
	ReasonTooYoung   = "too_young"
	ReasonOther      = "other"
)

// Error is the error part of a Response.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	// Reason refines CodePasswordPolicy.
	Reason string `json:"reason,omitempty"`
	// Kinds lists the privilege reason kinds with CodePrivileged, what
	// collided with CodeExists, and the attributes with CodeConflict.
	Kinds []string `json:"kinds,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("conductor-provisioner: %s: %s", e.Code, e.Message)
}

// Response answers a Request with the same ID.
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Params is implemented by every parameter type.
type Params interface{ Validate() error }

// Allowlist maps each operation to a constructor of its parameter type.
var Allowlist = map[Op]func() Params{
	OpStatus:         func() Params { return &NoParams{} },
	OpUserCheck:      func() Params { return &UserCheckParams{} },
	OpUserFind:       func() Params { return &UserFindParams{} },
	OpTokenIssue:     func() Params { return &TokenIssueParams{} },
	OpTokenCheck:     func() Params { return &TokenCheckParams{} },
	OpPasswordSet:    func() Params { return &PasswordSetParams{} },
	OpInviteComplete: func() Params { return &InviteCompleteParams{} },
	OpTokenRevoke:    func() Params { return &TokenRevokeParams{} },
	OpTokenList:      func() Params { return &TokenListParams{} },
	OpUserCreate:     func() Params { return &UserCreateParams{} },
	OpUserUpdate:     func() Params { return &UserUpdateParams{} },
	OpUserSetEnabled: func() Params { return &UserSetEnabledParams{} },
	OpUserMove:       func() Params { return &UserMoveParams{} },
}

func invalid(format string, a ...any) *Error {
	return &Error{Code: CodeInvalidParams, Message: fmt.Sprintf(format, a...)}
}

// NewRequest builds a validated request. id is the caller's request ID
// (NewRequestID makes one).
func NewRequest(id string, op Op, actor Actor, params Params) (Request, error) {
	if params == nil {
		params = NoParams{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return Request{}, err
	}
	req := Request{Version: ProtocolVersion, ID: id, Op: op, Actor: actor, Params: raw, SentAt: time.Now().UTC()}
	if _, err := req.Decode(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Decode validates the envelope and decodes the typed parameters. Errors
// are *Error with CodeInvalidParams.
func (r Request) Decode() (Params, error) {
	if r.Version != ProtocolVersion {
		return nil, invalid("protocol version %d, want %d", r.Version, ProtocolVersion)
	}
	if !idRE.MatchString(r.ID) {
		return nil, invalid("invalid request id")
	}
	if err := r.Actor.Validate(); err != nil {
		return nil, invalid("%s", err)
	}
	mk, ok := Allowlist[r.Op]
	if !ok {
		return nil, invalid("operation %q is not allowlisted", clip(string(r.Op), 64))
	}
	p := mk()
	params := r.Params
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, invalid("params: %s", clip(err.Error(), 200))
	}
	if dec.More() {
		return nil, invalid("params: trailing data")
	}
	if err := p.Validate(); err != nil {
		return nil, invalid("%s", err)
	}
	return p, nil
}

// clip shortens s for an error message.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// OKResponse builds a successful response.
func OKResponse(id string, result any) (Response, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{}, err
	}
	return Response{Version: ProtocolVersion, ID: id, OK: true, Result: raw}, nil
}

// ErrorResponse builds a failed response.
func ErrorResponse(id string, e *Error) Response {
	return Response{Version: ProtocolVersion, ID: id, Error: e}
}

// ErrTooLarge is returned for a message beyond MaxMessageSize.
var ErrTooLarge = errors.New("provapi: message too large")

// WriteMessage frames v as one JSON line.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxMessageSize {
		return ErrTooLarge
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadMessage reads one framed message into v (unknown fields and
// trailing data rejected). It never buffers more than MaxMessageSize
// bytes.
func ReadMessage(r *bufio.Reader, v any) error {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return err
		}
		line = append(line, chunk...)
		if len(line)+1 > MaxMessageSize {
			return ErrTooLarge
		}
		if !isPrefix {
			break
		}
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("provapi: trailing data after the message")
	}
	return nil
}
