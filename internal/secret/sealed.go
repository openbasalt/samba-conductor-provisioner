package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

// Sealed keeps one value (the delegated account's password) encrypted in
// memory under a random key made for this process (AES-256-GCM), so the
// plaintext exists only for the moment it is used and never in a core
// dump of an idle process. It is not a defence against an attacker who can
// read the process memory at will, only against accidental exposure.
type Sealed struct {
	mu     sync.Mutex
	aead   cipher.AEAD
	nonce  []byte
	ct     []byte
	aad    []byte
	closed bool
}

// Seal encrypts value under a fresh per-process key. aad binds the value
// to its use (the account name). The caller clears value afterwards.
func Seal(value, aad []byte) (*Sealed, error) {
	if len(value) == 0 {
		return nil, errors.New("secret: empty value")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aadCopy := append([]byte(nil), aad...)
	return &Sealed{aead: aead, nonce: nonce, ct: aead.Seal(nil, nonce, value, aadCopy), aad: aadCopy}, nil
}

// ErrClosed is returned by Open after Close.
var ErrClosed = errors.New("secret: sealed value closed")

// Open returns the plaintext; the caller clears it right after use.
func (s *Sealed) Open() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	return s.aead.Open(nil, s.nonce, s.ct, s.aad)
}

// Close forgets the value.
func (s *Sealed) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.ct)
	s.ct, s.closed = nil, true
}

// KeySize is the state key's length.
const KeySize = 32

// ParseKey accepts a key file's content: 32 raw bytes, 64 hex digits or
// standard base64 of 32 bytes (surrounding whitespace ignored), so both
// `head -c 32 /dev/urandom` and `openssl rand -hex 32` work.
func ParseKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		return append([]byte(nil), b...), nil
	}
	s := strings.TrimSpace(string(b))
	if k, err := hex.DecodeString(s); err == nil && len(k) == KeySize {
		return k, nil
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == KeySize {
		return k, nil
	}
	return nil, errors.New("secret: the state key must be 32 bytes (raw, 64 hex digits or base64)")
}
