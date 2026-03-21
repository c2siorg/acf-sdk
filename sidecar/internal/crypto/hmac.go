// Package crypto provides HMAC-SHA256 signing and verification for IPC frames,
// and nonce generation and replay protection for the sidecar.
// The HMAC key is loaded from the ACF_HMAC_KEY environment variable at startup.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"errors"
	"os"
)

// ErrEmptyKey is returned when a zero-length key is provided.
var ErrEmptyKey = errors.New("crypto: HMAC key must not be empty")

// ErrMissingEnvKey is returned when ACF_HMAC_KEY is not set.
var ErrMissingEnvKey = errors.New("crypto: ACF_HMAC_KEY environment variable is not set")

// Signer holds the HMAC key and exposes Sign and Verify.
type Signer struct {
	key []byte
}

// NewSigner creates a Signer from raw key bytes.
// Returns ErrEmptyKey if key is nil or zero-length.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}, nil
}

// NewSignerFromEnv reads ACF_HMAC_KEY from the environment, hex-decodes it,
// and returns a Signer. Returns an error if the variable is absent, empty,
// or not valid hexadecimal.
func NewSignerFromEnv() (*Signer, error) {
	val := os.Getenv("ACF_HMAC_KEY")
	if val == "" {
		return nil, ErrMissingEnvKey
	}
	key, err := hex.DecodeString(val)
	if err != nil {
		return nil, errors.New("crypto: ACF_HMAC_KEY is not valid hex: " + err.Error())
	}
	return NewSigner(key)
}

// Sign computes HMAC-SHA256 over msg and returns the 32-byte MAC.
func (s *Signer) Sign(msg []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// SignHex computes HMAC-SHA256 over msg and returns the hex-encoded MAC.
func (s *Signer) SignHex(msg []byte) string {
	return hex.EncodeToString(s.Sign(msg))
}

// Verify returns true iff mac matches HMAC-SHA256 over msg.
// Uses hmac.Equal for constant-time comparison to prevent timing attacks.
func (s *Signer) Verify(msg, mac []byte) bool {
	expected := s.Sign(msg)
	return hmac.Equal(expected, mac)
}

// VerifyHex returns true iff macHex decodes and matches the expected HMAC.
func (s *Signer) VerifyHex(msg []byte, macHex string) bool {
	decoded, err := hex.DecodeString(macHex)
	if err != nil {
		return false
	}
	return s.Verify(msg, decoded)
}

// ProvenanceMessage returns the canonical byte sequence covered by the
// provenance HMAC. Each field is length-prefixed to avoid ambiguity.
func ProvenanceMessage(hookType, provenance, sessionID, executionID, nonce string, expiresAtUnix int64, payload []byte) []byte {
	fields := [][]byte{
		[]byte(hookType),
		[]byte(provenance),
		[]byte(sessionID),
		[]byte(executionID),
		[]byte(nonce),
	}

	total := 8 + len(payload)
	for _, field := range fields {
		total += 4 + len(field)
	}

	buf := make([]byte, 0, total)
	for _, field := range fields {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, field...)
	}

	var expBuf [8]byte
	binary.BigEndian.PutUint64(expBuf[:], uint64(expiresAtUnix))
	buf = append(buf, expBuf[:]...)
	buf = append(buf, payload...)
	return buf
}