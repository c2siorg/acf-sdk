// Package crypto provides HMAC-SHA256 signing and verification for IPC frames.
// The HMAC key is loaded from the ACF_HMAC_KEY environment variable at startup.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
)

// ErrEmptyKey is returned when a zero-length key is provided.
var ErrEmptyKey = errors.New("crypto: HMAC key must not be empty")

// ErrMissingEnvKey is returned when ACF_HMAC_KEY is not set.
var ErrMissingEnvKey = errors.New("crypto: ACF_HMAC_KEY environment variable is not set")

// Signer holds the HMAC key and exposes Sign and Verify methods.
type Signer struct {
	key []byte
}

// NewSigner creates a Signer from raw key bytes.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}, nil
}

// NewSignerFromEnv reads ACF_HMAC_KEY from the environment (hex-encoded)
// and returns a Signer.
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

// Verify returns true if the mac matches the HMAC-SHA256 over the message.
// Uses hmac.Equal for constant-time comparison to prevent timing attacks.
func (s *Signer) Verify(msg, mac []byte) bool {
	expected := s.Sign(msg)
	return hmac.Equal(expected, mac)
}