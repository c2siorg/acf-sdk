package crypto

import (
	"encoding/hex"
	"os"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSign_Deterministic(t *testing.T) {
	s := testSigner(t)
	msg := []byte("hello world")
	mac1 := s.Sign(msg)
	mac2 := s.Sign(msg)
	if string(mac1) != string(mac2) {
		t.Error("Sign is not deterministic for the same key and message")
	}
}

func TestSign_DifferentKeys(t *testing.T) {
	s1, _ := NewSigner([]byte("key-one-32-bytes-long-padded!!!!"))
	s2, _ := NewSigner([]byte("key-two-32-bytes-long-padded!!!!"))
	msg := []byte("same message")
	if string(s1.Sign(msg)) == string(s2.Sign(msg)) {
		t.Error("different keys produced the same MAC")
	}
}

func TestVerify_ValidMAC(t *testing.T) {
	s := testSigner(t)
	msg := []byte("verify me")
	mac := s.Sign(msg)
	if !s.Verify(msg, mac) {
		t.Error("Verify returned false for a valid MAC")
	}
}

func TestVerify_CorruptedMAC(t *testing.T) {
	s := testSigner(t)
	msg := []byte("verify me")
	mac := s.Sign(msg)
	mac[0] ^= 0xFF // flip all bits in first byte
	if s.Verify(msg, mac) {
		t.Error("Verify returned true for a corrupted MAC")
	}
}

func TestVerify_CorruptedMessage(t *testing.T) {
	s := testSigner(t)
	msg := []byte("verify me")
	mac := s.Sign(msg)
	msg[0] ^= 0xFF
	if s.Verify(msg, mac) {
		t.Error("Verify returned true for a corrupted message")
	}
}

func TestNewSigner_EmptyKey(t *testing.T) {
	_, err := NewSigner(nil)
	if err == nil {
		t.Error("expected error for nil key, got nil")
	}
	_, err = NewSigner([]byte{})
	if err == nil {
		t.Error("expected error for empty key, got nil")
	}
}

func TestNewSignerFromEnv_Valid(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("ACF_HMAC_KEY", hex.EncodeToString(key))
	s, err := NewSignerFromEnv()
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Signer")
	}
}

func TestNewSignerFromEnv_Missing(t *testing.T) {
	os.Unsetenv("ACF_HMAC_KEY")
	_, err := NewSignerFromEnv()
	if err == nil {
		t.Error("expected error when ACF_HMAC_KEY is missing")
	}
}

func TestNewSignerFromEnv_InvalidHex(t *testing.T) {
	t.Setenv("ACF_HMAC_KEY", "ZZZZ")
	_, err := NewSignerFromEnv()
	if err == nil {
		t.Error("expected error for invalid hex value")
	}
}

func TestVerifyHex_ValidMAC(t *testing.T) {
	s := testSigner(t)
	msg := []byte("verify me")
	macHex := s.SignHex(msg)
	if !s.VerifyHex(msg, macHex) {
		t.Error("VerifyHex returned false for a valid MAC")
	}
}

func TestProvenanceMessage_Deterministic(t *testing.T) {
	msg1 := ProvenanceMessage("on_prompt", "user", "s1", "e1", "n1", 1700000000, []byte(`"hello"`))
	msg2 := ProvenanceMessage("on_prompt", "user", "s1", "e1", "n1", 1700000000, []byte(`"hello"`))
	if string(msg1) != string(msg2) {
		t.Error("ProvenanceMessage should be deterministic")
	}
}