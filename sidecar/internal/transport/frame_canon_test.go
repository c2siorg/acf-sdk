package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/acf-sdk/sidecar/internal/crypto"
)

// ============================================================================
// PART A: Canonicalization Tests
// ============================================================================

func TestCanonicalizeJSON_KeyOrder(t *testing.T) {
	// Different key order should produce identical canonicalization
	payload1 := []byte(`{"b":2,"a":1}`)
	payload2 := []byte(`{"a":1,"b":2}`)

	canon1, err1 := CanonicalizeJSON(payload1)
	canon2, err2 := CanonicalizeJSON(payload2)

	if err1 != nil || err2 != nil {
		t.Fatalf("CanonicalizeJSON: %v, %v", err1, err2)
	}

	if !bytes.Equal(canon1, canon2) {
		t.Errorf("canonicalization with different key orders should match\n  canon1: %s\n  canon2: %s",
			string(canon1), string(canon2))
	}
}

func TestCanonicalizeJSON_Whitespace(t *testing.T) {
	// Whitespace differences should produce identical canonicalization
	payload1 := []byte(`{"a": 1, "b": 2}`)
	payload2 := []byte(`{"a":1,"b":2}`)
	payload3 := []byte(`{
		"a": 1,
		"b": 2
	}`)

	canon1, _ := CanonicalizeJSON(payload1)
	canon2, _ := CanonicalizeJSON(payload2)
	canon3, _ := CanonicalizeJSON(payload3)

	if !bytes.Equal(canon1, canon2) {
		t.Error("whitespace differences should produce identical canonical form")
	}
	if !bytes.Equal(canon2, canon3) {
		t.Error("newlines and indentation should produce identical canonical form")
	}
}

func TestCanonicalizeJSON_NestedObjects(t *testing.T) {
	// Nested objects should have keys sorted recursively
	payload1 := []byte(`{"outer":{"z":26,"a":1},"x":10}`)
	payload2 := []byte(`{"x":10,"outer":{"a":1,"z":26}}`)

	canon1, _ := CanonicalizeJSON(payload1)
	canon2, _ := CanonicalizeJSON(payload2)

	if !bytes.Equal(canon1, canon2) {
		t.Errorf("nested objects should be recursively sorted\n  canon1: %s\n  canon2: %s",
			string(canon1), string(canon2))
	}
}

func TestCanonicalizeJSON_Idempotent(t *testing.T) {
	// canonical(canonical(x)) should equal canonical(x)
	payload := []byte(`{"c":3,"a":1,"b":2}`)

	canon1, _ := CanonicalizeJSON(payload)
	canon2, _ := CanonicalizeJSON(canon1)
	canon3, _ := CanonicalizeJSON(canon2)

	if !bytes.Equal(canon1, canon2) {
		t.Error("canonicalization should be idempotent (first application)")
	}
	if !bytes.Equal(canon2, canon3) {
		t.Error("canonicalization should be idempotent (second application)")
	}
}

func TestCanonicalizeJSON_InvalidJSON(t *testing.T) {
	testCases := []string{
		`{invalid}`,
		`{missing: colon}`,
		`["unclosed array"`,
		``,
		`undefined`,
		`not_valid_at_all`,
	}

	for _, payload := range testCases {
		_, err := CanonicalizeJSON([]byte(payload))
		if err == nil {
			t.Errorf("CanonicalizeJSON should return error for invalid JSON: %q", payload)
		}
	}
}

func TestCanonicalizeJSON_Arrays(t *testing.T) {
	// Arrays should not be reordered, but whitespace removed
	payload1 := []byte(`{"items":[3,1,2]}`)
	payload2 := []byte(`{"items": [3, 1, 2]}`)

	canon1, _ := CanonicalizeJSON(payload1)
	canon2, _ := CanonicalizeJSON(payload2)

	if !bytes.Equal(canon1, canon2) {
		t.Error("arrays should preserve order but remove whitespace")
	}

	// Verify array order is preserved
	expected := []byte(`{"items":[3,1,2]}`)
	if !bytes.Equal(canon1, expected) {
		t.Errorf("array order should not be modified; got %s, want %s",
			string(canon1), string(expected))
	}
}

func TestCanonicalizeJSON_SpecialCharacters(t *testing.T) {
	// Unicode and escaped characters should be handled correctly
	payload := []byte(`{"emoji":"😀","escaped":"line\nbreak","unicode":"\u0041"}`)

	canon, err := CanonicalizeJSON(payload)
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}

	// Verify idempotency with special characters
	canon2, _ := CanonicalizeJSON(canon)
	if !bytes.Equal(canon, canon2) {
		t.Error("canonicalization with special characters should be idempotent")
	}
}

// ============================================================================
// PART B: Cross-SDK Interoperability Tests (Fixed Nonce)
// ============================================================================

// FixedNonceSignedMessage is a helper that creates a signed message with
// a fixed nonce (useful for cross-SDK testing). This allows us to verify
// that two different JSON representations of the same data produce identical
// HMACs when using the same nonce.
func FixedNonceSignedMessage(version byte, nonce [16]byte, payload []byte) ([]byte, error) {
	return SignedMessage(version, nonce, payload)
}

// FixedNonceHMAC computes HMAC with a fixed nonce. Used to verify
// cross-SDK determinism at the signed message level.
func FixedNonceHMAC(signer *crypto.Signer, version byte, nonce [16]byte, payload []byte) ([]byte, error) {
	msg, err := FixedNonceSignedMessage(version, nonce, payload)
	if err != nil {
		return nil, err
	}
	return signer.Sign(msg), nil
}

func TestCrossSDK_SameDataDifferentKeyOrder(t *testing.T) {
	// Simulates: Python SDK sends {"a":1,"b":2}, Go sends {"b":2,"a":1}
	// With the same nonce, both should produce identical HMACs.

	signer := testSigner(t)
	fixedNonce := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	payload1 := []byte(`{"a":1,"b":2}`)
	payload2 := []byte(`{"b":2,"a":1}`)

	hmac1, _ := FixedNonceHMAC(signer, VersionByte, fixedNonce, payload1)
	hmac2, _ := FixedNonceHMAC(signer, VersionByte, fixedNonce, payload2)

	if !bytes.Equal(hmac1, hmac2) {
		t.Error("cross-SDK: same data with different key order should produce identical HMACs")
	}
}

func TestCrossSDK_IdenticalSignedMessage(t *testing.T) {
	// Verify that both payloads produce identical signed messages (before HMAC)
	fixedNonce := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	payload1 := []byte(`{"user":"alice","role":"admin"}`)
	payload2 := []byte(`{"role":"admin","user":"alice"}`)

	msg1, _ := FixedNonceSignedMessage(VersionByte, fixedNonce, payload1)
	msg2, _ := FixedNonceSignedMessage(VersionByte, fixedNonce, payload2)

	if !bytes.Equal(msg1, msg2) {
		t.Error("cross-SDK: different key orders should produce identical signed messages")
	}

	// Verify structure: [version(1B) | canonical_length(4B) | nonce(16B) | canonical_payload]
	if msg1[0] != VersionByte {
		t.Errorf("version byte mismatch: got %#x", msg1[0])
	}

	length1 := binary.BigEndian.Uint32(msg1[1:5])
	length2 := binary.BigEndian.Uint32(msg2[1:5])
	if length1 != length2 {
		t.Errorf("canonical lengths should match: %d vs %d", length1, length2)
	}

	if !bytes.Equal(msg1[5:21], msg2[5:21]) {
		t.Error("nonces should match in signed message")
	}
}

func TestCrossSDK_ComplexNested(t *testing.T) {
	// Test with more complex nested structures
	fixedNonce := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

	signer := testSigner(t)

	// Two equivalent but structurally different representations
	payload1 := []byte(`{
		"context": {
			"request_id": "req-123",
			"user": {"name": "bob", "id": 42},
			"timestamp": "2024-01-01T00:00:00Z"
		},
		"action": "execute"
	}`)

	payload2 := []byte(`{"action":"execute","context":{"timestamp":"2024-01-01T00:00:00Z","request_id":"req-123","user":{"id":42,"name":"bob"}}}`)

	hmac1, _ := FixedNonceHMAC(signer, VersionByte, fixedNonce, payload1)
	hmac2, _ := FixedNonceHMAC(signer, VersionByte, fixedNonce, payload2)

	if !bytes.Equal(hmac1, hmac2) {
		t.Error("complex nested structures with different formatting should produce identical HMACs")
	}
}

func TestCrossSDK_CanonicalLengthInSignedMessage(t *testing.T) {
	// Verify that the length field in signed message uses canonical length,
	// not raw input length (BONUS test from requirements).
	fixedNonce := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}

	// Payload with extra whitespace (raw length > canonical length)
	rawPayload := []byte(`{  "a"  :  1  ,  "b"  :  2  }`)

	msg, _ := SignedMessage(VersionByte, fixedNonce, rawPayload)

	// Extract length from signed message
	msgLength := binary.BigEndian.Uint32(msg[1:5])

	// Get canonical payload
	canonical, _ := CanonicalizeJSON(rawPayload)

	if msgLength != uint32(len(canonical)) {
		t.Errorf("signed message length should be canonical length (%d), not raw input length (%d)",
			len(canonical), len(rawPayload))
	}

	// Verify canonical payload is exactly at the expected offset
	payload := msg[21:]
	if !bytes.Equal(payload, canonical) {
		t.Errorf("payload in signed message should match canonicalization\n  got: %s\n  want: %s",
			string(payload), string(canonical))
	}
}

// ============================================================================
// PART C: Negative/Expected Behavior Tests
// ============================================================================

func TestNegativeBehavior_DifferentNonces(t *testing.T) {
	// Two encode_request calls with the same payload MUST produce different nonces.
	// This is expected behavior and should result in different HMACs.
	s := testSigner(t)
	payload := []byte(`{"data":"test"}`)

	frame1, _ := EncodeRequest(payload, s)
	frame2, _ := EncodeRequest(payload, s)

	nonce1 := frame1[6:22]
	nonce2 := frame2[6:22]

	if bytes.Equal(nonce1, nonce2) {
		t.Error("two EncodeRequest calls should produce different nonces (not deterministic)")
	}

	// Different nonces should result in different HMAC values
	hmac1 := frame1[22:54]
	hmac2 := frame2[22:54]

	if bytes.Equal(hmac1, hmac2) {
		t.Error("different nonces should produce different HMACs")
	}
}

func TestNegativeBehavior_FixedNonceComparison(t *testing.T) {
	// Now verify that WITH a fixed nonce, the same payload does yield the same HMAC.
	s := testSigner(t)
	fixedNonce := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	payload := []byte(`{"fixed":"test"}`)

	hmac1, _ := FixedNonceHMAC(s, VersionByte, fixedNonce, payload)
	hmac2, _ := FixedNonceHMAC(s, VersionByte, fixedNonce, payload)

	if !bytes.Equal(hmac1, hmac2) {
		t.Error("same payload with fixed nonce should always produce identical HMAC")
	}
}

func TestNegativeBehavior_InvalidJSON(t *testing.T) {
	signer := testSigner(t)
	fixedNonce := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	invalidPayloads := [][]byte{
		[]byte(`not json at all`),
		[]byte(`{unclosed`),
		[]byte(`{"key": undefined}`),
		[]byte(`[1, 2, 3`),
	}

	for _, payload := range invalidPayloads {
		// EncodeRequest should fail with invalid JSON
		_, encErr := EncodeRequest(payload, signer)
		if encErr == nil {
			t.Errorf("EncodeRequest should fail with invalid JSON: %q", string(payload))
		}

		// SignedMessage should also fail
		_, sigErr := SignedMessage(VersionByte, fixedNonce, payload)
		if sigErr == nil {
			t.Errorf("SignedMessage should fail with invalid JSON: %q", string(payload))
		}
	}
}

// ============================================================================
// PART D: Frame Header Length Field Test
// ============================================================================

func TestFrameHeader_LengthFieldIsRawPayload(t *testing.T) {
	// The frame header's length field should represent the raw payload length,
	// not the canonical length. This is because the frame stores the original payload.
	s := testSigner(t)

	// Payload with extra whitespace (raw length > canonical length)
	payload := []byte(`{  "a"  :  1  }`)
	rawLen := uint32(len(payload))

	frame, _ := EncodeRequest(payload, s)

	// Extract length from frame header
	headerLen := binary.BigEndian.Uint32(frame[2:6])

	if headerLen != rawLen {
		t.Errorf("frame header length should be raw payload length (%d), got %d",
			rawLen, headerLen)
	}

	// Verify we can read back the exact payload
	if !bytes.Equal(frame[54:], payload) {
		t.Error("frame should contain the exact original payload bytes")
	}
}

func TestFrameHeader_CanonicalVsRaw(t *testing.T) {
	// Demonstrate the difference between frame header length and signed message length.
	s := testSigner(t)
	fixedNonce := [16]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
		0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00}

	// Payload with whitespace
	payload := []byte(`{  "x"  :  1  ,  "y"  :  2  }`)

	// Manually create frame to inspect both lengths
	msg, _ := SignedMessage(VersionByte, fixedNonce, payload)
	mac := s.Sign(msg)

	frame := make([]byte, HeaderSize+len(payload))
	frame[0] = MagicByte
	frame[1] = VersionByte
	binary.BigEndian.PutUint32(frame[2:6], uint32(len(payload))) // raw length
	copy(frame[6:22], fixedNonce[:])
	copy(frame[22:54], mac)
	copy(frame[54:], payload)

	// Extract lengths
	headerLength := binary.BigEndian.Uint32(frame[2:6])
	signedMsgCanonicalLength := binary.BigEndian.Uint32(msg[1:5])

	canonical, _ := CanonicalizeJSON(payload)
	expectedCanonical := uint32(len(canonical))

	if headerLength == signedMsgCanonicalLength {
		// They happen to be equal for this payload
		t.Logf("raw payload length and canonical length both: %d",
			headerLength)
	} else {
		// Whitespace was removed, so canonical is smaller
		if headerLength > signedMsgCanonicalLength {
			t.Logf("raw payload length (%d) > canonical length (%d) — whitespace removed",
				headerLength, signedMsgCanonicalLength)
		} else {
			t.Logf("raw payload length (%d) < canonical length (%d) — keys were reordered",
				headerLength, signedMsgCanonicalLength)
		}
	}

	if signedMsgCanonicalLength != expectedCanonical {
		t.Errorf("signed message canonical length mismatch: got %d, want %d",
			signedMsgCanonicalLength, expectedCanonical)
	}
}

// ============================================================================
// PART E: Table-Driven Canonicalization Tests
// ============================================================================

func TestCanonicalizeJSON_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "simple object",
			payload:  []byte(`{"a":1}`),
			expected: []byte(`{"a":1}`),
			wantErr:  false,
		},
		{
			name:     "reversed keys",
			payload:  []byte(`{"z":9,"a":1}`),
			expected: []byte(`{"a":1,"z":9}`),
			wantErr:  false,
		},
		{
			name:     "with whitespace",
			payload:  []byte(`{ "a" : 1 , "z" : 9 }`),
			expected: []byte(`{"a":1,"z":9}`),
			wantErr:  false,
		},
		{
			name:     "nested object",
			payload:  []byte(`{"outer":{"b":2,"a":1}}`),
			expected: []byte(`{"outer":{"a":1,"b":2}}`),
			wantErr:  false,
		},
		{
			name:     "array preserved",
			payload:  []byte(`{"items":[3,2,1]}`),
			expected: []byte(`{"items":[3,2,1]}`),
			wantErr:  false,
		},
		{
			name:     "invalid json",
			payload:  []byte(`{bad`),
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeJSON(tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("CanonicalizeJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Errorf("CanonicalizeJSON() got %q, want %q", string(got), string(tt.expected))
			}
		})
	}
}

// ============================================================================
// PART F: Integration Test with Listener Verification
// ============================================================================

func TestIntegration_EncodeAndVerifyWithCanonical(t *testing.T) {
	// Simulates what the listener does: encode a request, then verify the HMAC.
	signer := testSigner(t)
	payload := []byte(`{"request":"test","priority":10}`)

	// Encode the request (will generate a random nonce)
	frame, err := EncodeRequest(payload, signer)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}

	// Decode it back
	decoded, err := DecodeRequest(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}

	// Verify HMAC (this is what the listener does)
	signedMsg, err := SignedMessage(decoded.Version, decoded.Nonce, decoded.Payload)
	if err != nil {
		t.Fatalf("SignedMessage: %v", err)
	}

	if !signer.Verify(signedMsg, decoded.HMAC[:]) {
		t.Error("HMAC verification failed")
	}
}

func TestIntegration_CrossSDKSimulation(t *testing.T) {
	// Simulate: Python SDK encodes payload with specific key order,
	// Go sidecar receives it and can verify it even with different canonical form.
	signer := testSigner(t)

	// "Python SDK" sends this payload
	pythonPayload := []byte(`{"service":"auth","action":"validate"}`)

	// "Go Sidecar" decodes it and creates a signed message for verification
	fixedNonce := [16]byte{
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}

	// Python SDK computed HMAC with fixed nonce
	pythonSignedMsg, _ := SignedMessage(VersionByte, fixedNonce, pythonPayload)
	pythonHMAC := signer.Sign(pythonSignedMsg)

	// Now Go sidecar receives a payload with different key order but same data
	goPayload := []byte(`{"action":"validate","service":"auth"}`)

	// Go computes signed message with same nonce
	goSignedMsg, _ := SignedMessage(VersionByte, fixedNonce, goPayload)
	goHMAC := signer.Sign(goSignedMsg)

	// Both HMACs should match
	if !bytes.Equal(pythonHMAC, goHMAC) {
		t.Error("Python and Go HMACs should match for semantically equivalent JSON")
	}

	// Sidecar can verify Python's original payload because canonical form is identical
	if !signer.Verify(pythonSignedMsg, pythonHMAC) {
		t.Error("failed to verify Python SDK payload")
	}
}
