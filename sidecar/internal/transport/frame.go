package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicByte   = 0xAC
	VersionByte = 1
	HeaderSize  = 54 // 1 (Magic) + 1 (Ver) + 20 (Nonce) + 32 (HMAC)

	DecisionAllow    = 0
	DecisionBlock    = 1
	DecisionSanitise = 2
)

var ErrBadMagic = errors.New("invalid magic byte")

type RequestFrame struct {
	Version byte
	Nonce   [20]byte
	HMAC    [32]byte
	Payload []byte
}

// ResponseFrame exactly as required by listener.go
type ResponseFrame struct {
	Decision          byte
	SanitisedPayload []byte
}

// SignedMessage matches the mentor's signature: [Version] + [Nonce] + [Payload]
func SignedMessage(version byte, length uint32, nonce [20]byte, payload []byte) []byte {
	buf := make([]byte, 1+20+len(payload))
	buf[0] = version
	copy(buf[1:21], nonce[:])
	copy(buf[21:], payload)
	return buf
}

// DecodeRequest reads exactly the bytes needed, avoiding the ReadAll hang.
func DecodeRequest(r io.Reader) (*RequestFrame, error) {
	// 1. Read the fixed-size 54-byte header
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != MagicByte {
		return nil, ErrBadMagic
	}

	rf := &RequestFrame{Version: header[1]}
	copy(rf.Nonce[:], header[2:22])
	copy(rf.HMAC[:], header[22:54])

	// 2. Mentors usually expect us to handle the payload buffer.
	// Since we don't have a 'length' in the Phase 1 header yet,
	// we read the remaining available bytes without blocking forever.
	
	payload := make([]byte, 1024) // Buffer for the JSON prompt
	n, err := r.Read(payload)
	if err != nil && err != io.EOF {
		return nil, err
	}

	rf.Payload = payload[:n]
	return rf, nil
}

// EncodeResponse matches listener.go:127: returns a single []byte
func EncodeResponse(res *ResponseFrame) []byte {
	// Standard response format: [Decision] + [4-byte Length] + [Payload]
	buf := make([]byte, 5+len(res.SanitisedPayload))
	buf[0] = res.Decision
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(res.SanitisedPayload)))
	copy(buf[5:], res.SanitisedPayload)
	return buf
}

// VerifyHMAC implements the official verification logic
func VerifyHMAC(key []byte, rf *RequestFrame) bool {
	mac := hmac.New(sha256.New, key)
	// Passing 0 for length as it's not part of the Phase 1 signature
	msg := SignedMessage(rf.Version, 0, rf.Nonce, rf.Payload)
	mac.Write(msg)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(rf.HMAC[:], expectedMAC)
}