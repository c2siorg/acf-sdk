package pipeline

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func signedContext(t *testing.T, signer *crypto.Signer, mutate func(*riskcontext.RiskContext), now time.Time) []byte {
	t.Helper()
	ctx := &riskcontext.RiskContext{
		Score:           0,
		Signals:         []string{},
		Provenance:      "user",
		SessionID:       "session-1",
		ExecutionID:     "exec-1",
		ProvenanceNonce: "prov-nonce-1",
		ExpiresAtUnix:   now.Add(time.Minute).Unix(),
		HookType:        "on_prompt",
		Payload:         "hello",
		State:           nil,
	}
	if mutate != nil {
		mutate(ctx)
	}
	payloadBytes, err := json.Marshal(ctx.Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	ctx.ProvenanceHMAC = signer.SignHex(crypto.ProvenanceMessage(
		ctx.HookType,
		ctx.Provenance,
		ctx.SessionID,
		ctx.ExecutionID,
		ctx.ProvenanceNonce,
		ctx.ExpiresAtUnix,
		payloadBytes,
	))
	if mutate != nil {
		mutate(ctx)
	}
	blob, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal ctx: %v", err)
	}
	return blob
}

func validationConfig(t *testing.T, signer *crypto.Signer, now time.Time) ValidationConfig {
	t.Helper()
	store := crypto.NewNonceStore(time.Minute)
	t.Cleanup(store.Stop)
	return ValidationConfig{
		Signer:              signer,
		NonceStore:          store,
		ExpectedExecutionID: "exec-1",
		Now:                 func() time.Time { return now },
	}
}

func TestValidatePayload_AllowsValidProvenance(t *testing.T) {
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	now := time.Unix(1700000000, 0)

	ctx, decision, err := ValidatePayload(signedContext(t, signer, nil, now), validationConfig(t, signer, now))
	if err != nil {
		t.Fatalf("ValidatePayload: %v", err)
	}
	if decision != 0x00 {
		t.Fatalf("expected ALLOW, got %#x", decision)
	}
	if ctx.ProvenanceTrust != 1.0 {
		t.Fatalf("expected provenance trust 1.0, got %v", ctx.ProvenanceTrust)
	}
	if len(ctx.ProvenanceFlags) != 0 {
		t.Fatalf("expected no provenance flags, got %v", ctx.ProvenanceFlags)
	}
}

func TestValidatePayload_BlocksReplay(t *testing.T) {
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	now := time.Unix(1700000000, 0)
	cfg := validationConfig(t, signer, now)
	payload := signedContext(t, signer, nil, now)

	if _, _, err := ValidatePayload(payload, cfg); err != nil {
		t.Fatalf("initial ValidatePayload: %v", err)
	}
	ctx, decision, err := ValidatePayload(payload, cfg)
	if err == nil {
		t.Fatal("expected replay error")
	}
	if decision != 0x02 {
		t.Fatalf("expected BLOCK, got %#x", decision)
	}
	if got := ctx.ProvenanceFlags; len(got) != 1 || got[0] != ProvenanceFlagReplay {
		t.Fatalf("expected replay flag, got %v", got)
	}
}

func TestValidatePayload_BlocksExpired(t *testing.T) {
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	now := time.Unix(1700000000, 0)
	payload := signedContext(t, signer, func(ctx *riskcontext.RiskContext) {
		ctx.ExpiresAtUnix = now.Add(-time.Second).Unix()
	}, now)

	ctx, decision, err := ValidatePayload(payload, validationConfig(t, signer, now))
	if err == nil {
		t.Fatal("expected expiry error")
	}
	if decision != 0x02 {
		t.Fatalf("expected BLOCK, got %#x", decision)
	}
	if got := ctx.ProvenanceFlags; len(got) != 1 || got[0] != ProvenanceFlagExpired {
		t.Fatalf("expected expired flag, got %v", got)
	}
}

func TestValidatePayload_BlocksExecutionMismatch(t *testing.T) {
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	now := time.Unix(1700000000, 0)
	payload := signedContext(t, signer, func(ctx *riskcontext.RiskContext) {
		ctx.ExecutionID = "exec-2"
	}, now)

	ctx, decision, err := ValidatePayload(payload, validationConfig(t, signer, now))
	if err == nil {
		t.Fatal("expected execution mismatch error")
	}
	if decision != 0x02 {
		t.Fatalf("expected BLOCK, got %#x", decision)
	}
	if got := ctx.ProvenanceFlags; len(got) != 1 || got[0] != ProvenanceFlagMismatch {
		t.Fatalf("expected mismatch flag, got %v", got)
	}
}

func TestValidatePayload_BlocksHMACMismatch(t *testing.T) {
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	now := time.Unix(1700000000, 0)
	payload := signedContext(t, signer, func(ctx *riskcontext.RiskContext) {
		ctx.ProvenanceHMAC = "00"
	}, now)

	ctx, decision, err := ValidatePayload(payload, validationConfig(t, signer, now))
	if err == nil {
		t.Fatal("expected HMAC mismatch error")
	}
	if decision != 0x02 {
		t.Fatalf("expected BLOCK, got %#x", decision)
	}
	if got := ctx.ProvenanceFlags; len(got) != 1 || got[0] != ProvenanceFlagMismatch {
		t.Fatalf("expected mismatch flag, got %v", got)
	}
}