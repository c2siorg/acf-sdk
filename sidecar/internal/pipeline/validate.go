// validate.go — Stage 1 of the pipeline.
// Responsibilities:
//   - HMAC verification of the inbound frame (already done in transport, re-checked here for defence-in-depth)
//   - Nonce replay check against the nonce store
//   - JSON schema validation of the RiskContext payload
// Invalid frames are rejected before any payload parsing.
package pipeline

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

const (
	ProvenanceFlagReplay   = "replay"
	ProvenanceFlagExpired  = "expired"
	ProvenanceFlagMismatch = "mismatch"
)

var errSchemaInvalid = errors.New("pipeline: invalid risk context schema")

// ValidationConfig contains the external dependencies for the validate stage.
type ValidationConfig struct {
	Signer              *crypto.Signer
	NonceStore          *crypto.NonceStore
	ExpectedExecutionID string
	Now                 func() time.Time
}

// ValidatePayload parses and validates an inbound RiskContext JSON payload.
// It writes a normalized provenance signal into the returned context and
// returns BLOCK when provenance validation fails.
func ValidatePayload(payload []byte, cfg ValidationConfig) (*riskcontext.RiskContext, byte, error) {
	ctx := &riskcontext.RiskContext{}
	if err := json.Unmarshal(payload, ctx); err != nil {
		return nil, 0, err
	}
	if err := validateSchema(ctx); err != nil {
		ctx.ProvenanceTrust = 0
		ctx.ProvenanceFlags = []string{ProvenanceFlagMismatch}
		return ctx, 0x02, err
	}
	if err := validateProvenance(ctx, cfg); err != nil {
		return ctx, 0x02, err
	}
	ctx.ProvenanceTrust = 1.0
	ctx.ProvenanceFlags = nil
	return ctx, 0x00, nil
}

func validateSchema(ctx *riskcontext.RiskContext) error {
	if strings.TrimSpace(ctx.HookType) == "" || strings.TrimSpace(ctx.Provenance) == "" {
		return errSchemaInvalid
	}
	if ctx.Payload == nil {
		return errSchemaInvalid
	}
	return nil
}

func validateProvenance(ctx *riskcontext.RiskContext, cfg ValidationConfig) error {
	flags := make([]string, 0, 3)
	markFailure := func(flag string, err error) error {
		ctx.ProvenanceTrust = 0
		ctx.ProvenanceFlags = appendUnique(flags, flag)
		return err
	}

	if cfg.Signer == nil || cfg.NonceStore == nil {
		return markFailure(ProvenanceFlagMismatch, errSchemaInvalid)
	}
	if strings.TrimSpace(ctx.ExecutionID) == "" || strings.TrimSpace(ctx.ProvenanceNonce) == "" || strings.TrimSpace(ctx.ProvenanceHMAC) == "" || ctx.ExpiresAtUnix == 0 {
		return markFailure(ProvenanceFlagMismatch, errSchemaInvalid)
	}
	if cfg.ExpectedExecutionID != "" && ctx.ExecutionID != cfg.ExpectedExecutionID {
		return markFailure(ProvenanceFlagMismatch, errors.New("pipeline: execution_id mismatch"))
	}

	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	if now().After(time.Unix(ctx.ExpiresAtUnix, 0)) {
		return markFailure(ProvenanceFlagExpired, errors.New("pipeline: provenance expired"))
	}

	payloadBytes, err := json.Marshal(ctx.Payload)
	if err != nil {
		return markFailure(ProvenanceFlagMismatch, err)
	}
	msg := crypto.ProvenanceMessage(
		ctx.HookType,
		ctx.Provenance,
		ctx.SessionID,
		ctx.ExecutionID,
		ctx.ProvenanceNonce,
		ctx.ExpiresAtUnix,
		payloadBytes,
	)
	if !cfg.Signer.VerifyHex(msg, ctx.ProvenanceHMAC) {
		return markFailure(ProvenanceFlagMismatch, errors.New("pipeline: provenance HMAC mismatch"))
	}
	if cfg.NonceStore.SeenString(ctx.ProvenanceNonce) {
		return markFailure(ProvenanceFlagReplay, errors.New("pipeline: provenance nonce replay detected"))
	}
	return nil
}

func appendUnique(flags []string, flag string) []string {
	for _, existing := range flags {
		if existing == flag {
			return flags
		}
	}
	return append(flags, flag)
}