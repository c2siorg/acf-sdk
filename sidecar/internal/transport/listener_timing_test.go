package transport

import (
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
)

func TestListener_OnTimingReportsEachStep(t *testing.T) {
	address := testAddress(t)
	signer, err := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	t.Cleanup(nonceStore.Stop)

	cfg := &config.Config{
		Pipeline:     config.PipelineConfig{StrictMode: true},
		Thresholds:   config.ThresholdConfig{BlockScore: 0.85, SanitiseScore: 0.50},
		TrustWeights: map[string]float64{"user": 1.0},
	}
	pl := pipeline.New(cfg, []pipeline.Stage{
		pipeline.NewValidateStage(),
		pipeline.NewNormaliseStage(),
		pipeline.NewScanStage(cfg, nil),
		pipeline.NewAggregateStage(cfg, pipeline.StaticWeights{}),
	})

	timings := make(chan Timing, 1)
	ln, err := NewListener(Config{
		Address:    address,
		Connector:  DefaultConnector(),
		Signer:     signer,
		NonceStore: nonceStore,
		Pipeline:   pl,
		OnTiming:   func(tm Timing) { timings <- tm },
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	go ln.Serve() //nolint:errcheck
	t.Cleanup(ln.Stop)
	time.Sleep(10 * time.Millisecond)

	payload := []byte(`{"hook_type":"on_prompt","payload":"hello","session_id":"s1","provenance":"user","signals":[],"score":0,"state":null}`)
	frame, err := EncodeRequest(payload, signer)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	resp, err := sendFrame(t, address, frame)
	if err != nil {
		t.Fatalf("sendFrame: %v", err)
	}
	if len(resp) < 1 || resp[0] != DecisionAllow {
		t.Fatalf("expected ALLOW, got %v", resp)
	}

	var tm Timing
	select {
	case tm = <-timings:
	case <-time.After(2 * time.Second):
		t.Fatal("OnTiming was not called within 2s")
	}

	if tm.HookType != "on_prompt" || tm.Decision != DecisionAllow || tm.PayloadBytes != len(payload) {
		t.Errorf("got hook=%q decision=%d bytes=%d, want on_prompt ALLOW %d",
			tm.HookType, tm.Decision, tm.PayloadBytes, len(payload))
	}
	want := []string{"validate", "normalise", "scan", "aggregate"}
	if len(tm.Pipeline.Stages) != len(want) {
		t.Fatalf("stages = %+v, want %v", tm.Pipeline.Stages, want)
	}
	for i, name := range want {
		if tm.Pipeline.Stages[i].Name != name {
			t.Errorf("stage %d = %q, want %q", i, tm.Pipeline.Stages[i].Name, name)
		}
	}
	parts := tm.Read + tm.Verify + tm.Nonce + tm.Unmarshal + tm.Log + tm.Write +
		tm.Pipeline.Policy + tm.Pipeline.Sanitise
	for _, s := range tm.Pipeline.Stages {
		parts += s.Duration
	}
	if parts > tm.Total {
		t.Errorf("steps sum to %v, more than total %v", parts, tm.Total)
	}
}
