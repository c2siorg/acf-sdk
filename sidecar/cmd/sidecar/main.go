// main.go — sidecar entrypoint.
// Phase 2: loads config, builds the enforcement pipeline, and starts the
// IPC listener (UDS on Linux/macOS, named pipe on Windows).
package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/telemetry"
	"github.com/acf-sdk/sidecar/internal/transport"
)

func main() {
	// 1. Load sidecar config (falls back to defaults if sidecar.yaml absent).
	// Config path can be overridden via ACF_CONFIG env var.
	// Default: ../config/sidecar.yaml — one level up from the sidecar/ directory,
	// which is the repo root when running with: go run ./sidecar/cmd/sidecar
	configPath := "../config/sidecar.yaml"
	if p := os.Getenv("ACF_CONFIG"); p != "" {
		configPath = p
	}
	cfg, err := config.LoadOrDefault(configPath)
	if err != nil {
		log.Fatalf("sidecar: config error: %v", err)
	}

	// 2. Load HMAC key from environment.
	signer, err := crypto.NewSignerFromEnv()
	if err != nil {
		log.Fatalf("sidecar: failed to load HMAC key: %v\n"+
			"  Set ACF_HMAC_KEY to a hex-encoded key (min 32 bytes).\n"+
			"  Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\"", err)
	}

	// 3. Start nonce store with 5-minute TTL.
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	// 4. Load jailbreak patterns.
	patterns, err := config.LoadPatterns(cfg.PolicyDir)
	if err != nil {
		log.Printf("sidecar: warning — could not load jailbreak patterns: %v (scan stage will run with no patterns)", err)
		patterns = &config.Patterns{}
	}

	// 5. Wire telemetry. Empty endpoint or missing audit path install noops.
	tracer, shutdownTracer, err := telemetry.Init(context.Background(), &telemetry.OTelConfig{
		Endpoint:    cfg.Telemetry.OTelEndpoint,
		ServiceName: cfg.Telemetry.ServiceName,
		SampleRatio: cfg.Telemetry.SampleRatio,
		Insecure:    cfg.Telemetry.Insecure,
	})
	if err != nil {
		log.Printf("sidecar: telemetry init: %v (using noop tracer)", err)
	}

	auditWriter, closeAuditFile, err := openAuditWriter(cfg.Telemetry.AuditPath)
	if err != nil {
		log.Fatalf("sidecar: cannot open audit sink: %v", err)
	}
	buffer := cfg.Telemetry.AuditBuffer
	if buffer <= 0 {
		buffer = 1024
	}
	audit := telemetry.NewAsyncSink(auditWriter, buffer)

	// 6. Build the enforcement pipeline.
	pl := pipeline.NewWithOptions(cfg, []pipeline.Stage{
		pipeline.NewValidateStage(),
		pipeline.NewNormaliseStage(),
		pipeline.NewScanStage(cfg, patterns.Patterns),
		pipeline.NewAggregateStage(cfg),
	}, pipeline.Options{
		Tracer:        tracer,
		AuditSink:     audit,
		PolicyVersion: cfg.Telemetry.PolicyVersion,
	})

	mode := "strict"
	if !cfg.Pipeline.StrictMode {
		mode = "non-strict"
	}
	log.Printf("sidecar: pipeline ready (mode=%s, block_threshold=%.2f)", mode, cfg.Thresholds.BlockScore)

	// 7. Resolve IPC address (platform-specific default if unset).
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p := os.Getenv("ACF_SOCKET_PATH"); p != "" {
		address = p
	} else if cfg.SocketPath != "" {
		address = cfg.SocketPath
	}

	// 8. Create and start listener.
	ln, err := transport.NewListener(transport.Config{
		Address:    address,
		Connector:  connector,
		Signer:     signer,
		NonceStore: nonceStore,
		Pipeline:   pl,
	})
	if err != nil {
		log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
	}

	log.Printf("sidecar: listening on %s", address)

	// 9. Serve in background; block on shutdown signal.
	serveErr := make(chan error, 1)
	go func() { serveErr <- ln.Serve() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Printf("sidecar: received %s, shutting down", sig)
		ln.Stop()
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("sidecar: listener error: %v", err)
		}
	}

	// 10. Drain in-flight handlers before tearing down telemetry so their
	// spans close cleanly and their audit entries reach the sink.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := ln.Drain(drainCtx); err != nil {
		log.Printf("sidecar: handler drain timed out: %v", err)
	}
	drainCancel()

	flushCtx, flushCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer flushCancel()
	if err := shutdownTracer(flushCtx); err != nil {
		log.Printf("sidecar: tracer shutdown: %v", err)
	}
	if err := audit.Close(); err != nil {
		log.Printf("sidecar: audit close: %v", err)
	}
	if closeAuditFile != nil {
		if err := closeAuditFile(); err != nil {
			log.Printf("sidecar: audit file close: %v", err)
		}
	}
}

// openAuditWriter routes audit output to stdout (empty or "-") or a file,
// creating the parent directory on demand.
func openAuditWriter(path string) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return os.Stdout, nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
