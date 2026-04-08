// main.go — sidecar entrypoint.
// Phase 2: loads config, builds the enforcement pipeline, and starts the
// IPC listener (UDS on Linux/macOS, named pipe on Windows).
package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/transport"
)

func main() {
	// 1. Load sidecar config (falls back to defaults if sidecar.yaml absent).
	// Config path can be overridden via ACF_CONFIG env var. Otherwise we locate
	// the project root from the current working directory so the sidecar behaves
	// the same from repo root, sidecar/, or nested package directories.
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("sidecar: failed to determine working directory: %v", err)
	}

	configPath := config.DefaultConfigPath(cwd)
	if p := os.Getenv("ACF_CONFIG"); p != "" {
		if filepath.IsAbs(p) {
			configPath = p
		} else {
			configPath = filepath.Clean(filepath.Join(cwd, p))
		}
	}
	cfg, err := config.LoadOrDefault(configPath)
	if err != nil {
		log.Fatalf("sidecar: config error: %v", err)
	}
	cfg.PolicyDir = config.ResolvePolicyDir(cfg.PolicyDir, configPath, cwd)

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

	// 5. Build the enforcement pipeline.
	pl := pipeline.New(cfg, []pipeline.Stage{
		pipeline.NewValidateStage(),
		pipeline.NewNormaliseStage(),
		pipeline.NewScanStage(cfg, patterns.Patterns),
		pipeline.NewAggregateStage(cfg),
	})

	mode := "strict"
	if !cfg.Pipeline.StrictMode {
		mode = "non-strict"
	}
	log.Printf("sidecar: pipeline ready (mode=%s, block_threshold=%.2f)", mode, cfg.Thresholds.BlockScore)

	// 6. Resolve IPC address (platform-specific default if unset).
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p := os.Getenv("ACF_SOCKET_PATH"); p != "" {
		address = p
	} else if cfg.SocketPath != "" {
		address = cfg.SocketPath
	}

	// 7. Create and start listener.
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

	// 8. Serve in background; block on shutdown signal.
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
}
