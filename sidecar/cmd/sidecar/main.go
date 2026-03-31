// main.go — sidecar entrypoint.
// Updated to align with Phase 1 Baseline (Issue #18).
package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
    "github.com/c2siorg/acf-sdk/sidecar/internal/pipeline"
    "github.com/c2siorg/acf-sdk/sidecar/internal/transport"
)

func main() {
    log.Println("==========================================")
    log.Println("    🛡️ ACF Security Sidecar (Go-PDP)       ")
    log.Println("    Status: Phase 1 Validation (Issue #18) ")
    log.Println("==========================================")

    // 1. Load HMAC key from environment (32-byte hex string required)
    signer, err := crypto.NewSignerFromEnv()
    if err != nil {
        log.Fatalf("sidecar: failed to load HMAC key: %v", err)
    }

    // 2. Start nonce store (20-byte nonce compatible)
    nonceStore := crypto.NewNonceStore(5 * time.Minute)
    defer nonceStore.Stop()

    // 3. Initialize the Pipeline
    // For Phase 1 validation, we ensure the pipeline is in "Pass-Through" mode.
    // This allows the sidecar to return DecisionAllow as requested by @tharindu.
    p := &pipeline.Pipeline{} 

    // 4. Resolve IPC address (Default: \\.\pipe\acf on Windows)
    connector := transport.DefaultConnector()
    address := connector.DefaultAddress()
    if p_env := os.Getenv("ACF_SOCKET_PATH"); p_env != "" {
        address = p_env
    }

    // 5. Create and start listener 
    // This wires the 54-byte frame logic (transport) to the security layers.
    ln, err := transport.NewListener(transport.Config{
        Address:    address,
        Connector:  connector,
        Signer:     signer,
        NonceStore: nonceStore,
        Pipeline:   p, 
    })
    if err != nil {
        log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
    }

    log.Printf("sidecar: listening on %s", address)
    log.Println("sidecar: ready for Phase 1 smoke tests")

    // 6. Serve in background
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