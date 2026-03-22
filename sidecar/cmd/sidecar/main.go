// main.go — sidecar entrypoint.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
	"github.com/c2siorg/acf-sdk/sidecar/internal/pipeline" // 1. IMPORT THE PIPELINE
	"github.com/c2siorg/acf-sdk/sidecar/internal/transport"
)

func main() {
	log.Println("==========================================")
	log.Println("    🛡️ ACF Security Sidecar (Go-PDP)       ")
	log.Println("    Status: Phase 2 - Pipeline Active     ")
	log.Println("==========================================")

	// 1. Load HMAC key from environment
	signer, err := crypto.NewSignerFromEnv()
	if err != nil {
		log.Fatalf("sidecar: failed to load HMAC key: %v", err)
	}

	// 2. Start nonce store
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	// 3. Initialize the Pipeline (The Brain)
	p := &pipeline.Pipeline{} // 2. CREATE THE PIPELINE INSTANCE

	// 4. Resolve IPC address
	connector := transport.DefaultConnector()
	address := connector.DefaultAddress()
	if p_env := os.Getenv("ACF_SOCKET_PATH"); p_env != "" {
		address = p_env
	}

	// 5. Create and start listener (PLUG IN THE PIPELINE)
	ln, err := transport.NewListener(transport.Config{
		Address:    address,
		Connector:  connector,
		Signer:     signer,
		NonceStore: nonceStore,
		Pipeline:   p, // 3. CONNECT THE BRAIN TO THE EAR
	})
	if err != nil {
		log.Fatalf("sidecar: failed to create listener on %s: %v", address, err)
	}

	log.Printf("sidecar: listening on %s", address)

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