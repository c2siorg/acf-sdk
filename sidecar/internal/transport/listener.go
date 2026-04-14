// listener.go — IPC accept loop.
// Accepts connections from the platform Connector (UDS on Linux/macOS,
// named pipe on Windows). Spawns one goroutine per connection.
// Each connection: read frame → verify HMAC → check nonce → run pipeline → write response.
// Invalid HMAC or reused nonce drops the connection immediately with no response.
package transport

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Config holds listener configuration.
type Config struct {
	// Address is the UDS socket path (Linux/macOS) or named pipe name (Windows).
	// If empty, Connector.DefaultAddress() is used.
	Address    string
	Connector  Connector
	Signer     *crypto.Signer
	NonceStore *crypto.NonceStore
	// Pipeline is the enforcement pipeline. If nil, a hardcoded ALLOW is returned
	// (Phase 1 fallback — should not be nil in Phase 2+).
	Pipeline *pipeline.Pipeline
}

// Listener wraps a platform net.Listener and handles incoming connections.
type Listener struct {
	cfg       Config
	ln        net.Listener
	stopCh    chan struct{}
	serveDone chan struct{}
	handlers  sync.WaitGroup
}

// NewListener creates a Listener bound to cfg.Address using cfg.Connector.
// Any platform-specific cleanup (e.g. stale UDS socket file) is performed
// before binding.
func NewListener(cfg Config) (*Listener, error) {
	if cfg.Address == "" {
		cfg.Address = cfg.Connector.DefaultAddress()
	}

	if err := cfg.Connector.Cleanup(cfg.Address); err != nil {
		return nil, err
	}

	ln, err := cfg.Connector.Listen(cfg.Address)
	if err != nil {
		return nil, err
	}

	return &Listener{
		cfg:       cfg,
		ln:        ln,
		stopCh:    make(chan struct{}),
		serveDone: make(chan struct{}),
	}, nil
}

// Serve enters the accept loop. Blocks until Stop is called.
// Returns nil after a clean shutdown, or a non-nil error on unexpected failure.
// serveDone is closed when Serve returns, so Drain can wait for the accept
// loop to finish before waiting on handlers.
func (l *Listener) Serve() error {
	defer close(l.serveDone)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return nil // clean shutdown
			default:
				return err
			}
		}
		l.handlers.Add(1)
		go func() {
			defer l.handlers.Done()
			l.handleConn(conn)
		}()
	}
}

// Stop closes the underlying listener, causing Serve to return. It does not
// wait for in-flight handlers or for Serve itself; callers that need that
// ordering should call Drain after Stop.
func (l *Listener) Stop() {
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
	l.ln.Close()
}

// Drain blocks until the accept loop has exited AND every in-flight handler
// has returned, or until ctx is done. Waiting on Serve first closes the gap
// where a connection accepted after Stop could still register a handler
// after handlers.Wait() has returned. Safe to call after Stop. Returns
// ctx.Err() if the deadline hits first.
func (l *Listener) Drain(ctx context.Context) error {
	select {
	case <-l.serveDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	done := make(chan struct{})
	go func() {
		l.handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleConn processes a single client connection.
func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. Decode the frame header and payload.
	rf, err := DecodeRequest(conn)
	if err != nil {
		log.Printf("transport: decode error: %v", err)
		return
	}

	// 2. Verify HMAC.
	length := uint32(len(rf.Payload))
	signedMsg := SignedMessage(rf.Version, length, rf.Nonce, rf.Payload)
	if !l.cfg.Signer.Verify(signedMsg, rf.HMAC[:]) {
		log.Printf("transport: %v", ErrBadHMAC)
		return
	}

	// 3. Check nonce replay.
	if l.cfg.NonceStore.Seen(rf.Nonce[:]) {
		log.Printf("transport: %v", ErrReplayNonce)
		return
	}

	// 4. Run pipeline if configured; fall back to ALLOW if not (Phase 1 compat).
	decision := DecisionAllow
	if l.cfg.Pipeline != nil {
		var rc riskcontext.RiskContext
		if err := json.Unmarshal(rf.Payload, &rc); err != nil {
			log.Printf("transport: JSON unmarshal error: %v", err)
			resp := EncodeResponse(&ResponseFrame{Decision: DecisionBlock})
			conn.Write(resp) //nolint:errcheck
			return
		}
		result := l.cfg.Pipeline.Run(&rc)
		decision = result.Decision
		log.Printf("transport: session=%s hook=%s score=%.2f signals=%v decision=%d blocked_at=%s",
			rc.SessionID, rc.HookType, result.Score, result.Signals, decision, result.BlockedAt)
	}

	// 5. Write response.
	resp := EncodeResponse(&ResponseFrame{Decision: decision})
	if _, err := conn.Write(resp); err != nil {
		log.Printf("transport: write error: %v", err)
	}
}
