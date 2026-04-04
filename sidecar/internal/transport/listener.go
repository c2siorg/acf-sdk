// listener.go — IPC accept loop.
// Accepts connections from the platform Connector (UDS on Linux/macOS,
// named pipe on Windows). Spawns one goroutine per connection.
// Each connection: read frame → verify HMAC → check nonce → write response.
// Invalid HMAC or reused nonce drops the connection immediately with no response.
package transport

import (
	"log"
	"net"

	"github.com/acf-sdk/sidecar/internal/crypto"
)

// Config holds listener configuration.
type Config struct {
	// Address is the UDS socket path (Linux/macOS) or named pipe name (Windows).
	// If empty, Connector.DefaultAddress() is used.
	Address    string
	Connector  Connector
	Signer     *crypto.Signer
	NonceStore *crypto.NonceStore
}

// Listener wraps a platform net.Listener and handles incoming connections.
type Listener struct {
	cfg    Config
	ln     net.Listener
	stopCh chan struct{}
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
		cfg:    cfg,
		ln:     ln,
		stopCh: make(chan struct{}),
	}, nil
}

// Serve enters the accept loop. Blocks until Stop is called.
// Returns nil after a clean shutdown, or a non-nil error on unexpected failure.
func (l *Listener) Serve() error {
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
		go l.handleConn(conn)
	}
}

// Stop closes the underlying listener, causing Serve to return.
func (l *Listener) Stop() {
	select {
	case <-l.stopCh:
		// already stopped
	default:
		close(l.stopCh)
	}
	l.ln.Close()
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

	// 2. Canonicalize and verify HMAC.
	length := uint32(len(rf.Payload))
	signedMsg, err := SignedMessage(rf.Version, length, rf.Nonce, rf.Payload)
	if err != nil {
		log.Printf("transport: canonicalization failed: %v", err)
		return
	}
	if !l.cfg.Signer.Verify(signedMsg, rf.HMAC[:]) {
		log.Printf("transport: %v", ErrBadHMAC)
		return
	}

	// 3. Check nonce replay.
	if l.cfg.NonceStore.Seen(rf.Nonce[:]) {
		log.Printf("transport: %v", ErrReplayNonce)
		return
	}

	// 4. Phase 1: return a hardcoded ALLOW response.
	//    Pipeline stages are wired in Phase 2.
	resp := EncodeResponse(&ResponseFrame{Decision: DecisionAllow})
	if _, err := conn.Write(resp); err != nil {
		log.Printf("transport: write error: %v", err)
	}
}
