package transport

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/telemetry"
)

func newTestListener(t *testing.T) (*Listener, *crypto.Signer, string) {
	return newTestListenerWithOptions(t, nil, nil)
}

func newTestListenerWithOptions(
	t *testing.T,
	audit telemetry.AuditSink,
	pl *pipeline.Pipeline,
) (*Listener, *crypto.Signer, string) {
	t.Helper()

	address := testAddress(t) // platform-specific: socket path or pipe name
	signer, err := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	t.Cleanup(nonceStore.Stop)

	ln, err := NewListener(Config{
		Address:       address,
		Connector:     DefaultConnector(),
		Signer:        signer,
		NonceStore:    nonceStore,
		AuditSink:     audit,
		PolicyVersion: "v1",
		Pipeline:      pl,
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}

	go ln.Serve() //nolint:errcheck
	t.Cleanup(ln.Stop)
	// Give the goroutine time to start accepting.
	time.Sleep(10 * time.Millisecond)

	return ln, signer, address
}

type capturedAuditSink struct {
	mu      sync.Mutex
	entries []telemetry.AuditEntry
}

func (s *capturedAuditSink) Emit(entry telemetry.AuditEntry) {
	s.mu.Lock()
	s.entries = append(s.entries, entry)
	s.mu.Unlock()
}

func (*capturedAuditSink) Close() error    { return nil }
func (*capturedAuditSink) Dropped() uint64 { return 0 }

func requireAuditCategory(t *testing.T, sink *capturedAuditSink, category string) {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, entry := range sink.entries {
		if len(entry.Signals) == 1 && entry.Signals[0] == category {
			if entry.Decision != "block" || entry.BlockedAt != "transport" || entry.PolicyVersion != "v1" {
				t.Fatalf("audit entry = %+v", entry)
			}
			return
		}
	}
	t.Fatalf("missing audit category %q in %+v", category, sink.entries)
}

// dial opens a client connection to the test listener.
func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	c, err := platformDial(address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	return c
}

func sendFrame(t *testing.T, address string, frame []byte) ([]byte, error) {
	t.Helper()
	conn, err := platformDial(address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func TestListener_RoundTrip(t *testing.T) {
	_, signer, address := newTestListener(t)

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
		t.Errorf("expected ALLOW (0x00), got %#x", resp[0])
	}
}

func TestListener_BadHMAC(t *testing.T) {
	audit := &capturedAuditSink{}
	_, signer, address := newTestListenerWithOptions(t, audit, nil)

	frame, _ := EncodeRequest([]byte(`{}`), signer)
	frame[22] ^= 0xFF // corrupt the HMAC

	conn, err := platformDial(address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	conn.Write(frame) //nolint:errcheck

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Errorf("expected no response on bad HMAC, got %d bytes", n)
	}
	requireAuditCategory(t, audit, "transport:hmac_invalid")
}

func TestListener_NonceReplay(t *testing.T) {
	audit := &capturedAuditSink{}
	_, signer, address := newTestListenerWithOptions(t, audit, nil)

	payload := []byte(`{"hook_type":"on_prompt","payload":"hi","session_id":"s1","provenance":"user","signals":[],"score":0,"state":null}`)
	frame, _ := EncodeRequest(payload, signer)

	// First request — should succeed.
	resp, err := sendFrame(t, address, frame)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if len(resp) < 1 || resp[0] != DecisionAllow {
		t.Fatalf("first request: expected ALLOW, got %v", resp)
	}

	// Replay: same frame, same nonce — must be rejected.
	conn, err := platformDial(address)
	if err != nil {
		t.Fatalf("replay dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	conn.Write(frame) //nolint:errcheck

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Errorf("expected no response on nonce replay, got %d bytes", n)
	}
	requireAuditCategory(t, audit, "transport:replay_nonce")
}

func TestListener_BadMagic(t *testing.T) {
	audit := &capturedAuditSink{}
	_, signer, address := newTestListenerWithOptions(t, audit, nil)

	frame, _ := EncodeRequest([]byte(`{}`), signer)
	frame[0] = 0xFF // corrupt magic byte

	conn, err := platformDial(address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	conn.Write(frame) //nolint:errcheck

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Errorf("expected no response on bad magic, got %d bytes", n)
	}
	requireAuditCategory(t, audit, "transport:bad_magic")
}

func TestListener_BadJSONAudit(t *testing.T) {
	audit := &capturedAuditSink{}
	cfg := &config.Config{}
	pl := pipeline.New(cfg, nil)
	_, signer, address := newTestListenerWithOptions(t, audit, pl)

	frame, err := EncodeRequest([]byte(`{"hook_type":`), signer)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	resp, err := sendFrame(t, address, frame)
	if err != nil {
		t.Fatalf("send frame: %v", err)
	}
	if len(resp) < 1 || resp[0] != DecisionBlock {
		t.Fatalf("expected BLOCK, got %v", resp)
	}
	requireAuditCategory(t, audit, "transport:invalid_json")
}

func TestDecodeRejectCategory(t *testing.T) {
	if got := decodeRejectCategory(ErrBadVersion); got != "transport:bad_version" {
		t.Fatalf("bad version category = %q", got)
	}
}

func TestListener_Stop(t *testing.T) {
	address := testAddress(t)
	signer, _ := crypto.NewSigner([]byte("test-key-32-bytes-long-padded!!!"))
	nonceStore := crypto.NewNonceStore(5 * time.Minute)
	defer nonceStore.Stop()

	ln, err := NewListener(Config{
		Address:    address,
		Connector:  DefaultConnector(),
		Signer:     signer,
		NonceStore: nonceStore,
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- ln.Serve() }()

	time.Sleep(10 * time.Millisecond)
	ln.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error after Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return after Stop within 2s")
	}
}
