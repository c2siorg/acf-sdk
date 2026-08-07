// audit.go — structured audit log formatting.
// Writes one JSON line per enforcement decision to the configured audit sink.
// Fields: hook_type, decision, score, signals, provenance, session_id, policy_version, trace_id.
package telemetry

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEntry is one record written to the audit sink. Raw payloads and
// canonical text are deliberately never included.
type AuditEntry struct {
	Timestamp      string   `json:"ts"`
	TraceID        string   `json:"trace_id,omitempty"`
	SpanID         string   `json:"span_id,omitempty"`
	HookType       string   `json:"hook_type"`
	Decision       string   `json:"decision"`
	Score          float64  `json:"score"`
	Signals        []string `json:"signals"`
	Provenance     string   `json:"provenance"`
	SessionID      string   `json:"session_id,omitempty"`
	PolicyVersion  string   `json:"policy_version"`
	BlockedAt      string   `json:"blocked_at,omitempty"`
	DurationMillis float64  `json:"duration_ms"`
}

// AuditSink accepts audit entries. Implementations must be safe to call from
// any goroutine and must not block the caller.
type AuditSink interface {
	Emit(AuditEntry)
	Close() error
	Dropped() uint64
}

// NopSink discards everything. Default when Options.AuditSink is nil.
type NopSink struct{}

func (NopSink) Emit(AuditEntry) {}
func (NopSink) Close() error    { return nil }
func (NopSink) Dropped() uint64 { return 0 }

// asyncJSONSink drains entries onto an io.Writer in a background goroutine.
// The state mutex protects the closed flag and the channel close, so Emit
// can never race a Close into sending on a closed channel.
type asyncJSONSink struct {
	w       io.Writer
	ch      chan AuditEntry
	wg      sync.WaitGroup
	dropped atomic.Uint64

	mu     sync.RWMutex
	closed bool

	writeMu  sync.Mutex
	errOnce  sync.Once
	writeErr error
}

// NewAsyncSink wraps w in an async JSON-line audit sink with the given buffer
// size. Emit is non-blocking; entries are dropped when the buffer is full or
// after Close.
func NewAsyncSink(w io.Writer, buffer int) AuditSink {
	if buffer < 1 {
		buffer = 1
	}
	s := &asyncJSONSink{
		w:  w,
		ch: make(chan AuditEntry, buffer),
	}
	s.wg.Add(1)
	go s.drain()
	return s
}

func (s *asyncJSONSink) Emit(e AuditEntry) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

func (s *asyncJSONSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.writeErr
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
	s.wg.Wait()
	return s.writeErr
}

func (s *asyncJSONSink) Dropped() uint64 { return s.dropped.Load() }

func (s *asyncJSONSink) drain() {
	defer s.wg.Done()
	for entry := range s.ch {
		s.writeOne(entry)
	}
}

func (s *asyncJSONSink) writeOne(e AuditEntry) {
	line, err := json.Marshal(e)
	if err != nil {
		s.errOnce.Do(func() { s.writeErr = err })
		return
	}
	line = append(line, '\n')
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.w.Write(line); err != nil {
		s.errOnce.Do(func() { s.writeErr = err })
	}
}

// NewEntry builds a skeleton AuditEntry with the current UTC timestamp.
func NewEntry() AuditEntry {
	return AuditEntry{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	}
}
