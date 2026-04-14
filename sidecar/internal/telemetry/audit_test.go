package telemetry

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestAuditEntry_JSONShape(t *testing.T) {
	entry := NewEntry()
	entry.HookType = "on_prompt"
	entry.Decision = "block"
	entry.Score = 0.91
	entry.Signals = []string{"jailbreak_pattern"}
	entry.Provenance = "user"
	entry.SessionID = "sess-1"
	entry.PolicyVersion = "v1"
	entry.BlockedAt = "scan"
	entry.DurationMillis = 1.7
	entry.TraceID = "0123456789abcdef0123456789abcdef"
	entry.SpanID = "0123456789abcdef"

	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	required := []string{
		`"ts":`,
		`"hook_type":"on_prompt"`,
		`"decision":"block"`,
		`"score":0.91`,
		`"signals":["jailbreak_pattern"]`,
		`"provenance":"user"`,
		`"session_id":"sess-1"`,
		`"policy_version":"v1"`,
		`"trace_id":"0123456789abcdef0123456789abcdef"`,
		`"span_id":"0123456789abcdef"`,
		`"blocked_at":"scan"`,
		`"duration_ms":1.7`,
	}
	for _, frag := range required {
		if !bytes.Contains(raw, []byte(frag)) {
			t.Errorf("audit JSON missing fragment %q in: %s", frag, raw)
		}
	}

	for _, frag := range []string{`"payload"`, `"canonical_text"`} {
		if bytes.Contains(raw, []byte(frag)) {
			t.Errorf("audit JSON must not include %q, got: %s", frag, raw)
		}
	}
}

func TestAsyncSink_WritesJSONLine(t *testing.T) {
	var buf safeBuffer
	sink := NewAsyncSink(&buf, 8)

	entry := NewEntry()
	entry.HookType = "on_prompt"
	entry.Decision = "allow"
	entry.Score = 0.1
	sink.Emit(entry)

	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw := buf.String()
	if !strings.HasSuffix(raw, "\n") {
		t.Errorf("expected trailing newline, got %q", raw)
	}
	var decoded AuditEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &decoded); err != nil {
		t.Fatalf("decode: %v raw=%q", err, raw)
	}
	if decoded.HookType != "on_prompt" || decoded.Decision != "allow" {
		t.Errorf("round-trip mismatch: %+v", decoded)
	}
}

func TestAsyncSink_DropsUnderBackpressure(t *testing.T) {
	gate := make(chan struct{})
	w := &gatedWriter{release: gate}

	sink := NewAsyncSink(w, 2)

	const sent = 50
	for i := 0; i < sent; i++ {
		entry := NewEntry()
		entry.HookType = "on_prompt"
		sink.Emit(entry)
	}

	dropped := sink.Dropped()
	if dropped == 0 {
		t.Fatalf("expected some drops under backpressure, got 0")
	}

	close(gate)
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if dropped+3 < sent-10 {
		t.Errorf("dropped=%d + absorbed=3 < sent=%d", dropped, sent)
	}
}

func TestAsyncSink_ConcurrentEmit(t *testing.T) {
	var buf safeBuffer
	sink := NewAsyncSink(&buf, 4096)

	const workers = 16
	const perWorker = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				entry := NewEntry()
				entry.HookType = "on_prompt"
				entry.Decision = "allow"
				sink.Emit(entry)
			}
		}()
	}
	wg.Wait()

	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wrote := strings.Count(buf.String(), "\n")
	drop := int(sink.Dropped())
	if total := wrote + drop; total != workers*perWorker {
		t.Errorf("accounting mismatch: wrote=%d dropped=%d total=%d want=%d",
			wrote, drop, total, workers*perWorker)
	}
}

func TestAsyncSink_EmitAfterCloseNoop(t *testing.T) {
	var buf safeBuffer
	sink := NewAsyncSink(&buf, 8)
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for i := 0; i < 5; i++ {
		sink.Emit(NewEntry())
	}
	if buf.Len() != 0 {
		t.Errorf("expected no writes after Close, got %d bytes", buf.Len())
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestNopSink_Interface(t *testing.T) {
	var sink AuditSink = NopSink{}
	sink.Emit(NewEntry())
	if got := sink.Dropped(); got != 0 {
		t.Errorf("expected 0 drops from NopSink, got %d", got)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("NopSink.Close returned %v", err)
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

type gatedWriter struct {
	release chan struct{}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	<-g.release
	return len(p), nil
}
