package telemetry

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/transport"
)

func TestTimingLog_WritesOneJSONLinePerRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timing.jsonl")
	tl, err := NewTimingLog(path)
	if err != nil {
		t.Fatalf("NewTimingLog: %v", err)
	}
	for i := 0; i < 3; i++ {
		tl.Record(transport.Timing{
			HookType:     "on_context",
			Decision:     transport.DecisionSanitise,
			PayloadBytes: 100 + i,
			Verify:       2 * time.Microsecond,
			Pipeline: pipeline.Trace{
				Stages: []pipeline.StageTiming{{Name: "scan", Duration: 3 * time.Microsecond}},
				Policy: 5 * time.Microsecond,
			},
			Total: time.Millisecond,
		})
	}
	if err := tl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var lines []timingRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec timingRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line %q is not JSON: %v", sc.Text(), err)
		}
		lines = append(lines, rec)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	got := lines[2]
	if got.HookType != "on_context" || got.Decision != transport.DecisionSanitise || got.PayloadBytes != 102 {
		t.Errorf("record = %+v", got)
	}
	if got.VerifyNs != 2000 || got.StagesNs["scan"] != 3000 || got.PolicyNs != 5000 || got.TotalNs != 1_000_000 {
		t.Errorf("durations = %+v", got)
	}
	if tl.Dropped() != 0 {
		t.Errorf("dropped %d records, want 0", tl.Dropped())
	}
}

func TestTimingLog_RecordDropsInsteadOfBlocking(t *testing.T) {
	// No writer goroutine and no buffer: the only way Record can return is by
	// dropping.
	tl := &TimingLog{ch: make(chan transport.Timing)}
	done := make(chan struct{})
	go func() {
		tl.Record(transport.Timing{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Record blocked on a full buffer")
	}
	if tl.Dropped() != 1 {
		t.Errorf("Dropped = %d, want 1", tl.Dropped())
	}
}
