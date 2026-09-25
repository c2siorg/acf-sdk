// timing.go — per-request timing log for overhead measurement.
// Enabled by setting ACF_TIMING_LOG to a file path. Record never blocks the
// enforcement path: timings go onto a buffered channel and a background
// goroutine writes them as JSON lines. When the buffer is full the record is
// dropped and counted, so a slow disk cannot add latency to a request.
package telemetry

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"

	"github.com/acf-sdk/sidecar/internal/transport"
)

// timingBuffer is the number of records held before new ones are dropped.
const timingBuffer = 1 << 14

// TimingLog writes transport.Timing records to a file asynchronously.
type TimingLog struct {
	f       *os.File
	ch      chan transport.Timing
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64
}

// timingRecord is the JSON line written for one request. Durations are in
// nanoseconds.
type timingRecord struct {
	HookType     string           `json:"hook_type"`
	Decision     byte             `json:"decision"`
	BlockedAt    string           `json:"blocked_at,omitempty"`
	PayloadBytes int              `json:"payload_bytes"`
	ReadNs       int64            `json:"read_ns"`
	VerifyNs     int64            `json:"verify_ns"`
	NonceNs      int64            `json:"nonce_ns"`
	UnmarshalNs  int64            `json:"unmarshal_ns"`
	StagesNs     map[string]int64 `json:"stages_ns"`
	PolicyNs     int64            `json:"policy_ns"`
	SanitiseNs   int64            `json:"sanitise_ns"`
	LogNs        int64            `json:"log_ns"`
	WriteNs      int64            `json:"write_ns"`
	TotalNs      int64            `json:"total_ns"`
}

// NewTimingLog creates (or truncates) path and starts the writer goroutine.
func NewTimingLog(path string) (*TimingLog, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	t := &TimingLog{
		f:    f,
		ch:   make(chan transport.Timing, timingBuffer),
		done: make(chan struct{}),
	}
	go t.run()
	return t, nil
}

// Record queues tm for writing. It never blocks; a full buffer drops tm.
// Safe for concurrent use. Satisfies the transport.Config OnTiming hook.
func (t *TimingLog) Record(tm transport.Timing) {
	select {
	case t.ch <- tm:
	default:
		t.dropped.Add(1)
	}
}

// Dropped returns how many records were discarded because the buffer was full.
func (t *TimingLog) Dropped() uint64 { return t.dropped.Load() }

// Close stops accepting records, flushes what is queued, and closes the file.
// Record must not be called after Close.
func (t *TimingLog) Close() error {
	var err error
	t.once.Do(func() {
		close(t.ch)
		<-t.done
		err = t.f.Close()
	})
	return err
}

func (t *TimingLog) run() {
	defer close(t.done)
	w := bufio.NewWriterSize(t.f, 1<<16)
	enc := json.NewEncoder(w)
	for tm := range t.ch {
		_ = enc.Encode(toRecord(tm))
		if len(t.ch) == 0 {
			_ = w.Flush()
		}
	}
	_ = w.Flush()
}

func toRecord(tm transport.Timing) timingRecord {
	stages := make(map[string]int64, len(tm.Pipeline.Stages))
	for _, s := range tm.Pipeline.Stages {
		stages[s.Name] = s.Duration.Nanoseconds()
	}
	return timingRecord{
		HookType:     tm.HookType,
		Decision:     tm.Decision,
		BlockedAt:    tm.BlockedAt,
		PayloadBytes: tm.PayloadBytes,
		ReadNs:       tm.Read.Nanoseconds(),
		VerifyNs:     tm.Verify.Nanoseconds(),
		NonceNs:      tm.Nonce.Nanoseconds(),
		UnmarshalNs:  tm.Unmarshal.Nanoseconds(),
		StagesNs:     stages,
		PolicyNs:     tm.Pipeline.Policy.Nanoseconds(),
		SanitiseNs:   tm.Pipeline.Sanitise.Nanoseconds(),
		LogNs:        tm.Log.Nanoseconds(),
		WriteNs:      tm.Write.Nanoseconds(),
		TotalNs:      tm.Total.Nanoseconds(),
	}
}
