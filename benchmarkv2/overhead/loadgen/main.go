// Command loadgen drives a running ACF sidecar with signed requests and
// records each request's latency as the client sees it, one new connection
// per request as the Python SDK does. run_overhead.py uses it for the
// latency, payload-size, throughput and open-loop measurements.
//
// Closed loop: -concurrency workers send back to back until -requests have
// completed, which gives throughput at that concurrency.
//
// Open loop: requests are released on a fixed -rate schedule whatever the
// sidecar's speed. Latency runs from each request's scheduled time, so a
// stalled sidecar shows up as latency rather than as fewer requests sent.
//
// Latency is read from internal/clock, which uses QueryPerformanceCounter on
// Windows, where the Go runtime clock is too coarse for sub-millisecond steps.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acf-sdk/sidecar/internal/benchdata"
	"github.com/acf-sdk/sidecar/internal/clock"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/transport"
)

type result struct {
	Mode        string         `json:"mode"`
	Workload    string         `json:"workload"`
	Concurrency int            `json:"concurrency"`
	Rate        float64        `json:"rate"`
	Requests    int            `json:"requests"`
	Warmup      int            `json:"warmup"`
	Completed   int            `json:"completed"`
	Errors      int            `json:"errors"`
	FirstError  string         `json:"first_error,omitempty"`
	WallNs      int64          `json:"wall_ns"`
	Decisions   map[string]int `json:"decisions"`
	LatenciesNs []int64        `json:"latencies_ns"`
	// SendLagNs is, in open loop, how late each request started against its
	// schedule. It separates load-generator lag from sidecar latency.
	SendLagNs  []int64 `json:"send_lag_ns,omitempty"`
	GOMAXPROCS int     `json:"gomaxprocs"`
}

var decisionNames = map[int16]string{
	int16(transport.DecisionAllow):    "ALLOW",
	int16(transport.DecisionSanitise): "SANITISE",
	int16(transport.DecisionBlock):    "BLOCK",
}

type errorLog struct {
	mu    sync.Mutex
	count int
	first string
}

func (e *errorLog) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.count == 0 {
		e.first = err.Error()
	}
	e.count++
}

func main() {
	socket := flag.String("socket", "", "sidecar IPC address (required)")
	keyHex := flag.String("key", "", "hex-encoded HMAC key (required)")
	workload := flag.String("workload", "corpus", "corpus | context:<bytes>")
	mode := flag.String("mode", "closed", "closed | open")
	concurrency := flag.Int("concurrency", 1, "closed loop: concurrent workers")
	rate := flag.Float64("rate", 0, "open loop: requests per second")
	requests := flag.Int("requests", 10000, "measured requests")
	warmup := flag.Int("warmup", 500, "unmeasured requests sent one at a time before measuring")
	maxInflight := flag.Int("max-inflight", 512, "open loop: in-flight limit; requests over it count as errors")
	out := flag.String("out", "", "result JSON path (default: stdout)")
	flag.Parse()

	if *socket == "" || *keyHex == "" {
		fatalf("-socket and -key are required")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		fatalf("-key: %v", err)
	}
	signer, err := crypto.NewSigner(key)
	if err != nil {
		fatalf("signer: %v", err)
	}
	bodies, err := loadWorkload(*workload)
	if err != nil {
		fatalf("workload: %v", err)
	}

	// Sign every frame up front so signing is not measured and each request
	// still carries its own nonce.
	frames := make([][]byte, *warmup+*requests)
	for i := range frames {
		if frames[i], err = transport.EncodeRequest(bodies[i%len(bodies)], signer); err != nil {
			fatalf("sign: %v", err)
		}
	}
	for i := 0; i < *warmup; i++ {
		if _, err := roundTrip(*socket, frames[i]); err != nil {
			fatalf("warmup request %d: %v", i, err)
		}
	}

	res := result{
		Mode:        *mode,
		Workload:    *workload,
		Concurrency: *concurrency,
		Rate:        *rate,
		Requests:    *requests,
		Warmup:      *warmup,
		GOMAXPROCS:  runtime.GOMAXPROCS(0),
	}
	measured := frames[*warmup:]
	switch *mode {
	case "closed":
		closedLoop(&res, *socket, measured, *concurrency)
	case "open":
		if *rate <= 0 {
			fatalf("-rate must be positive in open loop")
		}
		openLoop(&res, *socket, measured, *rate, *maxInflight)
	default:
		fatalf("unknown -mode %q", *mode)
	}

	enc, err := json.Marshal(res)
	if err != nil {
		fatalf("encode result: %v", err)
	}
	if *out == "" {
		os.Stdout.Write(append(enc, '\n')) //nolint:errcheck
		return
	}
	if err := os.WriteFile(*out, enc, 0o644); err != nil {
		fatalf("write %s: %v", *out, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "loadgen: "+format+"\n", args...)
	os.Exit(1)
}

func loadWorkload(spec string) ([][]byte, error) {
	if spec == "corpus" {
		cases, err := benchdata.Corpus()
		if err != nil {
			return nil, err
		}
		bodies := make([][]byte, len(cases))
		for i, c := range cases {
			bodies[i] = c.Body()
		}
		return bodies, nil
	}
	if size, ok := strings.CutPrefix(spec, "context:"); ok {
		n, err := strconv.Atoi(size)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad size in %q", spec)
		}
		return [][]byte{benchdata.Body("on_context", "rag", benchdata.BenignText(n))}, nil
	}
	return nil, fmt.Errorf("unknown workload %q", spec)
}

// roundTrip opens a connection, sends one frame, and reads the response.
func roundTrip(address string, frame []byte) (byte, error) {
	conn, err := dial(address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(frame); err != nil {
		return 0, err
	}
	resp, err := transport.DecodeResponse(conn)
	if err != nil {
		return 0, err
	}
	return resp.Decision, nil
}

func newDecisions(n int) []int16 {
	dec := make([]int16, n)
	for i := range dec {
		dec[i] = -1
	}
	return dec
}

func closedLoop(res *result, address string, frames [][]byte, workers int) {
	lat := make([]int64, len(frames))
	dec := newDecisions(len(frames))
	errs := &errorLog{}
	var next atomic.Int64
	var wg sync.WaitGroup

	start := clock.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(frames) {
					return
				}
				t0 := clock.Now()
				d, err := roundTrip(address, frames[i])
				lat[i] = int64(clock.Since(t0))
				if err != nil {
					errs.add(err)
					continue
				}
				dec[i] = int16(d)
			}
		}()
	}
	wg.Wait()
	res.WallNs = int64(clock.Since(start))
	collect(res, lat, nil, dec, errs)
}

func openLoop(res *result, address string, frames [][]byte, rate float64, maxInflight int) {
	interval := time.Duration(float64(time.Second) / rate)
	lat := make([]int64, len(frames))
	lag := make([]int64, len(frames))
	dec := newDecisions(len(frames))
	errs := &errorLog{}
	var inflight atomic.Int64
	var wg sync.WaitGroup

	start := clock.Now()
	for i := range frames {
		due := start + time.Duration(i)*interval
		waitUntil(due)
		if inflight.Load() >= int64(maxInflight) {
			errs.add(fmt.Errorf("more than %d requests in flight", maxInflight))
			continue
		}
		inflight.Add(1)
		wg.Add(1)
		go func(i int, due time.Duration) {
			defer wg.Done()
			defer inflight.Add(-1)
			lag[i] = int64(clock.Now() - due)
			d, err := roundTrip(address, frames[i])
			lat[i] = int64(clock.Now() - due)
			if err != nil {
				errs.add(err)
				return
			}
			dec[i] = int16(d)
		}(i, due)
	}
	wg.Wait()
	res.WallNs = int64(clock.Since(start))
	collect(res, lat, lag, dec, errs)
}

// waitUntil sleeps until close to due, then yields until due. Sleep alone
// overshoots by up to a timer tick on Windows.
func waitUntil(due time.Duration) {
	for {
		left := due - clock.Now()
		if left <= 0 {
			return
		}
		if left > 2*time.Millisecond {
			time.Sleep(left - 2*time.Millisecond)
			continue
		}
		runtime.Gosched()
	}
}

func collect(res *result, lat, lag []int64, dec []int16, errs *errorLog) {
	res.Decisions = map[string]int{}
	for i, d := range dec {
		if d < 0 {
			continue
		}
		res.Completed++
		res.LatenciesNs = append(res.LatenciesNs, lat[i])
		if lag != nil {
			res.SendLagNs = append(res.SendLagNs, lag[i])
		}
		name, ok := decisionNames[d]
		if !ok {
			name = fmt.Sprintf("0x%02x", d)
		}
		res.Decisions[name]++
	}
	res.Errors = errs.count
	res.FirstError = errs.first
}
