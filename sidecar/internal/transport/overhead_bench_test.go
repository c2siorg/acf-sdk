package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/benchdata"
	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/pipeline"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

var benchKey = []byte("bench-key-32-bytes-long-padded!!")

// benchPipeline builds the pipeline main.go builds, from the shipped config,
// patterns and policies.
func benchPipeline(b *testing.B) *pipeline.Pipeline {
	b.Helper()
	cfg, err := config.Load(benchdata.ConfigPath())
	if err != nil {
		b.Fatalf("config: %v", err)
	}
	pats, err := config.LoadPatterns(benchdata.PolicyDir())
	if err != nil {
		b.Fatalf("patterns: %v", err)
	}
	eng, err := policy.NewEngine(benchdata.PolicyDir())
	if err != nil {
		b.Fatalf("engine: %v", err)
	}
	b.Cleanup(eng.Stop)
	return pipeline.NewWithEvaluator(cfg, []pipeline.Stage{
		pipeline.NewValidateStage(),
		pipeline.NewNormaliseStage(),
		pipeline.NewScanStage(cfg, pats.Entries),
		pipeline.NewAggregateStage(cfg, eng),
	}, eng)
}

func corpusBodies(b *testing.B) [][]byte {
	b.Helper()
	cases, err := benchdata.Corpus()
	if err != nil {
		b.Fatalf("corpus: %v", err)
	}
	bodies := make([][]byte, len(cases))
	for i, c := range cases {
		bodies[i] = c.Body()
	}
	return bodies
}

func contextBody(n int) [][]byte {
	return [][]byte{benchdata.Body("on_context", "rag", benchdata.BenignText(n))}
}

// framePool hands out signed frames with fresh nonces, as the SDK sends them.
// It signs in batches with the timer stopped so signing is not measured.
type framePool struct {
	b      *testing.B
	signer *crypto.Signer
	bodies [][]byte
	frames [][]byte
	next   int
	sent   int
}

func (p *framePool) get() []byte {
	if p.next == len(p.frames) {
		p.b.StopTimer()
		p.frames = p.frames[:0]
		for j := 0; j < 1024; j++ {
			f, err := EncodeRequest(p.bodies[p.sent%len(p.bodies)], p.signer)
			if err != nil {
				p.b.Fatal(err)
			}
			p.frames = append(p.frames, f)
			p.sent++
		}
		p.next = 0
		p.b.StartTimer()
	}
	f := p.frames[p.next]
	p.next++
	return f
}

// quietLog sends the standard logger to w for the rest of the benchmark.
func quietLog(b *testing.B, w io.Writer) {
	prev := log.Writer()
	log.SetOutput(w)
	b.Cleanup(func() { log.SetOutput(prev) })
}

func BenchmarkDecodeRequest(b *testing.B) {
	signer, _ := crypto.NewSigner(benchKey)
	for _, n := range benchdata.Sizes {
		frame, err := EncodeRequest(contextBody(n)[0], signer)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("size=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			r := bytes.NewReader(frame)
			for i := 0; i < b.N; i++ {
				r.Reset(frame)
				if _, err := DecodeRequest(r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerify is step 2 of handleConn: rebuild the signed message and
// check its HMAC.
func BenchmarkVerify(b *testing.B) {
	signer, _ := crypto.NewSigner(benchKey)
	for _, n := range benchdata.Sizes {
		frame, _ := EncodeRequest(contextBody(n)[0], signer)
		rf, err := DecodeRequest(bytes.NewReader(frame))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("size=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(rf.Payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				msg := SignedMessage(rf.Version, uint32(len(rf.Payload)), rf.Nonce, rf.Payload)
				if !signer.Verify(msg, rf.HMAC[:]) {
					b.Fatal("HMAC did not verify")
				}
			}
		})
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	run := func(name string, bodies [][]byte, setBytes bool) {
		b.Run(name, func(b *testing.B) {
			if setBytes {
				b.SetBytes(int64(len(bodies[0])))
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var rc riskcontext.RiskContext
				if err := json.Unmarshal(bodies[i%len(bodies)], &rc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	run("corpus", corpusBodies(b), false)
	for _, n := range benchdata.Sizes {
		run(fmt.Sprintf("size=%d", n), contextBody(n), true)
	}
}

// BenchmarkHandleConn runs the real request handler over an in-memory pipe:
// every sidecar step for one request, without the OS IPC channel.
func BenchmarkHandleConn(b *testing.B) {
	pl := benchPipeline(b)
	signer, _ := crypto.NewSigner(benchKey)
	logFile, err := os.Create(filepath.Join(b.TempDir(), "sidecar.log"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { logFile.Close() })

	corpus := corpusBodies(b)
	variants := []struct {
		name     string
		bodies   [][]byte
		out      io.Writer
		onTiming func(Timing)
	}{
		{"corpus/log=discard", corpus, io.Discard, nil},
		{"corpus/log=file", corpus, logFile, nil},
		{"corpus/log=discard/timing=on", corpus, io.Discard, func(Timing) {}},
	}
	for _, n := range benchdata.Sizes {
		variants = append(variants, struct {
			name     string
			bodies   [][]byte
			out      io.Writer
			onTiming func(Timing)
		}{fmt.Sprintf("size=%d/log=discard", n), contextBody(n), io.Discard, nil})
	}

	for _, v := range variants {
		b.Run(v.name, func(b *testing.B) {
			quietLog(b, v.out)
			ns := crypto.NewNonceStore(5 * time.Minute)
			defer ns.Stop()
			l := &Listener{cfg: Config{Signer: signer, NonceStore: ns, Pipeline: pl, OnTiming: v.onTiming}}
			pool := &framePool{b: b, signer: signer, bodies: v.bodies}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				frame := pool.get()
				client, server := net.Pipe()
				go l.handleConn(server)
				if _, err := client.Write(frame); err != nil {
					b.Fatal(err)
				}
				if _, err := DecodeResponse(client); err != nil {
					b.Fatal(err)
				}
				client.Close()
			}
		})
	}
}

func benchAddress() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\acf_bench_%d`, time.Now().UnixNano())
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("acf_bench_%d.sock", time.Now().UnixNano()))
}

// BenchmarkIPCRoundTrip is one request over the platform IPC channel with a
// new connection per request, as the Python SDK does. auth-only has no
// pipeline, so it is the cost of the channel, framing, HMAC and nonce check.
func BenchmarkIPCRoundTrip(b *testing.B) {
	signer, _ := crypto.NewSigner(benchKey)
	bodies := corpusBodies(b)
	quietLog(b, io.Discard)

	for _, v := range []struct {
		name string
		pl   *pipeline.Pipeline
	}{{"auth-only", nil}, {"full", benchPipeline(b)}} {
		b.Run(v.name+"/corpus", func(b *testing.B) {
			ns := crypto.NewNonceStore(5 * time.Minute)
			defer ns.Stop()
			address := benchAddress()
			ln, err := NewListener(Config{
				Address:    address,
				Connector:  DefaultConnector(),
				Signer:     signer,
				NonceStore: ns,
				Pipeline:   v.pl,
			})
			if err != nil {
				b.Fatal(err)
			}
			go ln.Serve() //nolint:errcheck
			defer ln.Stop()

			pool := &framePool{b: b, signer: signer, bodies: bodies}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				frame := pool.get()
				conn, err := platformDial(address)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := conn.Write(frame); err != nil {
					b.Fatal(err)
				}
				if _, err := DecodeResponse(conn); err != nil {
					b.Fatal(err)
				}
				conn.Close()
			}
		})
	}
}
