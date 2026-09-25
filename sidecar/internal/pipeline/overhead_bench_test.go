package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/acf-sdk/sidecar/internal/benchdata"
	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

var benchHooks = []string{"on_prompt", "on_context", "on_tool_call", "on_memory"}

// benchEnv is the pipeline main.go builds, from the shipped config, patterns
// and policies.
type benchEnv struct {
	cfg    *config.Config
	eng    *policy.Engine
	stages []Stage
	pl     *Pipeline
}

func newBenchEnv(tb testing.TB) *benchEnv {
	tb.Helper()
	cfg, err := config.Load(benchdata.ConfigPath())
	if err != nil {
		tb.Fatalf("config: %v", err)
	}
	pats, err := config.LoadPatterns(benchdata.PolicyDir())
	if err != nil {
		tb.Fatalf("patterns: %v", err)
	}
	eng, err := policy.NewEngine(benchdata.PolicyDir())
	if err != nil {
		tb.Fatalf("engine: %v", err)
	}
	tb.Cleanup(eng.Stop)
	stages := []Stage{
		NewValidateStage(),
		NewNormaliseStage(),
		NewScanStage(cfg, pats.Entries),
		NewAggregateStage(cfg, eng),
	}
	return &benchEnv{cfg: cfg, eng: eng, stages: stages, pl: NewWithEvaluator(cfg, stages, eng)}
}

// snapshots decodes each body and records it as it enters each stage:
// out[k][i] is body i before stage k, and out[len(stages)][i] is after the
// last stage, as OPA sees it.
func (e *benchEnv) snapshots(tb testing.TB, bodies [][]byte) [][]riskcontext.RiskContext {
	tb.Helper()
	out := make([][]riskcontext.RiskContext, len(e.stages)+1)
	for _, body := range bodies {
		var rc riskcontext.RiskContext
		if err := json.Unmarshal(body, &rc); err != nil {
			tb.Fatalf("unmarshal: %v", err)
		}
		for k, s := range e.stages {
			out[k] = append(out[k], cloneRC(rc))
			s.Run(&rc)
		}
		out[len(e.stages)] = append(out[len(e.stages)], cloneRC(rc))
	}
	return out
}

func cloneRC(rc riskcontext.RiskContext) riskcontext.RiskContext {
	rc.Signals = append(rc.Signals[:0:0], rc.Signals...)
	return rc
}

// corpusBodies returns the corpus request bodies for hook, or all of them
// when hook is empty.
func corpusBodies(tb testing.TB, hook string) [][]byte {
	tb.Helper()
	cases, err := benchdata.Corpus()
	if err != nil {
		tb.Fatalf("corpus: %v", err)
	}
	var bodies [][]byte
	for _, c := range cases {
		if hook == "" || c.HookType == hook {
			bodies = append(bodies, c.Body())
		}
	}
	return bodies
}

func contextBody(text string) [][]byte {
	return [][]byte{benchdata.Body("on_context", "rag", text)}
}

// runStage runs s on copies of in, cycling through them. Each copy is a
// struct copy, so per-iteration setup is a few nanoseconds.
func runStage(b *testing.B, s Stage, in []riskcontext.RiskContext, bytes int) {
	if bytes > 0 {
		b.SetBytes(int64(bytes))
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rc := in[i%len(in)]
		s.Run(&rc)
	}
}

func BenchmarkStage(b *testing.B) {
	env := newBenchEnv(b)
	snaps := env.snapshots(b, corpusBodies(b, ""))
	for k, s := range env.stages {
		b.Run(s.Name()+"/corpus", func(b *testing.B) { runStage(b, s, snaps[k], 0) })
	}
}

func BenchmarkPolicy(b *testing.B) {
	env := newBenchEnv(b)
	for _, hook := range benchHooks {
		in := env.snapshots(b, corpusBodies(b, hook))[len(env.stages)]
		b.Run(hook, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc := in[i%len(in)]
				if _, _, err := env.eng.Evaluate(&rc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPipeline is all four stages, OPA, and the executor on SANITISE.
func BenchmarkPipeline(b *testing.B) {
	env := newBenchEnv(b)
	run := func(name string, bodies [][]byte, bytes int) {
		in := env.snapshots(b, bodies)[0]
		b.Run(name, func(b *testing.B) {
			if bytes > 0 {
				b.SetBytes(int64(bytes))
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc := in[i%len(in)]
				env.pl.Run(&rc)
			}
		})
	}
	run("corpus", corpusBodies(b, ""), 0)
	for _, hook := range benchHooks {
		run(hook, corpusBodies(b, hook), 0)
	}
}

// BenchmarkSize sweeps an on_context chunk from 256 B to 64 KB, clean and with
// one injected sentence.
func BenchmarkSize(b *testing.B) {
	env := newBenchEnv(b)
	kinds := []struct {
		name string
		gen  func(int) string
	}{{"benign", benchdata.BenignText}, {"injected", benchdata.InjectedText}}
	for _, stage := range []string{"normalise", "scan", "pipeline"} {
		for _, kind := range kinds {
			for _, n := range benchdata.Sizes {
				snaps := env.snapshots(b, contextBody(kind.gen(n)))
				name := fmt.Sprintf("%s/%s/size=%d", stage, kind.name, n)
				switch stage {
				case "normalise":
					b.Run(name, func(b *testing.B) { runStage(b, env.stages[1], snaps[1], n) })
				case "scan":
					b.Run(name, func(b *testing.B) { runStage(b, env.stages[2], snaps[2], n) })
				case "pipeline":
					b.Run(name, func(b *testing.B) {
						b.SetBytes(int64(n))
						b.ReportAllocs()
						for i := 0; i < b.N; i++ {
							rc := snaps[0][0]
							env.pl.Run(&rc)
						}
					})
				}
			}
		}
	}
}

// adversarialInputs make normalise do the most work: every decode layer is a
// full pass over the text.
var adversarialInputs = []struct {
	name string
	gen  func(int) string
}{
	{"benign", benchdata.BenignText},
	{"base64-tokens", benchdata.Base64Tokens},
	{"base64-depth=1", func(n int) string { return benchdata.Base64Nested(n, 1) }},
	{"base64-depth=3", func(n int) string { return benchdata.Base64Nested(n, 3) }},
	{"base64-depth=6", func(n int) string { return benchdata.Base64Nested(n, 6) }},
	{"url-depth=4", func(n int) string { return benchdata.URLNested(n, 4) }},
	{"url-depth=12", func(n int) string { return benchdata.URLNested(n, 12) }},
	{"zerowidth", benchdata.ZeroWidthDense},
}

func BenchmarkNormaliseAdversarial(b *testing.B) {
	st := NewNormaliseStage()
	for _, in := range adversarialInputs {
		for _, n := range []int{4096, 65536} {
			text := in.gen(n)
			b.Run(fmt.Sprintf("%s/size=%d", in.name, n), func(b *testing.B) {
				b.SetBytes(int64(len(text)))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					rc := riskcontext.RiskContext{HookType: "on_context", Provenance: "rag", Payload: text}
					st.Run(&rc)
				}
			})
		}
	}
}

// BenchmarkScanPatterns scales the pattern library past the shipped one on a
// fixed 4 KB chunk.
func BenchmarkScanPatterns(b *testing.B) {
	cfg, err := config.Load(benchdata.ConfigPath())
	if err != nil {
		b.Fatalf("config: %v", err)
	}
	shipped, err := config.LoadPatterns(benchdata.PolicyDir())
	if err != nil {
		b.Fatalf("patterns: %v", err)
	}
	const n = 4096
	text := benchdata.InjectedText(n)
	canonical := normalise(text)

	sets := []struct {
		name    string
		entries []config.PatternEntry
	}{
		{fmt.Sprintf("patterns=%d", len(shipped.Entries)), shipped.Entries},
		{"patterns=1000", benchdata.SyntheticPatterns(1000, 1)},
		{"patterns=10000", benchdata.SyntheticPatterns(10000, 1)},
		{"patterns=100000", benchdata.SyntheticPatterns(100000, 1)},
	}
	for _, set := range sets {
		st := NewScanStage(cfg, set.entries)
		b.Run(fmt.Sprintf("%s/size=%d", set.name, n), func(b *testing.B) {
			b.SetBytes(n)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc := riskcontext.RiskContext{
					HookType: "on_context", Provenance: "rag", Payload: text, CanonicalText: canonical,
				}
				st.Run(&rc)
			}
		})
	}
}

// BenchmarkSanitise is the executor transform for a chunk OPA sanitises.
func BenchmarkSanitise(b *testing.B) {
	env := newBenchEnv(b)
	for _, n := range []int{1024, 16384} {
		after := env.snapshots(b, contextBody(benchdata.InjectedText(n)))[len(env.stages)][0]
		probe := cloneRC(after)
		verdict, targets, err := env.eng.Evaluate(&probe)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("size=%d", n), func(b *testing.B) {
			if verdict != "SANITISE" || len(targets) == 0 {
				b.Skipf("OPA returned %s with targets %v, not SANITISE", verdict, targets)
			}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc := after
				policy.ApplySanitise(targets, &rc)
			}
		})
	}
}

// TestBenchWorkloads_ExerciseTheirPaths guards the benchmarks against
// measuring the wrong thing: the injected chunk must be flagged, the clean
// chunk allowed, and the nested encodings actually decoded.
func TestBenchWorkloads_ExerciseTheirPaths(t *testing.T) {
	env := newBenchEnv(t)
	verdict := func(text string) byte {
		rc := env.snapshots(t, contextBody(text))[0][0]
		return env.pl.Run(&rc).Decision
	}
	for _, n := range benchdata.Sizes {
		if d := verdict(benchdata.BenignText(n)); d != decision.Allow {
			t.Errorf("benign size=%d: decision %d, want ALLOW", n, d)
		}
		if d := verdict(benchdata.InjectedText(n)); d == decision.Allow {
			t.Errorf("injected size=%d: ALLOW, want SANITISE or BLOCK", n)
		}
	}
	if got := normalise(benchdata.Base64Tokens(4096)); !strings.Contains(got, benchdata.Phrase) {
		t.Errorf("base64 tokens were not decoded: %.80q", got)
	}
	for _, depth := range []int{1, 3, 6} {
		if got := normalise(benchdata.Base64Nested(4096, depth)); !strings.Contains(got, benchdata.Phrase) {
			t.Errorf("base64 depth %d was not decoded: %.80q", depth, got)
		}
	}
	if got := normalise(benchdata.URLNested(4096, 12)); !strings.Contains(got, "ignore previous instructions") {
		t.Errorf("url depth 12 was not decoded: %.80q", got)
	}
}
