// harness_test.go: end-to-end integration test suite.
// Spins up a real sidecar process, connects via UDS, fires each payload from
// adversarial_payloads.json, and asserts the decision matches expectations.
//
// Coverage grows toward all adversarial categories across the four hook types.
// Run with: make integration (builds the sidecar, then runs this suite).
package integration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/acf-sdk/sidecar/internal/crypto"
	"github.com/acf-sdk/sidecar/internal/transport"
	"github.com/acf-sdk/sidecar/pkg/decision"
)

// harnessKeyHex is the HMAC key the harness hands the sidecar via ACF_HMAC_KEY
// and signs its own requests with. Test-only, not a secret.
const harnessKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	socketPath string
	signer     *crypto.Signer
)

type corpus struct {
	Payloads []payloadCase `json:"payloads"`
}

type payloadCase struct {
	ID         string          `json:"id"`
	HookType   string          `json:"hook_type"`
	Category   string          `json:"category"`
	Provenance string          `json:"provenance"`
	Payload    json.RawMessage `json:"payload"`
	Expected   string          `json:"expected"`
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

// run builds and starts a real sidecar against a temp socket and config, then
// runs the suite. It returns the exit code so deferred cleanup still fires.
func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "acf-harness")
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness: tempdir:", err)
		return 1
	}
	defer os.RemoveAll(dir)

	socketPath = filepath.Join(dir, "acf.sock")

	root, err := filepath.Abs("../..")
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness: abs root:", err)
		return 1
	}

	keyBytes, _ := hex.DecodeString(harnessKeyHex)
	signer, err = crypto.NewSigner(keyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness: signer:", err)
		return 1
	}

	cfgPath := filepath.Join(dir, "sidecar.yaml")
	cfg := harnessConfig(socketPath, filepath.Join(root, "policies", "v1"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "harness: write config:", err)
		return 1
	}

	bin := filepath.Join(dir, "sidecar")
	build := exec.Command("go", "build", "-o", bin, "./cmd/sidecar")
	build.Dir = filepath.Join(root, "sidecar")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness: build sidecar:", err)
		return 1
	}

	var logs bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "ACF_HMAC_KEY="+harnessKeyHex, "ACF_CONFIG="+cfgPath)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "harness: start sidecar:", err)
		return 1
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	if !waitForSocket(socketPath, 10*time.Second) {
		fmt.Fprintln(os.Stderr, "harness: sidecar did not come up. logs:\n"+logs.String())
		return 1
	}

	return m.Run()
}

func waitForSocket(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", path); err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// send fires one payload at the sidecar and returns the decision name.
func send(t *testing.T, pc payloadCase) string {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"score":      0.0,
		"signals":    []any{},
		"provenance": pc.Provenance,
		"session_id": "",
		"hook_type":  pc.HookType,
		"payload":    pc.Payload,
		"state":      nil,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	frame, err := transport.EncodeRequest(body, signer)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial sidecar: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	resp, err := transport.DecodeResponse(conn)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decisionName(resp.Decision)
}

func decisionName(b byte) string {
	switch b {
	case decision.Allow:
		return "ALLOW"
	case decision.Sanitise:
		return "SANITISE"
	case decision.Block:
		return "BLOCK"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", b)
	}
}

func loadCorpus(t *testing.T) []payloadCase {
	t.Helper()
	raw, err := os.ReadFile("adversarial_payloads.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Payloads) == 0 {
		t.Fatal("corpus is empty")
	}
	return c.Payloads
}

func TestAdversarialPayloads(t *testing.T) {
	for _, pc := range loadCorpus(t) {
		pc := pc
		t.Run(pc.ID, func(t *testing.T) {
			got := send(t, pc)
			if got != pc.Expected {
				t.Errorf("[%s/%s] expected %s, got %s", pc.HookType, pc.Category, pc.Expected, got)
			}
		})
	}
}

// TestCoverageMatrix prints how many payloads hit each hook and verdict.
// Reporting only, it asserts nothing.
func TestCoverageMatrix(t *testing.T) {
	logCoverage(t, loadCorpus(t))
}

// logCoverage prints the hook/verdict counts and the categories the corpus hits.
func logCoverage(t *testing.T, all []payloadCase) {
	t.Helper()

	// Fixed hook order so an uncovered hook shows a zero row instead of vanishing.
	hooks := []string{"on_prompt", "on_context", "on_tool_call", "on_memory"}

	type cell struct{ hook, verdict string }
	counts := map[cell]int{}
	cats := map[string]bool{}
	for _, pc := range all {
		counts[cell{pc.HookType, pc.Expected}]++
		cats[pc.Category] = true
	}

	catList := make([]string, 0, len(cats))
	for c := range cats {
		catList = append(catList, c)
	}
	sort.Strings(catList)

	var b strings.Builder
	fmt.Fprintf(&b, "\nadversarial coverage: %d payloads across %d categories\n", len(all), len(cats))
	fmt.Fprintf(&b, "%-14s %6s %9s %6s\n", "hook", "ALLOW", "SANITISE", "BLOCK")
	for _, h := range hooks {
		fmt.Fprintf(&b, "%-14s %6d %9d %6d\n", h,
			counts[cell{h, "ALLOW"}], counts[cell{h, "SANITISE"}], counts[cell{h, "BLOCK"}])
	}
	fmt.Fprintf(&b, "categories: %s\n", strings.Join(catList, ", "))
	t.Log(b.String())
}

func harnessConfig(socket, policyDir string) string {
	return fmt.Sprintf(`socket_path: %q
policy_dir: %q
log_level: warn
pipeline:
  strict_mode: true
thresholds:
  block_score: 0.85
  sanitise_score: 0.50
trust_weights:
  user: 1.0
  user_input: 1.0
  tool_output: 0.8
  rag: 0.7
  rag_chunk: 0.7
  memory: 0.6
  memory_read: 0.6
tool_allowlist: []
memory_key_allowlist: []
signal_weights:
  jailbreak_pattern: 0.9
  instruction_override: 0.85
  role_escalation: 0.8
  shell_metachar: 0.75
  path_traversal: 0.75
  embedded_instruction: 0.65
  structural_anomaly: 0.40
  hmac_invalid: 1.0
  tool:not_allowed: 0.9
  memory:key_not_allowed: 0.7
  validate:invalid_hook_type: 1.0
  validate:missing_provenance: 0.9
  validate:nil_payload: 1.0
`, socket, policyDir)
}
