package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/acf-sdk/sidecar/internal/config"
)

// TestEngine_LoadsSignalWeightsFromPolicyConfig checks the weights come from
// policy_config.yaml, including categories that were dead before the move and
// the validate:* entries that used to live only in sidecar.yaml.
func TestEngine_LoadsSignalWeightsFromPolicyConfig(t *testing.T) {
	weights := newTestEngine(t).SignalWeights()
	for category, want := range map[string]float64{
		"jailbreak_pattern":       0.9,
		"memory_poisoning":        0.85, // scored 0.0 while the sidecar read sidecar.yaml
		"tool_boundary_violation": 0.8,  // scored 0.0 while the sidecar read sidecar.yaml
		"validate:nil_payload":    1.0,  // moved over from sidecar.yaml
	} {
		if got, ok := weights[category]; !ok || got != want {
			t.Errorf("weight[%q] = %v (present=%v), want %v", category, got, ok, want)
		}
	}
}

// TestPolicyConfig_EveryEmittableSignalHasAWeight fails when the sidecar can
// emit a signal category that policy_config.yaml does not weight. Such a signal
// scores 0.0 and can never change a verdict. This is how 11 of the semantic
// scanner's 13 categories went dead without anyone noticing.
//
// Categories come from the lexical pattern library and from every Category
// literal in the sidecar's non-test source, so a new emitter is covered without
// editing this test. The SDK scanner's categories are checked by the Python
// contract test, sdk/python/tests/test_signal_weight_contract.py.
func TestPolicyConfig_EveryEmittableSignalHasAWeight(t *testing.T) {
	weights := newTestEngine(t).SignalWeights()
	emitters := map[string]string{} // category → where it comes from

	patterns, err := config.LoadPatterns(policyDir(t))
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	for _, e := range patterns.Entries {
		if e.Category != "" {
			emitters[e.Category] = "jailbreak_patterns.json"
		}
	}

	literal := regexp.MustCompile(`Category:\s*"([^"]+)"`)
	internal := filepath.Join(policyDir(t), "..", "..", "sidecar", "internal")
	err = filepath.WalkDir(internal, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range literal.FindAllStringSubmatch(string(src), -1) {
			emitters[m[1]] = filepath.Base(path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning sidecar source: %v", err)
	}
	if len(emitters) == 0 {
		t.Fatal("found no emitted categories: the source scan is broken")
	}

	var missing []string
	for category, source := range emitters {
		if _, ok := weights[category]; !ok {
			missing = append(missing, category+" (from "+source+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("signal categories with no weight in policy_config.yaml; each scores 0.0:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

func TestEngine_AuditCategoriesIncludeWeightsAndRegoCategories(t *testing.T) {
	eng := newTestEngine(t)
	for _, category := range []string{
		"jailbreak_pattern",
		"content_scan",
		"low_trust_source",
		"obfuscation_escalation",
		"parameter_injection",
		"policy_integrity",
		"source_trust",
	} {
		if !eng.SignalCategoryAllowed(category) {
			t.Errorf("audit category %q is not approved", category)
		}
	}
	for _, category := range []string{"attacker-controlled", "attacker-controlled\nlog text"} {
		if eng.SignalCategoryAllowed(category) {
			t.Errorf("unknown category %q is approved for audit output", category)
		}
	}
}

func TestLoadPolicyData_RejectsMissingOrBadWeights(t *testing.T) {
	cases := map[string]string{
		"no signal_weights":    "thresholds:\n  block_score: 0.85\n",
		"empty signal_weights": "signal_weights: {}\n",
		"non-numeric weight":   "signal_weights:\n  jailbreak_pattern: high\n",
		"weight above 1":       "signal_weights:\n  jailbreak_pattern: 1.5\n",
		"negative weight":      "signal_weights:\n  jailbreak_pattern: -0.1\n",
		"NaN weight":           "signal_weights:\n  jailbreak_pattern: .nan\n",
		"positive infinity":    "signal_weights:\n  jailbreak_pattern: .inf\n",
		"negative infinity":    "signal_weights:\n  jailbreak_pattern: -.inf\n",
		"blank category":       "signal_weights:\n  \"   \": 0.5\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePolicyConfig(t, dir, body)
			if _, _, _, err := loadPolicyData(dir); err == nil {
				t.Errorf("loadPolicyData accepted a config with %s", name)
			}
		})
	}
}

func TestLoadPolicyData_RejectsMalformedAuditSignalCategories(t *testing.T) {
	cases := map[string]string{
		"scalar":        "audit_signal_categories: source_trust\n",
		"mapping":       "audit_signal_categories:\n  source_trust: true\n",
		"null value":    "audit_signal_categories: null\n",
		"empty entry":   "audit_signal_categories:\n  - \"\"\n",
		"blank entry":   "audit_signal_categories:\n  - \"   \"\n",
		"integer entry": "audit_signal_categories:\n  - 1\n",
		"boolean entry": "audit_signal_categories:\n  - false\n",
	}
	for name, suffix := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyPolicyDir(t)
			rewriteAuditSignalCategories(t, dir, suffix)
			if _, _, _, err := loadPolicyData(dir); err == nil {
				t.Errorf("loadPolicyData accepted malformed audit_signal_categories: %s", name)
			} else if !strings.Contains(err.Error(), "audit_signal_categories") {
				t.Fatalf("loadPolicyData rejected %s before audit parsing: %v", name, err)
			}
		})
	}
}

// A missing policy_config.yaml used to be tolerated with empty data. Now that it
// holds the weights, tolerating it would score every signal 0.0 and ALLOW
// everything, so it must fail closed.
func TestLoadPolicyData_MissingFileFailsClosed(t *testing.T) {
	if _, _, _, err := loadPolicyData(t.TempDir()); err == nil {
		t.Error("a missing policy_config.yaml must fail the load, not fall back to no weights")
	}
}

func TestLoadPolicyData_AcceptsIntegerWeights(t *testing.T) {
	dir := copyPolicyDir(t)
	rewritePolicyConfig(t, dir, "hmac_invalid: 1.0", "hmac_invalid: 1")
	rewritePolicyConfig(t, dir, "structural_anomaly: 0.40", "structural_anomaly: 0")
	_, weights, _, err := loadPolicyData(dir)
	if err != nil {
		t.Fatalf("loadPolicyData: %v", err)
	}
	if weights["hmac_invalid"] != 1 || weights["structural_anomaly"] != 0 {
		t.Errorf("integer weights not parsed as numbers: %v", weights)
	}
}

func TestLoadPolicyData_RejectsIncompleteWeightTable(t *testing.T) {
	dir := copyPolicyDir(t)
	removePolicyWeight(t, dir, "system_prompt_extraction: 0.8")
	if _, _, _, err := loadPolicyData(dir); err == nil {
		t.Fatal("loadPolicyData accepted a table that cannot score the current signal contract")
	} else if !strings.Contains(err.Error(), "system_prompt_extraction") {
		t.Fatalf("incomplete table error = %v, want missing category", err)
	}
}

func TestEngine_SnapshotBindsThresholdsTrustAndAuditCategories(t *testing.T) {
	dir := copyPolicyDir(t)
	eng, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(eng.Stop)

	before := eng.Snapshot()
	if got := before.Thresholds(); got.BlockScore != 0.85 || got.SanitiseScore != 0.50 {
		t.Fatalf("initial thresholds = %+v, want policy values", got)
	}
	if got := before.ProvenanceWeight("user"); got != 1.0 {
		t.Fatalf("initial user trust weight = %v, want 1.0", got)
	}
	if !before.SignalCategoryAllowed("content_scan") {
		t.Fatal("initial audit category content_scan is not approved")
	}

	rewritePolicyConfig(t, dir, "block_score: 0.85", "block_score: 0.95")
	rewritePolicyConfig(t, dir, "user: 1.0", "user: 0.4")
	if err := eng.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after := eng.Snapshot()
	if after == before {
		t.Fatal("successful reload reused the previous snapshot")
	}
	if got := after.Thresholds(); got.BlockScore != 0.95 || got.SanitiseScore != 0.50 {
		t.Fatalf("reloaded thresholds = %+v, want policy values", got)
	}
	if got := after.ProvenanceWeight("user"); got != 0.4 {
		t.Fatalf("reloaded user trust weight = %v, want 0.4", got)
	}
	if !after.SignalCategoryAllowed("content_scan") {
		t.Fatal("reloaded audit category content_scan is not approved")
	}
}

// TestEngine_ReloadPicksUpWeightChanges covers hot reload: the reason weights
// belong in policy_config.yaml is that they then change without a restart.
func TestEngine_ReloadPicksUpWeightChanges(t *testing.T) {
	dir := copyPolicyDir(t)
	eng, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(eng.Stop)
	if got := eng.SignalWeights()["memory_poisoning"]; got != 0.85 {
		t.Fatalf("initial memory_poisoning weight = %v, want 0.85", got)
	}

	rewritePolicyConfig(t, dir, "memory_poisoning: 0.85", "memory_poisoning: 0.6")
	if err := eng.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := eng.SignalWeights()["memory_poisoning"]; got != 0.6 {
		t.Errorf("memory_poisoning weight after reload = %v, want 0.6", got)
	}
}

// TestEngine_ReloadKeepsWeightsOnBadConfig guards a running sidecar: a broken
// edit to policy_config.yaml must not wipe its weights and start ALLOWing.
func TestEngine_ReloadKeepsWeightsOnBadConfig(t *testing.T) {
	dir := copyPolicyDir(t)
	eng, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(eng.Stop)
	before := eng.Snapshot()
	beforeWeights := eng.SignalWeights()

	writePolicyConfig(t, dir, "signal_weights: {}\n")
	if err := eng.reload(); err == nil {
		t.Fatal("reload accepted a policy_config.yaml with no signal weights")
	}
	if after := eng.Snapshot(); after != before {
		t.Fatal("rejected reload replaced the active policy snapshot")
	}
	if got := eng.SignalWeights(); len(got) != len(beforeWeights) || got["jailbreak_pattern"] != beforeWeights["jailbreak_pattern"] {
		t.Errorf("weights changed after a rejected reload: %v, want %v", got, beforeWeights)
	}
}

func writePolicyConfig(t *testing.T, dir, body string) {
	t.Helper()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "policy_config.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rewritePolicyConfig(t *testing.T, dir, old, new string) {
	t.Helper()
	path := filepath.Join(dir, "data", "policy_config.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(src), old, new, 1)
	if updated == string(src) {
		t.Fatalf("policy_config.yaml no longer contains %q", old)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

func removePolicyWeight(t *testing.T, dir, line string) {
	t.Helper()
	path := filepath.Join(dir, "data", "policy_config.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(src), "\n  "+line, "", 1)
	if updated == string(src) {
		t.Fatalf("policy_config.yaml no longer contains weight %q", line)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rewriteAuditSignalCategories(t *testing.T, dir, replacement string) {
	t.Helper()
	path := filepath.Join(dir, "data", "policy_config.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	idx := strings.Index(text, "\naudit_signal_categories:")
	if idx < 0 {
		t.Fatal("policy_config.yaml has no audit_signal_categories section")
	}
	updated := text[:idx+1] + replacement
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

// copyPolicyDir copies the real policies/v1 tree (Rego plus data/) into a temp
// directory the test is free to modify.
func copyPolicyDir(t *testing.T) string {
	t.Helper()
	src, dst := policyDir(t), t.TempDir()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying policy dir: %v", err)
	}
	return dst
}
