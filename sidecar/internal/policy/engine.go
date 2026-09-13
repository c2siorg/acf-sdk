// Package policy wraps the OPA Go SDK for policy evaluation, sanitisation
// execution, and result assembly.
//
// engine.go: OPA engine.
// Loads the Rego bundle from the policies directory at startup.
// Watches for file changes and hot-reloads without restarting.
// Serves signal_weights from policy_config.yaml to the aggregate stage.
// Queries the policy matching the RiskContext.HookType field.
// Returns a structured decision (ALLOW / SANITISE / BLOCK) with sanitise_targets.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"gopkg.in/yaml.v3"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// OPAResult is the structured output of a single OPA evaluation.
type OPAResult struct {
	// Decision is "ALLOW", "SANITISE", or "BLOCK".
	Decision string
	// SanitiseTargets lists the payload segments OPA wants transformed.
	SanitiseTargets []string
}

// preparedQueries holds a compiled query per hook type.
// Swapped atomically on hot reload.
type preparedQueries struct {
	onPrompt   rego.PreparedEvalQuery
	onContext  rego.PreparedEvalQuery
	onToolCall rego.PreparedEvalQuery
	onMemory   rego.PreparedEvalQuery
}

// Snapshot is 1 immutable, successfully loaded policy generation. Its
// prepared queries and policy data are never changed after construction.
type Snapshot struct {
	queries         *preparedQueries
	weights         map[string]float64
	thresholds      config.ThresholdConfig
	trustWeights    map[string]float64
	auditCategories map[string]struct{}
}

// SnapshotProvider exposes the generation that a request should use.
type SnapshotProvider interface {
	Snapshot() *Snapshot
}

type loadedPolicy struct {
	store           storage.Store
	weights         map[string]float64
	thresholds      config.ThresholdConfig
	trustWeights    map[string]float64
	auditCategories map[string]struct{}
}

// Engine is a thread-safe OPA policy evaluator with hot reload support.
type Engine struct {
	policyDir  string
	generation atomic.Pointer[Snapshot]
	stopCh     chan struct{}
}

// NewEngine constructs an Engine that loads Rego policies from policyDir.
// It compiles all policies once at startup and starts a background goroutine
// that polls for file changes every 5 seconds and hot-reloads as needed.
func NewEngine(policyDir string) (*Engine, error) {
	e := &Engine{
		policyDir: policyDir,
		stopCh:    make(chan struct{}),
	}
	if err := e.reload(); err != nil {
		return nil, fmt.Errorf("policy.Engine: initial load failed: %w", err)
	}
	go e.watchLoop()
	return e, nil
}

// Snapshot returns the most recent successful policy generation.
func (e *Engine) Snapshot() *Snapshot {
	return e.generation.Load()
}

// Evaluate runs the OPA policy for rc.HookType using 1 policy generation and
// returns the decision and sanitise_targets declared by Rego. Returns
// ("ALLOW", nil, nil) if no rule fires. Returns an error if the hook type is
// unknown or OPA evaluation fails.
//
// This method satisfies the pipeline.Evaluator interface:
//
//	Evaluate(rc) (decision string, sanitiseTargets []string, err error)
func (e *Engine) Evaluate(rc *riskcontext.RiskContext) (string, []string, error) {
	return e.Snapshot().Evaluate(rc)
}

// Evaluate runs the OPA policy using this immutable policy generation.
func (s *Snapshot) Evaluate(rc *riskcontext.RiskContext) (string, []string, error) {
	input := buildInput(rc)
	q := s.queries

	ctx := context.Background()

	var rs rego.ResultSet
	var err error

	switch rc.HookType {
	case "on_prompt":
		rs, err = q.onPrompt.Eval(ctx, rego.EvalInput(input))
	case "on_context":
		rs, err = q.onContext.Eval(ctx, rego.EvalInput(input))
	case "on_tool_call":
		rs, err = q.onToolCall.Eval(ctx, rego.EvalInput(input))
	case "on_memory":
		rs, err = q.onMemory.Eval(ctx, rego.EvalInput(input))
	default:
		return "BLOCK", nil, fmt.Errorf("policy.Engine: unknown hook_type %q", rc.HookType)
	}

	if err != nil {
		return "", nil, fmt.Errorf("policy.Engine: OPA evaluation error: %w", err)
	}

	result := extractResult(rs)
	return result.Decision, result.SanitiseTargets, nil
}

// Snapshot returns itself so a snapshot can be used wherever a provider is
// accepted by the pipeline.
func (s *Snapshot) Snapshot() *Snapshot { return s }

// Stop shuts down the hot-reload goroutine.
func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
}

// Reload synchronously loads and activates a new policy generation. A failed
// reload leaves the current generation active.
func (e *Engine) Reload() error {
	return e.reload()
}

// SignalWeights returns a copy of the signal weights from this policy
// generation. The snapshot keeps its internal map private and immutable.
func (s *Snapshot) SignalWeights() map[string]float64 {
	return cloneWeights(s.weights)
}

// SignalWeights returns a copy of the signal weights from the most recent
// successful load of policy_config.yaml.
func (e *Engine) SignalWeights() map[string]float64 {
	return e.Snapshot().SignalWeights()
}

// SignalCategoryAllowed reports whether category is approved for audit output
// by this policy generation.
func (s *Snapshot) SignalCategoryAllowed(category string) bool {
	_, ok := s.auditCategories[category]
	return ok
}

// SignalCategoryAllowed reports whether category is approved for audit output
// by the most recent successful policy generation.
func (e *Engine) SignalCategoryAllowed(category string) bool {
	return e.Snapshot().SignalCategoryAllowed(category)
}

// Thresholds returns the score thresholds bound to this policy generation.
func (s *Snapshot) Thresholds() config.ThresholdConfig {
	return s.thresholds
}

// Thresholds returns the score thresholds from the most recent successful
// policy generation.
func (e *Engine) Thresholds() config.ThresholdConfig {
	return e.Snapshot().Thresholds()
}

// ProvenanceWeight returns the trust multiplier bound to this policy
// generation, defaulting to 1.0 for an unknown provenance label.
func (s *Snapshot) ProvenanceWeight(provenance string) float64 {
	if weight, ok := s.trustWeights[provenance]; ok {
		return weight
	}
	return 1.0
}

// ProvenanceWeight returns the trust multiplier from the most recent
// successful policy generation.
func (e *Engine) ProvenanceWeight(provenance string) float64 {
	return e.Snapshot().ProvenanceWeight(provenance)
}

// reload compiles all Rego policies and atomically swaps the complete policy
// generation only after every component has loaded successfully.
func (e *Engine) reload() error {
	ctx := context.Background()

	// 1. Load data.config and the signal weights from policy_config.yaml.
	loaded, err := loadPolicyGeneration(e.policyDir)
	if err != nil {
		return err
	}

	// 2. Read all .rego files from policyDir (excluding test files).
	modules, err := loadModules(e.policyDir)
	if err != nil {
		return err
	}
	if len(modules) == 0 {
		return fmt.Errorf("policy.Engine: no .rego files found in %s", e.policyDir)
	}

	// 3. Compile a PreparedEvalQuery for each hook type.
	compile := func(pkg string) (rego.PreparedEvalQuery, error) {
		opts := append([]func(*rego.Rego){}, modules...)
		opts = append(opts, rego.Query("data."+pkg), rego.Store(loaded.store))
		return rego.New(opts...).PrepareForEval(ctx)
	}

	onPrompt, err := compile("acf.policy.prompt")
	if err != nil {
		return fmt.Errorf("policy.Engine: compile prompt: %w", err)
	}
	onContext, err := compile("acf.policy.context")
	if err != nil {
		return fmt.Errorf("policy.Engine: compile context: %w", err)
	}
	onToolCall, err := compile("acf.policy.tool")
	if err != nil {
		return fmt.Errorf("policy.Engine: compile tool: %w", err)
	}
	onMemory, err := compile("acf.policy.memory")
	if err != nil {
		return fmt.Errorf("policy.Engine: compile memory: %w", err)
	}

	// 4. Atomically swap 1 immutable generation so an in-flight request can
	// retain its old queries, weights, thresholds, trust weights, and audit
	// categories after a reload.
	e.generation.Store(&Snapshot{
		queries: &preparedQueries{
			onPrompt:   onPrompt,
			onContext:  onContext,
			onToolCall: onToolCall,
			onMemory:   onMemory,
		},
		weights:         loaded.weights,
		thresholds:      loaded.thresholds,
		trustWeights:    loaded.trustWeights,
		auditCategories: loaded.auditCategories,
	})

	return nil
}

// watchLoop polls the policy directory every 5 seconds and reloads on change.
// Uses modification-time comparison; no fsnotify dependency (Windows safe).
func (e *Engine) watchLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastMod := e.latestMod()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			if mod := e.latestMod(); mod.After(lastMod) {
				lastMod = mod
				if err := e.reload(); err != nil {
					log.Printf("policy.Engine: hot-reload failed: %v (keeping previous policies)", err)
				} else {
					log.Printf("policy.Engine: policies reloaded from %s", e.policyDir)
				}
			}
		}
	}
}

// latestMod returns the most recent modification time of any file in policyDir.
func (e *Engine) latestMod() time.Time {
	var latest time.Time
	_ = filepath.WalkDir(e.policyDir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

// loadPolicyData reads policy_config.yaml and prepares all policy-generation
// data. Weighted categories are always included in the audit allowlist.
//
// The file is required. Without it there are no signal weights: every signal
// would score 0.0 and every request would be ALLOWed. So a missing or
// weightless policy_config.yaml fails the load instead of failing open. At
// startup the sidecar refuses to run, and on hot reload the previous policies
// stay live.
func loadPolicyGeneration(policyDir string) (*loadedPolicy, error) {
	configPath := filepath.Join(policyDir, "data", "policy_config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: cannot read %s: %w", configPath, err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("policy.Engine: cannot parse policy_config.yaml: %w", err)
	}

	weights, err := parseSignalWeights(parsed["signal_weights"])
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
	}
	if err := validateSignalWeightCoverage(policyDir, weights); err != nil {
		return nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
	}
	thresholds, err := parsePolicyThresholds(parsed)
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
	}
	trustWeights, err := parsePolicyTrustWeights(parsed)
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
	}
	auditCategories := weightedAuditCategories(weights)
	if raw, ok := parsed["audit_signal_categories"]; ok {
		auditCategories, err = parseAuditSignalCategories(raw, weights)
		if err != nil {
			return nil, fmt.Errorf("policy.Engine: %s: %w", configPath, err)
		}
	}

	store := inmem.NewFromObject(map[string]any{"config": parsed})
	return &loadedPolicy{
		store:           store,
		weights:         weights,
		thresholds:      thresholds,
		trustWeights:    trustWeights,
		auditCategories: auditCategories,
	}, nil
}

// loadPolicyData preserves the data-loading helper used by older package
// tests and embedders while the engine itself consumes the complete snapshot
// data above.
func loadPolicyData(policyDir string) (storage.Store, map[string]float64, map[string]struct{}, error) {
	loaded, err := loadPolicyGeneration(policyDir)
	if err != nil {
		return nil, nil, nil, err
	}
	return loaded.store, loaded.weights, loaded.auditCategories, nil
}

var sidecarSignalCategories = []string{
	"hmac_invalid",
	"validate:invalid_hook_type",
	"validate:missing_provenance",
	"validate:nil_payload",
	"jailbreak_pattern",
	"tool:not_allowed",
	"shell_metacharacter",
	"path_traversal",
	"memory:key_not_allowed",
}

// These are the canonical categories emitted by the Python semantic scanner's
// hardcoded contract. Categories loaded from the shared lexical library are
// added below, so a policy update cannot silently disable either detector.
var pythonSemanticSignalCategories = []string{
	"instruction_override",
	"context_manipulation",
	"data_exfiltration",
	"tool_boundary_violation",
	"role_escalation",
	"encoding_bypass",
}

func validateSignalWeightCoverage(policyDir string, weights map[string]float64) error {
	required, err := requiredSignalCategories(policyDir)
	if err != nil {
		return err
	}

	var missing []string
	for category := range required {
		if _, ok := weights[category]; !ok {
			missing = append(missing, category)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("signal_weights is missing categories: %s", strings.Join(missing, ", "))
}

func requiredSignalCategories(policyDir string) (map[string]struct{}, error) {
	required := make(map[string]struct{}, len(sidecarSignalCategories)+len(pythonSemanticSignalCategories))
	for _, category := range sidecarSignalCategories {
		required[category] = struct{}{}
	}
	for _, category := range pythonSemanticSignalCategories {
		required[category] = struct{}{}
	}

	patterns, err := config.LoadPatterns(policyDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return required, nil
		}
		return nil, fmt.Errorf("cannot load lexical signal categories: %w", err)
	}
	for _, entry := range patterns.Entries {
		category := entry.Category
		if category == "" {
			category = "jailbreak_pattern"
		}
		required[category] = struct{}{}
	}
	return required, nil
}

func weightedAuditCategories(weights map[string]float64) map[string]struct{} {
	categories := make(map[string]struct{}, len(weights))
	for category := range weights {
		categories[category] = struct{}{}
	}
	return categories
}

func parseAuditSignalCategories(raw any, weights map[string]float64) (map[string]struct{}, error) {
	if raw == nil {
		return nil, errors.New("audit_signal_categories must be a list")
	}

	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("audit_signal_categories must be a list")
	}
	categories := weightedAuditCategories(weights)
	for i, item := range items {
		category, ok := item.(string)
		if !ok || strings.TrimSpace(category) == "" {
			return nil, fmt.Errorf("audit_signal_categories[%d] must be a non-empty string", i)
		}
		categories[category] = struct{}{}
	}
	return categories, nil
}

// parseSignalWeights validates the signal_weights table: a non-empty map from
// signal category to a weight in [0.0, 1.0].
func parseSignalWeights(raw any) (map[string]float64, error) {
	table, ok := raw.(map[string]any)
	if !ok || len(table) == 0 {
		return nil, errors.New("signal_weights is missing or empty")
	}
	weights := make(map[string]float64, len(table))
	for category, v := range table {
		if strings.TrimSpace(category) == "" {
			return nil, errors.New("signal_weights contains a blank category name")
		}
		w, ok := finiteNumber(v)
		if !ok {
			return nil, fmt.Errorf("signal_weights.%s: %v is not a number", category, v)
		}
		if w < 0 || w > 1 {
			return nil, fmt.Errorf("signal_weights.%s: %v is outside [0.0, 1.0]", category, w)
		}
		weights[category] = w
	}
	return weights, nil
}

func parsePolicyThresholds(parsed map[string]any) (config.ThresholdConfig, error) {
	thresholds := config.ThresholdConfig{BlockScore: 0.85, SanitiseScore: 0.50}
	raw, ok := parsed["thresholds"]
	if !ok {
		return thresholds, nil
	}
	table, ok := raw.(map[string]any)
	if !ok || table == nil {
		return thresholds, errors.New("thresholds must be a map")
	}
	if value, exists := table["block_score"]; exists {
		parsedValue, ok := finiteNumber(value)
		if !ok || parsedValue < 0 || parsedValue > 1 {
			return thresholds, errors.New("thresholds.block_score must be finite and between 0.0 and 1.0")
		}
		thresholds.BlockScore = parsedValue
	}
	if value, exists := table["sanitise_score"]; exists {
		parsedValue, ok := finiteNumber(value)
		if !ok || parsedValue < 0 || parsedValue > 1 {
			return thresholds, errors.New("thresholds.sanitise_score must be finite and between 0.0 and 1.0")
		}
		thresholds.SanitiseScore = parsedValue
	}
	if thresholds.SanitiseScore > thresholds.BlockScore {
		return thresholds, errors.New("thresholds.sanitise_score must be <= thresholds.block_score")
	}
	return thresholds, nil
}

func parsePolicyTrustWeights(parsed map[string]any) (map[string]float64, error) {
	raw, ok := parsed["trust_weights"]
	if !ok {
		return map[string]float64{}, nil
	}
	table, ok := raw.(map[string]any)
	if !ok || table == nil {
		return nil, errors.New("trust_weights must be a map")
	}
	weights := make(map[string]float64, len(table))
	for provenance, value := range table {
		if strings.TrimSpace(provenance) == "" {
			return nil, errors.New("trust_weights contains a blank provenance name")
		}
		weight, ok := finiteNumber(value)
		if !ok || weight < 0 || weight > 1 {
			return nil, fmt.Errorf("trust_weights.%s must be finite and between 0.0 and 1.0", provenance)
		}
		weights[provenance] = weight
	}
	return weights, nil
}

func finiteNumber(value any) (float64, bool) {
	var number float64
	switch n := value.(type) {
	case float64:
		number = n
	case float32:
		number = float64(n)
	case int:
		number = float64(n)
	case int64:
		number = float64(n)
	case uint:
		number = float64(n)
	case uint64:
		number = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

func cloneWeights(weights map[string]float64) map[string]float64 {
	clone := make(map[string]float64, len(weights))
	for category, weight := range weights {
		clone[category] = weight
	}
	return clone
}

// loadModules reads all .rego files (excluding _test.rego) from policyDir
// and returns them as rego.Module functional options.
func loadModules(policyDir string) ([]func(*rego.Rego), error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, fmt.Errorf("policy.Engine: cannot read policy dir %s: %w", policyDir, err)
	}

	var opts []func(*rego.Rego)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".rego" {
			continue
		}
		// Skip test files: they define test rules that conflict with evaluation.
		if len(name) > 9 && name[len(name)-9:] == "_test.rego" {
			continue
		}
		path := filepath.Join(policyDir, name)
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("policy.Engine: cannot read %s: %w", path, err)
		}
		opts = append(opts, rego.Module(name, string(contents)))
	}
	return opts, nil
}

// buildInput constructs the OPA input document from a RiskContext.
// Common fields are always present; hook-specific fields are added per hook type.
func buildInput(rc *riskcontext.RiskContext) map[string]any {
	// Convert []Signal to []map[string]any for OPA.
	signals := make([]map[string]any, len(rc.Signals))
	for i, s := range rc.Signals {
		signals[i] = map[string]any{
			"category": s.Category,
			"score":    s.Score,
		}
	}

	input := map[string]any{
		"score":      rc.Score,
		"signals":    signals,
		"hook_type":  rc.HookType,
		"provenance": rc.Provenance,
		"session_id": rc.SessionID,
	}

	// Hook-specific fields extracted from rc.Payload.
	switch rc.HookType {
	case "on_tool_call":
		if m, ok := rc.Payload.(map[string]any); ok {
			input["tool_name"] = m["name"]
			if meta, ok := m["metadata"]; ok {
				input["tool_metadata"] = meta
			} else {
				input["tool_metadata"] = map[string]any{}
			}
		}
	case "on_context":
		if m, ok := rc.Payload.(map[string]any); ok {
			if s, ok := m["content"].(string); ok {
				input["payload_size_bytes"] = len([]byte(s))
			}
			if trust, ok := m["source_trust"]; ok {
				input["source_trust"] = trust
			}
		}
	case "on_memory":
		if m, ok := rc.Payload.(map[string]any); ok {
			input["memory_op"] = m["op"]
			if v, ok := m["value"].(string); ok {
				input["payload_size_bytes"] = len([]byte(v))
			}
			input["integrity"] = map[string]any{
				"hmac_valid": m["hmac_valid"],
			}
		}
	}

	return input
}

// extractResult parses an OPA ResultSet into an OPAResult.
// Returns ALLOW with no targets if the result set is empty (no rule fired).
func extractResult(rs rego.ResultSet) OPAResult {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return OPAResult{Decision: "ALLOW"}
	}

	obj, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return OPAResult{Decision: "ALLOW"}
	}

	decision, _ := obj["decision"].(string)
	if decision == "" {
		decision = "ALLOW"
	}

	var targets []string
	// OPA returns Rego set values as []interface{} via the Go SDK.
	if set, ok := obj["sanitise_targets"].([]any); ok {
		for _, t := range set {
			if s, ok := t.(string); ok {
				targets = append(targets, s)
			}
		}
	}

	return OPAResult{Decision: decision, SanitiseTargets: targets}
}
