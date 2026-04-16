// Package policy wraps the OPA Go SDK for policy evaluation, sanitisation
// execution, and result assembly.
//
// engine.go — OPA engine.
// Loads the Rego bundle from the policies directory at startup.
// Watches for file changes and hot-reloads without restarting.
// Queries the policy matching the RiskContext.HookType field.
// Returns a structured decision (ALLOW / SANITISE / BLOCK) with sanitise_targets.
package policy

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"gopkg.in/yaml.v3"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// OPAResult is the structured output of a single OPA evaluation.
type OPAResult struct {
	// Decision is "ALLOW", "SANITISE", or "BLOCK".
	Decision string
	// SanitiseTargets lists the payload segments OPA wants transformed.
	SanitiseTargets []string
}

// preparedQueries holds one compiled query per hook type.
// Swapped atomically on hot reload.
type preparedQueries struct {
	onPrompt   rego.PreparedEvalQuery
	onContext  rego.PreparedEvalQuery
	onToolCall rego.PreparedEvalQuery
	onMemory   rego.PreparedEvalQuery
}

// Engine is a thread-safe OPA policy evaluator with hot reload support.
type Engine struct {
	policyDir string
	mu        sync.RWMutex
	queries   *preparedQueries
	stopCh    chan struct{}
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

// Evaluate runs the OPA policy for rc.HookType and returns the decision and
// sanitise_targets declared by Rego. Returns ("ALLOW", nil, nil) if no rule
// fires. Returns an error if the hook type is unknown or OPA evaluation fails.
//
// This method satisfies the pipeline.Evaluator interface:
//
//	Evaluate(rc) (decision string, sanitiseTargets []string, err error)
func (e *Engine) Evaluate(rc *riskcontext.RiskContext) (string, []string, error) {
	input := buildInput(rc)

	e.mu.RLock()
	q := e.queries
	e.mu.RUnlock()

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

// Stop shuts down the hot-reload goroutine.
func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
}

// reload compiles all Rego policies and atomically swaps the prepared queries.
func (e *Engine) reload() error {
	ctx := context.Background()

	// 1. Load data.config from policy_config.yaml.
	store, err := loadDataStore(e.policyDir)
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
		opts := append(modules, rego.Query("data."+pkg), rego.Store(store))
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

	// 4. Atomically swap in the new compiled queries.
	e.mu.Lock()
	e.queries = &preparedQueries{
		onPrompt:   onPrompt,
		onContext:  onContext,
		onToolCall: onToolCall,
		onMemory:   onMemory,
	}
	e.mu.Unlock()

	return nil
}

// watchLoop polls the policy directory every 5 seconds and reloads on change.
// Uses modification-time comparison — no fsnotify dependency (Windows safe).
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

// loadDataStore reads policy_config.yaml and builds an OPA in-memory store
// with the parsed config available as data.config inside Rego rules.
func loadDataStore(policyDir string) (storage.Store, error) {
	configPath := filepath.Join(policyDir, "data", "policy_config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Non-fatal: OPA runs without data.config (allowlists etc. are empty).
		log.Printf("policy.Engine: cannot read policy_config.yaml: %v (data.config will be empty)", err)
		return inmem.New(), nil
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("policy.Engine: cannot parse policy_config.yaml: %w", err)
	}

	store := inmem.NewFromObject(map[string]any{"config": parsed})
	return store, nil
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
		// Skip test files — they define test rules that conflict with evaluation.
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
