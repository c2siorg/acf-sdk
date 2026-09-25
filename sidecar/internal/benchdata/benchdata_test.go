package benchdata

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerators_HitRequestedSize(t *testing.T) {
	for _, n := range Sizes {
		if got := len(BenignText(n)); got != n {
			t.Errorf("BenignText(%d) has %d bytes", n, got)
		}
		inj := InjectedText(n)
		if len(inj) != n || !strings.Contains(inj, Injection) {
			t.Errorf("InjectedText(%d): %d bytes, contains injection=%v", n, len(inj), strings.Contains(inj, Injection))
		}
		if got := len(Base64Tokens(n)); got != n {
			t.Errorf("Base64Tokens(%d) has %d bytes", n, got)
		}
		for _, depth := range []int{1, 3, 6} {
			if got := len(Base64Nested(n, depth)); got != n {
				t.Errorf("Base64Nested(%d, %d) has %d bytes", n, depth, got)
			}
		}
		if got := len(URLNested(n, 4)); got != n {
			t.Errorf("URLNested(%d, 4) has %d bytes", n, got)
		}
		if got := len(ZeroWidthDense(n)); got > n || got < n-3 {
			t.Errorf("ZeroWidthDense(%d) has %d bytes", n, got)
		}
	}
}

func TestCorpus_BodiesAreRiskContexts(t *testing.T) {
	cases, err := Corpus()
	if err != nil {
		t.Fatalf("Corpus: %v", err)
	}
	for _, c := range cases {
		var body map[string]any
		if err := json.Unmarshal(c.Body(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v", c.ID, err)
		}
		if body["hook_type"] != c.HookType || body["provenance"] != c.Provenance {
			t.Errorf("%s: body = %v", c.ID, body)
		}
	}
}

func TestSyntheticPatterns_DistinctAndDeterministic(t *testing.T) {
	a, b := SyntheticPatterns(1000, 7), SyntheticPatterns(1000, 7)
	seen := map[string]bool{}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("pattern %d differs between runs with the same seed", i)
		}
		if seen[a[i].Pattern] {
			t.Fatalf("pattern %q repeated", a[i].Pattern)
		}
		seen[a[i].Pattern] = true
	}
}
