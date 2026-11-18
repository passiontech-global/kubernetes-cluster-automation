// phase_d_polish_test.go — Phase-D leaf polish contracts: the static
// YAML elision leaf at the depth cap (no emitter round-trip per
// branch), the |to_yaml output cap, and the end-of-buffer |format
// cap for all-literal formats that never reach the in-loop check.
package jinja

import (
	"strings"
	"testing"

	yaml3 "go.yaml.in/yaml/v3"
)

// A deep (non-branching) value crosses the depth cap once — the
// elision leaf must be built directly, not by round-tripping a
// scalar through yaml's Encode/Parse (which is what made the
// branching-cycle case multi-second under -race).
func TestYAMLElisionLeafIsStaticNode(t *testing.T) {
	steps := 0
	n, err := yamlValueAt("payload", walkMaxDepth+1, &steps)
	if err != nil {
		t.Fatal(err)
	}
	if n.Kind != yaml3.ScalarNode || n.Tag != "!!str" ||
		n.Value != "[...]" || n.Style != 0 {
		t.Fatalf("elision leaf = {kind:%v tag:%q value:%q style:%v}, want static !!str [...] node",
			n.Kind, n.Tag, n.Value, n.Style)
	}
	if steps != 1 {
		t.Fatalf("elision walk burned %d steps, want 1", steps)
	}
}

// The |to_yaml output cap is checked on the marshaled bytes — the
// walk can stay inside its step budget while the document grows
// past maxStringBytes. Exercise the cap branch directly: building
// a 16 MiB YAML document under -race takes >10s, which would make
// an end-to-end test a suite bottleneck.
func TestToYAMLOutputCap(t *testing.T) {
	if err := outputSizeCap(maxStringBytes+1, "to_yaml"); err == nil ||
		!strings.Contains(err.Error(), "to_yaml: output exceeds") {
		t.Fatalf("oversized output: err = %v, want output-exceeds error", err)
	}
	if err := outputSizeCap(maxStringBytes, "to_yaml"); err != nil {
		t.Fatalf("at-cap output rejected: %v", err)
	}
}

// The in-loop |format cap runs only AFTER a % conversion: an
// all-literal format writes every byte through the `continue` path
// and would otherwise return unbounded output. The final check at
// the end of pyFormat closes that gap.
func TestFormatLiteralOnlyOutputCap(t *testing.T) {
	if _, err := pyFormat(strings.Repeat("x", maxStringBytes+1), nil); err == nil {
		t.Fatal("all-literal format over cap succeeded — end-of-buffer check missing")
	}
}
