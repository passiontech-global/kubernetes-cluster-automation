// phase1_fixes_test.go — regression coverage for iterative wide-chain eval
// (no stack overflow on deep flat chains) and allocation budgets in filterZip / filterMap.
package jinja

import (
	"strings"
	"testing"
)

func TestWideFlatChainsEvalIteratively(t *testing.T) {
	// 10,000-term flat chains stay in O(1) Go stack space without crashing.
	wideAdd := "{{ 1" + strings.Repeat(" + 1", 10000) + " }}"
	out, err := Render(wideAdd, nil, nil)
	if err != nil || out != "10001" {
		t.Fatalf("wide flat add got (%q, %v), want (\"10001\", nil)", out, err)
	}
	wideFilter := "{{ ' x '" + strings.Repeat(" | trim", 10000) + " }}"
	out, err = Render(wideFilter, nil, nil)
	if err != nil || out != "x" {
		t.Fatalf("wide flat filter got (%q, %v), want (\"x\", nil)", out, err)
	}
	wideAttr := "{{ x" + strings.Repeat(".a", 10000) + " | default('none') }}"
	out, err = Render(wideAttr, map[string]any{"x": map[string]any{}}, nil)
	if err != nil || out != "none" {
		t.Fatalf("wide flat attr got (%q, %v), want (\"none\", nil)", out, err)
	}
	// Exceeding exprMaxChain fails cleanly at parse time.
	over := "{{ 1" + strings.Repeat(" + 1", exprMaxChain+1) + " }}"
	if _, err := Render(over, nil, nil); err == nil {
		t.Fatal("expected parse error for chain exceeding exprMaxChain")
	}
}

func TestFilterZipAndMapBudgets(t *testing.T) {
	big := make([]any, 50000)
	for i := range big {
		big[i] = "x"
	}
	args := make([]any, 24)
	for i := range args {
		args[i] = big
	}
	if _, err := filterZip(big, args); err == nil {
		t.Fatal("expected zip element-cap error, got nil")
	}

	chunk := strings.Repeat("a", 1<<20) // 1 MiB
	items := make([]any, 20)            // 20 MiB > 16 MiB maxStringBytes
	for i := range items {
		items[i] = chunk
	}
	if _, err := Render(`{{ items | map('upper') }}`, map[string]any{"items": items}, nil); err == nil {
		t.Fatal("expected map output-byte cap error, got nil")
	}
}

func TestShortCircuitPrecedenceAndFilterEdges(t *testing.T) {
	// Mixed and/or/arithmetic/comparison short-circuiting and precedence
	// must be identical under iterative left-spine evaluation.
	cases := []struct {
		tpl  string
		want string
	}{
		{"{{ true or (1 / 0) }}", "True"},
		{"{{ false and (1 / 0) or 'ok' }}", "ok"},
		{"{{ true or (1 / 0) and (2 / 0) }}", "True"},
		{"{{ 0 and (1 / 0) }}", "0"},
		{"{{ (false or true) and 42 }}", "42"},
		{"{{ 1 + 2 * 3 == 7 and 'a' ~ 'b' == 'ab' }}", "True"},
		{"{{ 1 in [1, 2] and false or true }}", "True"},
		{"{{ [] | zip | length }}", "0"},
		{"{{ [1, 2] | zip([]) | length }}", "0"},
		{"{{ [] | map('upper') | length }}", "0"},
		{"{{ [1, 2] | map('int') | join(',') }}", "1,2"},
	}
	for _, tc := range cases {
		out, err := Render(tc.tpl, nil, nil)
		if err != nil || out != tc.want {
			t.Fatalf("Render(%q) = (%q, %v), want (%q, nil)", tc.tpl, out, err, tc.want)
		}
	}
	if _, err := Render("{{ (1 / 0) and false }}", nil, nil); err == nil {
		t.Fatal("expected division by zero error on LHS of and")
	}
	if _, err := Render("{{ false or (1 % 0) }}", nil, nil); err == nil {
		t.Fatal("expected modulo by zero error on RHS of or")
	}
}
