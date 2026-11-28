// wave4_caps_test.go — regression coverage for the Wave-4 hardening
// caps: exponential concat growth, oversized join separators, and
// the range→unique worst case must all terminate inside the budgets
// instead of hanging or OOMing the render. renderBounded (shared
// with audit_fixes_test.go) turns a hang regression into a deadline
// failure.
package jinja

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exponential string growth: each ~ doubles the payload. The
// maxStringBytes/maxSeqElems caps must cut the loop long before the
// result approaches memory exhaustion — the render errors instead
// of hanging or producing an unbounded string. renderBounded turns
// a hang regression into a deadline failure.
func TestConcatDoublingBounded(t *testing.T) {
	// Both templates must hit a hard budget (maxStringBytes /
	// maxSeqElems) and return an error — a silent truncation or a
	// short-but-valid render would mean the cap is not wired.
	for _, tpl := range []string{
		`{% set s = 'x' %}{% for i in range(64) %}{% set s = s ~ s %}{% endfor %}{{ s | length }}`,
		`{% set l = [1] %}{% for i in range(24) %}{% set l = l + l %}{% endfor %}{{ l | length }}`,
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("concat doubling completed without budget error\ntpl: %s", tpl)
		}
	}
}

// A huge join separator is one giant string allocation — capped by
// maxStringBytes, so the render errors instead of allocating
// unboundedly.
func TestJoinHugeSeparatorBounded(t *testing.T) {
	sep := strings.Repeat("s", maxStringBytes+1)
	_, err := renderBounded(t,
		`{{ ['a','b','c'] | join(sep) }}`,
		map[string]any{"sep": sep})
	if err == nil {
		t.Fatal("join with >maxStringBytes separator succeeded — cap missing")
	}
}

// range(200000) | unique exercises the all-ints fast path at scale:
// the dedup must stay O(N) and the render must finish quickly even
// though the naive quadratic path would take minutes.
func TestRangeUniqueLargeBounded(t *testing.T) {
	start := time.Now()
	out, err := renderBounded(t,
		`{{ range(200000) | unique | length }}`, nil)
	if err != nil {
		t.Fatalf("range|unique errored: %v", err)
	}
	if out != "200000" {
		t.Fatalf("range(200000)|unique|length = %q, want 200000", out)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("range|unique took %v — quadratic dedup regression?", elapsed)
	}
}

func TestRegexFastPathsSemanticsAndCaps(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
		ctx  map[string]any
		want string
	}{
		{"line_prefix_no_match", `{{ s | regex_replace('(?m)^zzz', 'X') }}`, map[string]any{"s": "a\nb\n"}, "a\nb\n"},
		{"line_prefix_matches", `{{ s | regex_replace('(?m)^a', 'X') }}`, map[string]any{"s": "\na\nba\na"}, "\nX\nba\nX"},
		{"line_prefix_crlf", `{{ s | regex_replace('(?m)^a', 'X') }}`, map[string]any{"s": "a\r\na\r\n"}, "X\r\nX\r\n"},
		{"empty_pat_with_expand", `{{ 'ab' | regex_replace('', '$$') }}`, nil, "$a$b$"},
		{"findall_batch_seam_empty", `{{ s | regex_findall('a*') | length }}`, map[string]any{"s": strings.Repeat("b", 5000)}, "5001"},
		{"findall_batch_capture_opt", `{{ s | regex_findall('(a)(b)?') | length }}`, map[string]any{"s": strings.Repeat("a", 5000)}, "5000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderBounded(t, tc.tpl, tc.ctx)
			if err != nil {
				t.Fatalf("render failed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("line_prefix_output_cap", func(t *testing.T) {
		s := strings.Repeat("a\n", 1024)
		repl := strings.Repeat("b", 32768)
		if _, err := renderBounded(t, `{{ s | regex_replace('(?m)^a', r) | length }}`, map[string]any{"s": s, "r": repl}); err == nil {
			t.Fatal("expected line-prefix regex_replace output cap error")
		}
	})

	t.Run("findall_non_literal_batch_cap", func(t *testing.T) {
		s := strings.Repeat("a", maxSeqElems+1)
		for _, pat := range []string{`[ab]`, `([ab])`} {
			tpl := `{{ s | regex_findall('` + pat + `') | length }}`
			if _, err := renderBounded(t, tpl, map[string]any{"s": s}); err == nil {
				t.Fatalf("expected regex_findall(%q) > maxSeqElems to fail", pat)
			}
		}
	})
}

func TestIndentNewlineFloodBounded(t *testing.T) {
	// 16 MiB of '\n' with blank=true or blank=false must fail the output cap
	// without allocating a ~268 MiB []string slice from strings.Split.
	s := strings.Repeat("\n", maxStringBytes)
	for _, tpl := range []string{
		`{{ s | indent(4) | length }}`,
		`{{ s | indent(4, blank=true) | length }}`,
	} {
		if _, err := renderBounded(t, tpl, map[string]any{"s": s}); err == nil {
			t.Fatalf("expected indent cap error for %s", tpl)
		}
	}
	// Smaller newline-dense input that fits under maxStringBytes with blank=false
	// must still preserve blank-line skipping while failing when blank=true.
	dense := strings.Repeat("\n", maxStringBytes/2)
	got, err := renderBounded(t, `{{ s | indent(4) | length }}`, map[string]any{"s": dense})
	if err != nil {
		t.Fatalf("indent(4) blank=false failed: %v", err)
	}
	wantLen := strconv.Itoa(len(dense) + 4)
	if got != wantLen {
		t.Fatalf("indent(4) blank=false length = %q, want %s", got, wantLen)
	}
	if _, err := renderBounded(t, `{{ s | indent(4, blank=true) | length }}`, map[string]any{"s": dense}); err == nil {
		t.Fatal("expected indent(4, blank=true) on dense newlines to exceed maxStringBytes")
	}
}

func TestJoinSeparatorCapAndLargeCount(t *testing.T) {
	sep := strings.Repeat("s", maxStringBytes+1)
	if _, err := renderBounded(t, `{{ ['a','b'] | join(sep) }}`, map[string]any{"sep": sep}); err == nil {
		t.Fatal("expected join with >maxStringBytes separator to fail")
	}
	// Single-element join does not emit the separator.
	got, err := renderBounded(t, `{{ ['a'] | join(sep) }}`, map[string]any{"sep": sep})
	if err != nil {
		t.Fatalf("single-item join failed: %v", err)
	}
	if got != "a" {
		t.Fatalf("single-item join = %q, want %q", got, "a")
	}
	// Multiplication of (len(parts)-1)*len(sep) must fail cleanly without overflow.
	bigSep := strings.Repeat("x", 1024)
	if _, err := renderBounded(t, `{{ range(20000) | join(sep) | length }}`, map[string]any{"sep": bigSep}); err == nil {
		t.Fatal("expected join output > maxStringBytes to fail")
	}
}

func TestFormatLeftAlignSignedFlags(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{`{{ '%-+5d' | format(7) }}`, "+7   "},
		{`{{ '%-+5d' | format(-7) }}`, "-7   "},
		{`{{ '%- 5d' | format(7) }}`, " 7   "},
		{`{{ '%- 5d' | format(-7) }}`, "-7   "},
		{`{{ '%+-5d' | format(7) }}`, "+7   "},
		{`{{ '%-05d' | format(7) }}`, "7    "},
		{`{{ '%-5d' | format(7) }}`, "7    "},
		{`{{ '%+5d' | format(7) }}`, "   +7"},
		{`{{ '% 5d' | format(7) }}`, "    7"},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, nil)
		if err != nil {
			t.Fatalf("%s failed: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}
