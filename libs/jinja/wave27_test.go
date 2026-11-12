// wave27_test.go — regressions for the v4 audit fixes: flatten's
// typed-nil *List, quoted "<<" YAML keys, from_json's explicit
// depth error, |sort int64 precision + stability, OMap.Set on a
// zero value, and deepEq's typed-nil list boxing.
package jinja

import (
	"math"
	"strings"
	"testing"
)

// |flatten must treat a typed-nil *List as an EMPTY list — appending
// it as an atom produced [nil] where python/jinja2 yields [].
func TestFlattenTypedNilList(t *testing.T) {
	out, err := renderBounded(t, `{{ l | flatten }}`,
		map[string]any{"l": []any{(*List)(nil), int64(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if out != "[1]" {
		t.Fatalf("flatten typed-nil = %q want [1]", out)
	}
}

// A QUOTED "<<" YAML key is a plain string key, not a merge — only
// an unquoted scalar tagged !!merge (or bare <<) merges.
func TestYAMLQuotedMergeKeyIsLiteral(t *testing.T) {
	v, err := DecodeYAML([]byte("\"<<\": merged-value\nplain: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(*OMap)
	if !ok {
		t.Fatalf("DecodeYAML = %T want *OMap", v)
	}
	got, found := m.Get("<<")
	if !found || got != "merged-value" {
		t.Fatalf("quoted << key = %v (found=%v) want literal 'merged-value'", got, found)
	}
	if _, found := m.Get("merged-value"); found {
		t.Fatal("quoted << must not splice a merge")
	}
}

// |from_json must ERROR on nesting deeper than fromJSONMaxDepth —
// silently truncating to nil hid malformed input. N nested arrays
// reach depth N-1 inside fromJSONAt, so the cap trips at
// fromJSONMaxDepth+2 opens.
func TestFromJSONDepthLimitErrors(t *testing.T) {
	deep := strings.Repeat("[", fromJSONMaxDepth+2) +
		strings.Repeat("]", fromJSONMaxDepth+2)
	if _, err := renderBounded(t, `{{ j | from_json }}`,
		map[string]any{"j": deep}); err == nil {
		t.Fatal("over-depth from_json must error, not nil-truncate")
	}
	// One level inside the cap still parses.
	atCap := strings.Repeat("[", fromJSONMaxDepth+1) +
		strings.Repeat("]", fromJSONMaxDepth+1)
	if _, err := renderBounded(t, `{{ j | from_json | length }}`,
		map[string]any{"j": atCap}); err != nil {
		t.Fatalf("at-depth-cap from_json errored: %v", err)
	}
}

// |sort must compare int64 exactly past 2^53 — float64 keys would
// tie 9007199254740992 and 9007199254740993 — and equal finite
// numbers must compare 0 so SortStableFunc keeps input order.
func TestSortInt64PrecisionAndStability(t *testing.T) {
	out, err := renderBounded(t, `{{ l | sort }}`, map[string]any{
		"l": []any{int64(9007199254740993), int64(9007199254740992)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "[9007199254740992, 9007199254740993]" {
		t.Fatalf("int64 sort = %q want exact order past 2^53", out)
	}
	// Comparator-level pins (rendering can't distinguish 1 vs 1.0):
	cmp := func(a, b any) int {
		return sortKeyCompare(newSortKey(a), newSortKey(b))
	}
	if c := cmp(int64(9007199254740993), int64(9007199254740992)); c <= 0 {
		t.Fatalf("int64 past 2^53 compared %d, want >0", c)
	}
	// An integral float64 in int64 range resolves to the same exact
	// comparison — 9007199254740993 > 9007199254740992.0.
	if c := cmp(int64(9007199254740993), 9007199254740992.0); c <= 0 {
		t.Fatalf("int64 vs integral float compared %d, want >0", c)
	}
	// Numerically equal FINITE values are equal keys (0) — stable
	// sort keeps input order like python's sorted().
	if c := cmp(int64(1), 1.0); c != 0 {
		t.Fatalf("1 vs 1.0 compared %d, want 0", c)
	}
	// NaN/±Inf share the sentinel num but are NOT equal — the str
	// half must still order them.
	if c := cmp(math.NaN(), math.Inf(1)); c == 0 {
		t.Fatal("NaN vs +Inf compared 0, want distinct")
	}
}

// (&OMap{}).Set must lazy-init the backing map — a zero OMap used
// to panic on first write.
func TestOMapSetZeroValue(t *testing.T) {
	var m OMap
	m.Set("k", "v")
	if got, _ := m.Get("k"); got != "v" {
		t.Fatalf("zero OMap Set/Get = %v want v", got)
	}
}

// deepEq: a typed-nil *List boxes to []any(nil) — equal to an empty
// list literal, never equal to None (python parity with *OMap).
func TestDeepEqTypedNilList(t *testing.T) {
	if !deepEq((*List)(nil), []any(nil)) {
		t.Fatal("(*List)(nil) must equal []any(nil)")
	}
	if deepEq((*List)(nil), nil) {
		t.Fatal("(*List)(nil) must NOT equal untyped nil (None)")
	}
}
