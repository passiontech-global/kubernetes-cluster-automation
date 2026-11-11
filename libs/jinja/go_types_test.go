package jinja

import (
	"math"
	"strings"
	"testing"
)

// Context-fed plain Go values (int, uint, maps) must behave like the
// engine's native int64/OMap — they used to fall through every
// numeric/mapping branch.
func TestGoNativeTypes(t *testing.T) {
	ctx := map[string]any{
		"i":    int(41),
		"i32":  int32(-7),
		"u":    uint(9),
		"u64":  uint64(math.MaxInt64),
		"m":    map[string]any{"b": int64(2), "a": "x"},
		"ms":   map[string]string{"k": "v"},
		"big":  int64(9007199254740993), // 2^53 + 1 — float64 can't tell it from 2^53
		"big2": int64(9007199254740992),
	}
	cases := map[string]string{
		`{{ i + 1 }}`:                     "42",
		`{{ i32 }}`:                       "-7",
		`{{ u * 2 }}`:                     "18",
		`{{ u64 }}`:                       "9223372036854775807",
		`{{ m.a }}`:                       "x",
		`{{ m['b'] + 1 }}`:                "3",
		`{{ ms.k }}`:                      "v",
		`{{ ms['k'] }}`:                   "v",
		`{{ m | length }}`:                "2",
		`{{ ms | length }}`:               "1",
		`{{ m is mapping }}`:              "True",
		`{{ ms is mapping }}`:             "True",
		`{{ m is iterable }}`:             "True",
		`{{ m | list | sort }}`:           "[a, b]",
		`{{ m | dict2items | list }}`:     "[{'key': a, 'value': x}, {'key': b, 'value': 2}]",
		`{{ i is number }}`:               "True",
		`{{ i | int }}`:                   "41",
		`{{ i | float }}`:                 "41",
		`{{ -i32 }}`:                      "7",
		`{{ big == big2 }}`:               "False", // exact past 2^53
		`{{ big > big2 }}`:                "True",
		`{{ big < big2 }}`:                "False",
		`{{ [big, big2] | min }}`:         "9007199254740992",
		`{{ [big, big2] | max }}`:         "9007199254740993",
		`{{ big == '9007199254740993' }}`: "True", // numeric string still coerces
	}
	for tpl, want := range cases {
		got, err := renderBounded(t, tpl, ctx)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// NaN/±Inf must never compare as 0.0 — toFloat rejects them and the
// ordering ops fall back to deterministic string order.
func TestNonFiniteComparisons(t *testing.T) {
	ctx := map[string]any{
		"nan":  math.NaN(),
		"inf":  math.Inf(1),
		"ninf": math.Inf(-1),
	}
	cases := map[string]string{
		`{{ nan < 5 }}`:      "False", // was True (NaN→0.0)
		`{{ nan > 5 }}`:      "False",
		`{{ 5 < nan }}`:      "False",
		`{{ nan == nan }}`:   "False",
		`{{ nan <= nan }}`:   "False",
		`{{ nan | int(9) }}`: "9",
		`{{ nan | float }}`:  "0",
		`{{ nan | string }}`: "NaN",
	}
	for tpl, want := range cases {
		got, err := renderBounded(t, tpl, ctx)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// ~ binds looser than +/-: the additive operand groups first.
func TestConcatPrecedence(t *testing.T) {
	cases := map[string]string{
		`{{ "node-" ~ 1 + 2 }}`: "node-3",
		`{{ 1 + 2 ~ "-x" }}`:    "3-x",
		`{{ "a" ~ "b" ~ "c" }}`: "abc",
		`{{ "n" ~ 2 * 3 }}`:     "n6",
	}
	for tpl, want := range cases {
		got, err := renderBounded(t, tpl, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// Leading-zero integer literals are decimal, not octal/rejected;
// 0x/0o/0b prefixes keep base-0 semantics.
func TestLeadingZeroNumbers(t *testing.T) {
	cases := map[string]string{
		`{{ 08 }}`:      "8",
		`{{ 09 }}`:      "9",
		`{{ 010 }}`:     "10",
		`{{ 010 + 1 }}`: "11",
		`{{ 0x10 }}`:    "16",
		`{{ 0X1f }}`:    "31",
		`{{ 0o17 }}`:    "15",
		`{{ 0b11 }}`:    "3",
	}
	for tpl, want := range cases {
		got, err := renderBounded(t, tpl, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// YAML !!int with leading zeros falls back to base-10; every !!null
// spelling decodes to nil, not the literal string.
func TestYAMLScalarEdgeCases(t *testing.T) {
	// "08"/"09" are digits-only → int64; "010" stays YAML-1.1 octal (8).
	v, err := DecodeYAML([]byte("a: 08\nb: 09\nc: 010\nd: 1.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	om, ok := v.(*OMap)
	if !ok {
		t.Fatalf("DecodeYAML = %T, want *OMap", v)
	}
	for k, want := range map[string]any{"a": int64(8), "b": int64(9), "c": int64(8), "d": 1.5} {
		got, _ := om.Get(k)
		if got != want {
			t.Fatalf("yaml %s = %#v (%T) want %#v", k, got, got, want)
		}
	}

	v, err = DecodeYAML([]byte("a: Null\nb: NULL\nc: ~\nd:\n"))
	if err != nil {
		t.Fatal(err)
	}
	om = v.(*OMap)
	for _, k := range []string{"a", "b", "c", "d"} {
		got, _ := om.Get(k)
		if got != nil {
			t.Fatalf("yaml %s = %#v want nil", k, got)
		}
	}
}

// for-unpack on a mapping errors for ANY arity > 1 (previously only
// == 2 was caught up-front; >= 3 leaked a confusing item error).
func TestForUnpackMappingArity(t *testing.T) {
	ctx := map[string]any{"m": map[string]any{"a": 1, "b": 2}}
	for _, tpl := range []string{
		`{% for k, v in m %}x{% endfor %}`,
		`{% for a, b, c in m %}x{% endfor %}`,
	} {
		if _, err := Render(tpl, ctx, nil); err == nil {
			t.Fatalf("render %q succeeded — want unpack error", tpl)
		} else if !strings.Contains(err.Error(), "unpack") {
			t.Fatalf("render %q error = %v, want unpack error", tpl, err)
		}
	}
}

// |format width/precision are capped — an absurd spec must not make
// fmt.Sprintf allocate unboundedly.
func TestFormatSpecClamped(t *testing.T) {
	got, err := renderBounded(t, `{{ "%999999999s" | format("x") | length }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10000" {
		t.Fatalf("format width clamp = %q want 10000", got)
	}
	got, err = renderBounded(t, `{{ "%.999999999f" | format(1.5) }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// "1." + up to 10000 fraction digits
	if len(got) < 9000 {
		t.Fatalf("format precision clamp len = %d, want ~10001", len(got))
	}
}
