// omap_test.go — the typed getters on *OMap (Str/Bool/BoolDef/Int/
// Slice/StrMap), the single home for the per-app omStr/omBool/omList
// accessor families. Table-driven over the coercions that matter:
// missing keys, wrong types, nested *OMap values, nil receivers.
package jinja

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func getterFixture() *OMap {
	m := NewOMap()
	m.Set("s", "txt")
	m.Set("empty", "")
	m.Set("i", int64(42))
	m.Set("f", 2.5)
	m.Set("fint", float64(3))
	m.Set("bt", true)
	m.Set("bf", false)
	m.Set("nilv", nil)
	m.Set("list", []any{"a"})
	m.Set("jlist", &List{V: []any{"p", "q"}})
	m.Set("numstr", "12")
	m.Set("badnum", "0x1f")
	m.Set("sub", func() *OMap {
		sm := NewOMap()
		sm.Set("host", "node-a")
		sm.Set("port", int64(22))
		sm.Set("flag", false)
		return sm
	}())
	m.Set("subnil", (*OMap)(nil))
	m.Set("subwrong", "not-a-map")
	return m
}

func TestOMapStr(t *testing.T) {
	m := getterFixture()
	cases := []struct{ key, want string }{
		{"s", "txt"},
		{"i", "42"},
		{"f", "2.5"},
		{"fint", "3"}, // integral floats print without a .0 tail
		{"bt", "true"},
		{"bf", ""},
		{"empty", ""},
		{"nilv", ""},
		{"missing", ""},
		{"list", ""}, // containers never stringify their repr
		{"jlist", ""},
		{"sub", ""},
		{"numstr", "12"},
		{"badnum", "0x1f"}, // Str is verbatim for strings, not ToInt'd
	}
	for _, c := range cases {
		if got := m.Str(c.key); got != c.want {
			t.Errorf("Str(%q) = %q want %q", c.key, got, c.want)
		}
	}
	var nilMap *OMap
	if got := nilMap.Str("x"); got != "" {
		t.Fatalf("nil receiver Str = %q want empty", got)
	}
}

func TestOMapBool(t *testing.T) {
	m := getterFixture()
	m.Set("i_is_zero", int64(0))
	m.Set("empty_list", []any{})
	// Truthy semantics (jinja): any non-empty string is true.
	if !m.Bool("bt") || !m.Bool("s") || !m.Bool("list") {
		t.Fatalf("Bool: truthy values must read true")
	}
	for _, k := range []string{"bf", "empty", "i_is_zero", "nilv", "missing", "empty_list"} {
		if m.Bool(k) {
			t.Errorf("Bool(%q) = true want false", k)
		}
	}
	var nilMap *OMap
	if nilMap.Bool("x") {
		t.Fatalf("nil receiver Bool = true want false")
	}
}

func TestOMapBoolDef(t *testing.T) {
	m := getterFixture()
	// Ansible/YAML scalar spellings — quoted YAML `True` decodes as a
	// string, so the string forms are the ones that matter.
	truthy := []any{true, "true", "TRUE", "Yes", " on ", "1", int64(2), int64(-1), 1.5}
	for _, v := range truthy {
		m.Set("k", v)
		if !m.BoolDef("k", false) {
			t.Errorf("BoolDef(%v) = false want true", v)
		}
	}
	falsy := []any{false, "false", "No", "0", "OFF", int64(0), float64(0)}
	for _, v := range falsy {
		m.Set("k", v)
		if m.BoolDef("k", true) {
			t.Errorf("BoolDef(%v) = true want false", v)
		}
	}
	// Unrecognized scalar (incl. the empty string), wrong type, and
	// missing key all → def — the hubsync omBool contract.
	m.Set("garbage", "maybe")
	m.Set("blank", "")
	m.Set("nilv2", nil)
	if !m.BoolDef("garbage", true) || m.BoolDef("garbage", false) {
		t.Fatalf("unrecognized string must return def verbatim")
	}
	if !m.BoolDef("blank", true) || !m.BoolDef("nilv2", true) {
		t.Fatalf("empty string and nil must return def, got def-else")
	}
	if !m.BoolDef("list", true) {
		t.Fatalf("container value must fall back to def")
	}
	if m.BoolDef("missing", true) != true || m.BoolDef("missing", false) != false {
		t.Fatalf("BoolDef(missing) must return def verbatim")
	}
	var nilMap *OMap
	if !nilMap.BoolDef("x", true) {
		t.Fatalf("nil receiver BoolDef = false want def(true)")
	}
}

func TestOMapInt(t *testing.T) {
	m := getterFixture()
	cases := []struct {
		key  string
		want int64
	}{
		{"i", 42},
		{"numstr", 12},
		{"badnum", 0}, // base-10 only: "0x1f" is not parseable
		{"f", 2},      // floats truncate, like |int
		{"bt", 1},
		{"bf", 0},
		{"nilv", 0},
		{"missing", 0},
		{"s", 0}, // non-numeric string
	}
	for _, c := range cases {
		if got := m.Int(c.key); got != c.want {
			t.Errorf("Int(%q) = %d want %d", c.key, got, c.want)
		}
	}
	// Contexts feed plain Go ints (asInt64 path).
	m.Set("plain", 7)
	if got := m.Int("plain"); got != 7 {
		t.Fatalf("Int(plain int) = %d want 7", got)
	}
	var nilMap *OMap
	if got := nilMap.Int("x"); got != 0 {
		t.Fatalf("nil receiver Int = %d want 0", got)
	}
}

func TestOMapSlice(t *testing.T) {
	m := getterFixture()
	if got := m.Slice("list"); !reflect.DeepEqual(got, []any{"a"}) {
		t.Fatalf("Slice(list) = %v", got)
	}
	// *List unwraps to the same backing array (live, like Keys).
	jl := m.Slice("jlist")
	if !reflect.DeepEqual(jl, []any{"p", "q"}) {
		t.Fatalf("Slice(jlist) = %v", jl)
	}
	jl[0] = "zz"
	got, _ := m.Get("jlist")
	if !reflect.DeepEqual(got.(*List).V, []any{"zz", "q"}) {
		t.Fatalf("Slice must share the stored *List backing array")
	}
	for _, k := range []string{"s", "i", "nilv", "missing", "sub"} {
		if got := m.Slice(k); got != nil {
			t.Errorf("Slice(%q) = %v want nil", k, got)
		}
	}
	var nilMap *OMap
	if got := nilMap.Slice("x"); got != nil {
		t.Fatalf("nil receiver Slice = %v want nil", got)
	}
}

// scalarStr's non-OMap-typed inputs: a stored Undefined must read
// like a missing key (never its String() repr), a Go []string
// coerces element-wise, and map shapes without a faithful scalar
// form drop to "" instead of fmt.Sprint reprs.
func TestOMapStrScalarStrEdges(t *testing.T) {
	m := NewOMap()
	m.Set("und", NewUndefined("und_key"))
	m.Set("goslice", []string{"a", "b"})
	m.Set("gointlist", []int64{1, 2})
	m.Set("gointmap", map[string]int{"a": 1})
	m.Set("gostrmap", map[string]string{"a": "x"})
	m.Set("emptylist", []string{})
	cases := map[string]string{
		"und":       "",    // Undefined ≠ Undefined(und_key)
		"goslice":   "a,b", // element-wise, ',' joined
		"gointlist": "1,2",
		"gointmap":  "", // no faithful scalar form → ""
		"gostrmap":  "", // string maps stay containers
		"emptylist": "",
	}
	for k, want := range cases {
		if got := m.Str(k); got != want {
			t.Errorf("Str(%q) = %q want %q", k, got, want)
		}
	}
	// StrMap flattening routes through the same coercion.
	sub := NewOMap()
	sub.Set("u", NewUndefined("x"))
	sub.Set("l", []string{"p", "q"})
	m.Set("sub", sub)
	want := map[string]string{"u": "", "l": "p,q"}
	if got := m.StrMap("sub"); !reflect.DeepEqual(got, want) {
		t.Fatalf("StrMap(sub) = %v want %v", got, want)
	}
}

func TestOMapStrMap(t *testing.T) {
	m := getterFixture()
	want := map[string]string{"host": "node-a", "port": "22", "flag": ""}
	if got := m.StrMap("sub"); !reflect.DeepEqual(got, want) {
		t.Fatalf("StrMap(sub) = %v want %v", got, want)
	}
	// Missing key, wrong type, and typed-nil sub-map all give an
	// empty non-nil map — lookup-safe without a nil check.
	for _, k := range []string{"missing", "subwrong", "subnil", "list"} {
		got := m.StrMap(k)
		if got == nil || len(got) != 0 {
			t.Errorf("StrMap(%q) = %v want empty non-nil", k, got)
		}
	}
	var nilMap *OMap
	if got := nilMap.StrMap("x"); got == nil || len(got) != 0 {
		t.Fatalf("nil receiver StrMap = %v want empty non-nil", got)
	}
}

func TestOMapBoolDefNumericAndHardening(t *testing.T) {
	m := NewOMapCap(8)
	m.Set("int0", int(0))
	m.Set("int1", int(-3))
	m.Set("u0", uint64(0))
	m.Set("u1", uint64(7))
	m.Set("nan", math.NaN())
	m.Set("f0", float64(0))
	m.Set("f1", float64(1.5))

	if m.BoolDef("int0", true) || !m.BoolDef("int1", false) {
		t.Fatalf("BoolDef int mismatch")
	}
	if m.BoolDef("u0", true) || !m.BoolDef("u1", false) {
		t.Fatalf("BoolDef uint64 mismatch")
	}
	if m.BoolDef("nan", true) || m.BoolDef("f0", true) || !m.BoolDef("f1", false) {
		t.Fatalf("BoolDef float/NaN mismatch")
	}

	// from_yaml payload size limit (parseMaxBytes = 4 MiB)
	bigYAML := "a: " + strings.Repeat("x", parseMaxBytes+1)
	if _, err := Render("{{ s | from_yaml }}", map[string]any{"s": bigYAML}, nil); err == nil {
		t.Fatal("from_yaml > parseMaxBytes succeeded, want error")
	}

	// Negative int64 < -2^53 sort exactness
	gotSort, err := Render("{{ xs | sort | join(',') }}", map[string]any{
		"xs": []any{int64(-(1 << 53) - 1), int64(-(1 << 53) - 3), int64(-(1 << 53) - 2)},
	}, nil)
	if err != nil {
		t.Fatalf("negative int64 sort error: %v", err)
	}
	if wantSort := "-9007199254740995,-9007199254740994,-9007199254740993"; gotSort != wantSort {
		t.Fatalf("negative int64 sort = %q, want %q", gotSort, wantSort)
	}

	// Uppercase 0B binary literal
	gotBin, err := Render("{{ 0B1010 }}", nil, nil)
	if err != nil {
		t.Fatalf("0B1010 render error: %v", err)
	}
	if gotBin != "10" {
		t.Fatalf("0B1010 = %q, want 10", gotBin)
	}
}
