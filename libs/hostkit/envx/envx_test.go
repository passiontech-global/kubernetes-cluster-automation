package envx

import (
	"slices"
	"testing"
	"time"
)

func TestString(t *testing.T) {
	const key = "ENVX_TEST_STRING"
	if got := String(key, "def"); got != "def" {
		t.Fatalf("unset: got %q want def", got)
	}
	t.Setenv(key, "")
	if got := String(key, "def"); got != "def" {
		t.Fatalf("empty: got %q want def", got)
	}
	t.Setenv(key, "value")
	if got := String(key, "def"); got != "value" {
		t.Fatalf("set: got %q want value", got)
	}
}

func TestBool(t *testing.T) {
	const key = "ENVX_TEST_BOOL"
	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Run("true/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if !Bool(key, false) {
				t.Fatalf("%q: got false want true", v)
			}
		})
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		t.Run("false/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if Bool(key, true) {
				t.Fatalf("%q: got true want false", v)
			}
		})
	}
	// Anything else — including case variants, whitespace, and other
	// numbers — falls to the default.
	for _, v := range []string{"", "TRUE", "True", " 1", "2", "-1", "maybe", "on "} {
		t.Run("def/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if !Bool(key, true) || Bool(key, false) {
				t.Fatalf("%q: want def on both defaults", v)
			}
		})
	}
}

func TestModeEnv(t *testing.T) {
	const key = "ENVX_TEST_MODE"
	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Run("on/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if got := ModeEnv(key, ModeAuto); got != ModeOn {
				t.Fatalf("%q: got %d want ModeOn", v, got)
			}
		})
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		t.Run("off/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if got := ModeEnv(key, ModeAuto); got != ModeOff {
				t.Fatalf("%q: got %d want ModeOff", v, got)
			}
		})
	}
	// "auto", unset, empty and unrecognised values all resolve to the
	// caller's default — ModeAuto included.
	for _, v := range []string{"auto", "", "TRUE", "2", "maybe", " on"} {
		t.Run("def/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if got := ModeEnv(key, ModeAuto); got != ModeAuto {
				t.Fatalf("%q: got %d want ModeAuto (def)", v, got)
			}
			if got := ModeEnv(key, ModeOn); got != ModeOn {
				t.Fatalf("%q: got %d want ModeOn (def)", v, got)
			}
			if got := ModeEnv(key, ModeOff); got != ModeOff {
				t.Fatalf("%q: got %d want ModeOff (def)", v, got)
			}
		})
	}
	// Fully unset env also yields def.
	if got := ModeEnv("ENVX_TEST_MODE_UNSET", ModeOff); got != ModeOff {
		t.Fatalf("unset: got %d want ModeOff", got)
	}
}

func TestInt(t *testing.T) {
	const key = "ENVX_TEST_INT"
	cases := []struct {
		name string
		set  bool
		val  string
		want int
	}{
		{"unset", false, "", 7},
		{"empty", true, "", 7},
		{"non-numeric", true, "abc", 7},
		{"whitespace", true, " 5", 7},
		{"zero", true, "0", 0},
		{"negative", true, "-42", -42},
		{"plus", true, "+9", 9},
		{"plain", true, "123", 123},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(key, c.val)
			}
			if got := Int(key, 7); got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

func TestInt64(t *testing.T) {
	const key = "ENVX_TEST_INT64"
	if got := Int64(key, 9); got != 9 {
		t.Fatalf("unset: got %d want 9", got)
	}
	t.Setenv(key, "9223372036854775807")
	if got := Int64(key, 9); got != 1<<63-1 {
		t.Fatalf("max: got %d", got)
	}
	t.Setenv(key, "not-a-number")
	if got := Int64(key, 9); got != 9 {
		t.Fatalf("invalid: got %d want 9", got)
	}
}

func TestOr(t *testing.T) {
	const key = "ENVX_TEST_OR"
	if got := Or(key, "conf"); got != "conf" {
		t.Fatalf("unset: got %q want conf", got)
	}
	t.Setenv(key, "")
	if got := Or(key, "conf"); got != "conf" {
		t.Fatalf("empty env: got %q want conf", got)
	}
	t.Setenv(key, "env")
	if got := Or(key, "conf"); got != "env" {
		t.Fatalf("env set: got %q want env", got)
	}
	// conf itself may be empty — the consumer's default applies.
	if got := Or(key, ""); got != "env" {
		t.Fatalf("env set, empty conf: got %q want env", got)
	}
	t.Setenv(key, "")
	if got := Or(key, ""); got != "" {
		t.Fatalf("both empty: got %q want empty", got)
	}
}

func TestStr(t *testing.T) {
	if got := Str("a", "b"); got != "a" {
		t.Fatalf("a non-empty: got %q want a", got)
	}
	if got := Str("", "b"); got != "b" {
		t.Fatalf("a empty: got %q want b", got)
	}
	if got := Str("", ""); got != "" {
		t.Fatalf("both empty: got %q want empty", got)
	}
}

func TestIntOr(t *testing.T) {
	const key = "ENVX_TEST_INT_OR"
	cases := []struct {
		name    string
		set     bool
		val     string
		confVal int
		def     int
		want    int
	}{
		{"env beats conf", true, "5", 3, 9, 5},
		{"env invalid yields def not conf", true, "abc", 3, 9, 9},
		{"unset conf wins", false, "", 3, 9, 3},
		{"empty env conf wins", true, "", 3, 9, 3},
		{"conf zero falls to def", false, "", 0, 9, 9},
		{"conf negative falls to def", false, "", -2, 9, 9},
		{"env and conf unset", false, "", 0, 9, 9},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(key, c.val)
			}
			if got := IntOr(key, c.confVal, c.def); got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

func TestInt64Or(t *testing.T) {
	const key = "ENVX_TEST_INT64_OR"
	t.Setenv(key, "42")
	if got := Int64Or(key, 3, 9); got != 42 {
		t.Fatalf("env set: got %d want 42", got)
	}
	t.Setenv(key, "bogus")
	if got := Int64Or(key, 3, 9); got != 9 {
		t.Fatalf("env invalid: got %d want 9 (def, not conf)", got)
	}
	t.Setenv(key, "")
	if got := Int64Or(key, 3, 9); got != 3 {
		t.Fatalf("env empty: got %d want 3 (conf)", got)
	}
	if got := Int64Or(key, 0, 9); got != 9 {
		t.Fatalf("conf zero: got %d want 9 (def)", got)
	}
}

func TestDuration(t *testing.T) {
	const key = "ENVX_TEST_DURATION"
	def := 10 * time.Second
	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{"unset", false, "", def},
		{"empty", true, "", def},
		{"go duration", true, "1h30m", 90 * time.Minute},
		{"seconds unit", true, "45s", 45 * time.Second},
		{"bare int is seconds", true, "45", 45 * time.Second},
		{"bare negative", true, "-5", def},
		{"negative duration", true, "-5s", def},
		{"zero", true, "0", def},
		{"zero duration", true, "0s", def},
		{"unparseable", true, "abc", def},
		{"bad unit", true, "5x", def},
		{"leading space", true, " 5s", def},
		{"fractional", true, "1.5h", 90 * time.Minute},
		// Bare-integer seconds past the int64-ns ceiling must not
		// wrap — 18446744074s overflows into a POSITIVE ~0.29s that
		// the <=0 check alone would let through.
		{"bare int wraps positive", true, "18446744074", def},
		{"bare int over max seconds", true, "9223372037", def},
		{"bare int under min seconds", true, "-9223372037", def},
		{"bare int at max seconds", true, "9223372036",
			time.Duration(9223372036) * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(key, c.val)
			}
			if got := Duration(key, def); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestDurOr(t *testing.T) {
	const key = "ENVX_TEST_DUR_OR"
	def := 10 * time.Second

	// env set and valid → parsed duration beats conf seconds.
	t.Setenv(key, "2m")
	if got := DurOr(key, 30, def); got != 2*time.Minute {
		t.Fatalf("env set: got %v want 2m", got)
	}
	// env set but unparseable → def, not confSeconds.
	t.Setenv(key, "bogus")
	if got := DurOr(key, 30, def); got != def {
		t.Fatalf("env invalid: got %v want def %v", got, def)
	}
	// env set but non-positive → def, not confSeconds.
	t.Setenv(key, "-3s")
	if got := DurOr(key, 30, def); got != def {
		t.Fatalf("env non-positive: got %v want def %v", got, def)
	}
	// env unset/empty → conf seconds.
	t.Setenv(key, "")
	if got := DurOr(key, 30, def); got != 30*time.Second {
		t.Fatalf("env empty: got %v want 30s (conf)", got)
	}
	// conf <= 0 → def.
	if got := DurOr(key, 0, def); got != def {
		t.Fatalf("conf zero: got %v want def", got)
	}
	if got := DurOr(key, -5, def); got != def {
		t.Fatalf("conf negative: got %v want def", got)
	}
	// confSeconds past the int64-ns ceiling must not wrap to a bogus
	// interval — 18446744074s overflows into a positive ~0.29s.
	if got := DurOr(key, 18446744074, def); got != def {
		t.Fatalf("conf overflow: got %v want def", got)
	}
	// Fully unset env.
	t.Setenv(key, "")
	if got := DurOr(key, 0, def); got != def {
		t.Fatalf("all unset: got %v want def", got)
	}
}

func TestList(t *testing.T) {
	const key = "ENVX_TEST_LIST"

	if got := List(key); got != nil {
		t.Fatalf("unset: got %v want nil", got)
	}
	t.Setenv(key, "")
	if got := List(key); got != nil {
		t.Fatalf("empty: got %v want nil", got)
	}
	// Entries that trim to empty are dropped; if nothing survives the
	// result is still nil, not an empty slice.
	for _, v := range []string{",", " , ", ",,,", " , , "} {
		t.Setenv(key, v)
		if got := List(key); got != nil {
			t.Fatalf("%q: got %v want nil", v, got)
		}
	}
	t.Setenv(key, "a,b,c")
	if got := List(key); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("plain: got %v", got)
	}
	t.Setenv(key, " a , ,b ,")
	if got := List(key); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("trim/drop: got %v", got)
	}
	t.Setenv(key, ",a,")
	if got := List(key); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("edge commas: got %v", got)
	}
	t.Setenv(key, "single")
	if got := List(key); !slices.Equal(got, []string{"single"}) {
		t.Fatalf("single: got %v", got)
	}
}

func TestIntList(t *testing.T) {
	const key = "ENVX_TEST_INT_LIST"

	if got := IntList(key); got != nil {
		t.Fatalf("unset: got %v want nil", got)
	}
	t.Setenv(key, "")
	if got := IntList(key); got != nil {
		t.Fatalf("empty: got %v want nil", got)
	}
	t.Setenv(key, ",")
	if got := IntList(key); got != nil {
		t.Fatalf("commas only: got %v want nil", got)
	}
	t.Setenv(key, "1,2,3")
	if got := IntList(key); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("plain: got %v", got)
	}
	// Non-numeric entries are skipped (with a warn); negatives parse.
	t.Setenv(key, "1,x,-2, 3 ,y")
	if got := IntList(key); !slices.Equal(got, []int{1, -2, 3}) {
		t.Fatalf("skip non-numeric: got %v", got)
	}
	// All entries non-numeric → nil, not an empty slice.
	t.Setenv(key, "a,b")
	if got := IntList(key); got != nil {
		t.Fatalf("all invalid: got %v want nil", got)
	}
}

// Apply must run rows in table order and hand each row its own
// declared Name — the contract bespoke {Name, Resolve} rows rely on.
func TestApplyOrderAndName(t *testing.T) {
	var got []string
	Apply([]Knob{
		{Name: "ENVX_TEST_KNOB_B", Resolve: func(k string) { got = append(got, k) }},
		{Name: "ENVX_TEST_KNOB_A", Resolve: func(k string) { got = append(got, k) }},
		{Name: "ENVX_TEST_KNOB_C", Resolve: func(k string) { got = append(got, k) }},
	})
	want := []string{"ENVX_TEST_KNOB_B", "ENVX_TEST_KNOB_A", "ENVX_TEST_KNOB_C"}
	if !slices.Equal(got, want) {
		t.Fatalf("apply order = %v, want %v", got, want)
	}
}

// The *Knob constructors must resolve through the same helpers the
// imperative code called — env set wins, unset falls to def/conf.
func TestStringKnob(t *testing.T) {
	const key = "ENVX_TEST_STRING_KNOB"
	var s string
	Apply([]Knob{StringKnob(key, &s, "def")})
	if s != "def" {
		t.Fatalf("unset: got %q want def", s)
	}
	t.Setenv(key, "v")
	Apply([]Knob{StringKnob(key, &s, "def")})
	if s != "v" {
		t.Fatalf("set: got %q want v", s)
	}
}

func TestBoolKnob(t *testing.T) {
	const key = "ENVX_TEST_BOOL_KNOB"
	var b bool
	Apply([]Knob{BoolKnob(key, &b, true)})
	if !b {
		t.Fatal("unset: got false want def true")
	}
	t.Setenv(key, "0")
	Apply([]Knob{BoolKnob(key, &b, true)})
	if b {
		t.Fatal("set 0: got true want false")
	}
}

func TestIntKnob(t *testing.T) {
	const key = "ENVX_TEST_INT_KNOB"
	var n int
	Apply([]Knob{IntKnob(key, &n, 7)})
	if n != 7 {
		t.Fatalf("unset: got %d want 7", n)
	}
	t.Setenv(key, "42")
	Apply([]Knob{IntKnob(key, &n, 7)})
	if n != 42 {
		t.Fatalf("set: got %d want 42", n)
	}
}

func TestInt64Knob(t *testing.T) {
	const key = "ENVX_TEST_INT64_KNOB"
	var n int64
	t.Setenv(key, "42")
	Apply([]Knob{Int64Knob(key, &n, 9)})
	if n != 42 {
		t.Fatalf("set: got %d want 42", n)
	}
}

func TestDurationKnob(t *testing.T) {
	const key = "ENVX_TEST_DURATION_KNOB"
	var d time.Duration
	def := 10 * time.Second
	Apply([]Knob{DurationKnob(key, &d, def)})
	if d != def {
		t.Fatalf("unset: got %v want %v", d, def)
	}
	t.Setenv(key, "2m")
	Apply([]Knob{DurationKnob(key, &d, def)})
	if d != 2*time.Minute {
		t.Fatalf("set: got %v want 2m", d)
	}
}

func TestOrKnob(t *testing.T) {
	const key = "ENVX_TEST_OR_KNOB"
	var s string
	Apply([]Knob{OrKnob(key, &s, "conf")})
	if s != "conf" {
		t.Fatalf("unset: got %q want conf", s)
	}
	t.Setenv(key, "env")
	Apply([]Knob{OrKnob(key, &s, "conf")})
	if s != "env" {
		t.Fatalf("set: got %q want env", s)
	}
}

// StrOrKnob is the only three-tier constructor: env → conf → def,
// with a set-but-unparseable env still winning verbatim (Or string
// semantics — no parse layer to fall through).
func TestStrOrKnob(t *testing.T) {
	const key = "ENVX_TEST_STROR_KNOB"
	var s string
	Apply([]Knob{StrOrKnob(key, &s, "", "def")})
	if s != "def" {
		t.Fatalf("all empty: got %q want def", s)
	}
	Apply([]Knob{StrOrKnob(key, &s, "conf", "def")})
	if s != "conf" {
		t.Fatalf("conf only: got %q want conf", s)
	}
	t.Setenv(key, "env")
	Apply([]Knob{StrOrKnob(key, &s, "conf", "def")})
	if s != "env" {
		t.Fatalf("env set: got %q want env", s)
	}
}

func TestIntOrKnob(t *testing.T) {
	const key = "ENVX_TEST_INTOR_KNOB"
	var n int
	Apply([]Knob{IntOrKnob(key, &n, 3, 9)})
	if n != 3 {
		t.Fatalf("unset: got %d want 3 (conf)", n)
	}
	t.Setenv(key, "bogus")
	Apply([]Knob{IntOrKnob(key, &n, 3, 9)})
	if n != 9 {
		t.Fatalf("env invalid: got %d want 9 (def, not conf)", n)
	}
	t.Setenv(key, "5")
	Apply([]Knob{IntOrKnob(key, &n, 3, 9)})
	if n != 5 {
		t.Fatalf("env set: got %d want 5", n)
	}
}

func TestInt64OrKnob(t *testing.T) {
	const key = "ENVX_TEST_INT64OR_KNOB"
	var n int64
	t.Setenv(key, "42")
	Apply([]Knob{Int64OrKnob(key, &n, 3, 9)})
	if n != 42 {
		t.Fatalf("env set: got %d want 42", n)
	}
	t.Setenv(key, "")
	Apply([]Knob{Int64OrKnob(key, &n, 3, 9)})
	if n != 3 {
		t.Fatalf("env empty: got %d want 3 (conf)", n)
	}
}

func TestDurOrKnob(t *testing.T) {
	const key = "ENVX_TEST_DUROR_KNOB"
	var d time.Duration
	def := 10 * time.Second
	Apply([]Knob{DurOrKnob(key, &d, 30, def)})
	if d != 30*time.Second {
		t.Fatalf("unset: got %v want 30s (conf)", d)
	}
	t.Setenv(key, "bogus")
	Apply([]Knob{DurOrKnob(key, &d, 30, def)})
	if d != def {
		t.Fatalf("env invalid: got %v want def %v", d, def)
	}
	t.Setenv(key, "2m")
	Apply([]Knob{DurOrKnob(key, &d, 30, def)})
	if d != 2*time.Minute {
		t.Fatalf("env set: got %v want 2m", d)
	}
}

func TestListKnob(t *testing.T) {
	const key = "ENVX_TEST_LIST_KNOB"
	var l []string
	Apply([]Knob{ListKnob(key, &l)})
	if l != nil {
		t.Fatalf("unset: got %v want nil", l)
	}
	t.Setenv(key, "a, b")
	Apply([]Knob{ListKnob(key, &l)})
	if !slices.Equal(l, []string{"a", "b"}) {
		t.Fatalf("set: got %v", l)
	}
}

func TestIntListKnob(t *testing.T) {
	const key = "ENVX_TEST_INTLIST_KNOB"
	var l []int
	Apply([]Knob{IntListKnob(key, &l)})
	if l != nil {
		t.Fatalf("unset: got %v want nil", l)
	}
	t.Setenv(key, "1,x,2")
	Apply([]Knob{IntListKnob(key, &l)})
	if !slices.Equal(l, []int{1, 2}) {
		t.Fatalf("set: got %v", l)
	}
}
