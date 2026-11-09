// audit_fixes_test.go — one table-driven suite per plan item:
// the shared walk-step budget (exponential-structure + billion-
// laughs bails), |indent width cap, |int non-finite/range defaults,
// NaN rejection + coercion-strict ==, floored // and %, parser
// strictness (unclosed blocks, else-if, set '='), postfix name
// tokens, map(format) kw/default/error handling, and printf spec
// validation for %s/%v/%r/%c.
package jinja

import (
	"math"
	"strings"
	"testing"
	"time"
)

// renderBounded runs Render on a goroutine so a regression that
// hangs (the whole point of the step budget) fails the test on the
// deadline instead of stalling the suite.
func renderBounded(t *testing.T, tpl string, ctx map[string]any) (string, error) {
	t.Helper()
	type res struct {
		out string
		err error
	}
	done := make(chan res, 1)
	go func() {
		out, err := Render(tpl, ctx, nil)
		done <- res{out, err}
	}()
	select {
	case r := <-done:
		return r.out, r.err
	case <-time.After(10 * time.Second):
		t.Fatalf("render %q did not terminate within 10s", tpl)
		return "", nil
	}
}

// branchingCycle builds l.V=[l,l] — the structure that doubles the
// walk work per level while never deepening past the depth cap.
func branchingCycle() *List {
	l := &List{}
	l.V = []any{l, l}
	return l
}

// The shared step budget must stop an exponentially BRANCHING
// structure: stringify degrades to "[...]", the deepEq answers
// false, and the error-capable walkers (json/plain) error the
// filter instead of exploding to ~2^d node visits.
func TestWalkStepBudgetBranchingCycle(t *testing.T) {
	l := branchingCycle()

	// stringify: terminates with the elision marker.
	out, err := renderBounded(t, "{{ l }}", map[string]any{"l": l})
	if err != nil {
		t.Fatalf("stringify branching cycle: %v", err)
	}
	if !strings.Contains(out, "[...]") {
		t.Fatalf("stringify branching cycle = %q — want [...] elision", out)
	}

	// deepEq: two DISTINCT branching cycles compare false under the
	// budget (identical pointers short-circuit, so use a second one).
	m := branchingCycle()
	out, err = renderBounded(t, "{{ l == m }}", map[string]any{"l": l, "m": m})
	if err != nil {
		t.Fatalf("deepEq branching cycles: %v", err)
	}
	if out != "False" {
		t.Fatalf("branching cycle == = %q want False", out)
	}

	// to_json / to_yaml: the walkers CAN error — a runaway
	// structure must error the render, not silently truncate.
	for _, tpl := range []string{"{{ l | to_json }}", "{{ l | to_yaml }}"} {
		if _, err := renderBounded(t, tpl, map[string]any{"l": l}); err == nil {
			t.Fatalf("render %q succeeded — want step-budget error", tpl)
		} else if !strings.Contains(err.Error(), "steps") {
			t.Fatalf("render %q err = %v — want step-budget message", tpl, err)
		}
	}
	// Direct walker calls error the same way.
	if _, err := jsonValue(l); err == nil {
		t.Fatal("jsonValue(branching cycle) succeeded — want error")
	}
	if _, err := toPlain(l); err == nil {
		t.Fatal("toPlain(branching cycle) succeeded — want error")
	}
}

// Billion laughs: alias re-expansion multiplies node visits per
// level WITHOUT adding depth, so only the total step counter stops
// it — the decode must error, quickly.
func TestDecodeYAMLBillionLaughsStepBail(t *testing.T) {
	var b strings.Builder
	b.WriteString("a: &a [x, x, x, x, x, x, x, x, x]\n")
	levels := "abcdefgh"
	for i := 1; i < len(levels); i++ {
		prev, cur := string(levels[i-1]), string(levels[i])
		var refs []string
		for range 9 {
			refs = append(refs, "*"+prev)
		}
		b.WriteString(cur + ": &" + cur + " [" + strings.Join(refs, ", ") + "]\n")
	}
	var refs []string
	for range 9 {
		refs = append(refs, "*h")
	}
	b.WriteString("i: [" + strings.Join(refs, ", ") + "]\n")

	type res struct {
		v   any
		err error
	}
	done := make(chan res, 1)
	go func() {
		v, err := DecodeYAML([]byte(b.String()))
		done <- res{v, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("billion-laughs yaml decoded — want step-budget error")
		}
		if !strings.Contains(r.err.Error(), "steps") {
			t.Fatalf("billion-laughs err = %v — want step-budget message", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("billion-laughs decode did not terminate within 10s")
	}

	// A modest alias document still decodes — the budget only
	// catches runaway expansion.
	v, err := DecodeYAML([]byte("def: &d\n  a: 1\nuse: *d\n"))
	if err != nil {
		t.Fatalf("plain alias decode: %v", err)
	}
	if _, ok := v.(*OMap); !ok {
		t.Fatalf("plain alias decode = %T want *OMap", v)
	}
}

// |indent: a huge width must clamp to maxIndentWidth — strings.
// Repeat with a million-count pad per line is an OOM lever.
func TestIndentWidthCap(t *testing.T) {
	out, err := renderBounded(t, "{{ 'a\\nb' | indent(1000000) }}", nil)
	if err != nil {
		t.Fatalf("indent overflow: %v", err)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("indent lines = %d want 2", len(lines))
	}
	for i, ln := range lines {
		want := maxIndentWidth + 1 // pad + the single content char
		if len(ln) != want {
			t.Fatalf("indent line %d len = %d want %d (len %q)", i, len(ln), want, ln)
		}
		if strings.TrimSpace(ln) != "ab"[i:i+1] {
			t.Fatalf("indent line %d = %q — content mangled", i, ln)
		}
	}
	// Widths within the cap still indent, 0/-n don't (negative is
	// covered by TestIndentNegativeWidth).
	out, err = renderBounded(t, "{{ 'a\\nb' | indent(3) }}", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "   a\n   b" {
		t.Fatalf("indent(3) = %q", out)
	}
}

// |int: NaN/±Inf and out-of-int64-range values truncate to
// platform garbage (usually MinInt64) — the default is the honest
// answer instead.
func TestIntFilterNonFiniteAndRange(t *testing.T) {
	ctx := map[string]any{
		"nan": math.NaN(),
		"inf": math.Inf(1),
		"nif": math.Inf(-1),
	}
	cases := map[string]string{
		`{{ 'nan' | int(7) }}`:     "7",
		`{{ 'inf' | int(7) }}`:     "7",
		`{{ '-inf' | int(7) }}`:    "7",
		`{{ nan | int(7) }}`:       "7",
		`{{ inf | int(7) }}`:       "7",
		`{{ nif | int(7) }}`:       "7",
		`{{ 1e300 | int(7) }}`:     "7",                   // finite but far past int64
		`{{ 9.3e18 | int(7) }}`:    "7",                   // past MaxInt64
		`{{ '9.5e18' | int(7) }}`:  "7",                   // string float past MaxInt64
		`{{ 9.2e18 | int }}`:       "9200000000000000000", // biggest legit render
		`{{ 3.7 | int }}`:          "3",
		`{{ -3.7 | int }}`:         "-3",
		`{{ '42' | int }}`:         "42",
		`{{ 'ff' | int(0, 16) }}`:  "255",
		`{{ '0x10' | int(0, 0) }}`: "16",
		`{{ none | int(5) }}`:      "5",
		`{{ true | int }}`:         "1",
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

// toFloat must reject non-finite floats from EVERY source (string
// parse and float64 value alike).
func TestToFloatRejectsNonFinite(t *testing.T) {
	for _, in := range []any{"nan", "NAN", "inf", "-inf", "+Inf", math.NaN(), math.Inf(1), math.Inf(-1)} {
		if f, ok := toFloat(in); ok {
			t.Fatalf("toFloat(%#v) = %v, true — want rejection", in, f)
		}
	}
	for _, in := range []any{"1e2", " 2.5 ", int64(-3), 0.25, true} {
		if _, ok := toFloat(in); !ok {
			t.Fatalf("toFloat(%#v) rejected — want ok", in)
		}
	}
	// The |float filter surfaces the rejection as 0 rather than a
	// non-finite poison value.
	got, err := renderBounded(t, "{{ 'nan' | float }}|{{ 'inf' | float }}", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0|0" {
		t.Fatalf("float of non-finite = %q want \"0|0\"", got)
	}
}

// == must not coerce across types: strings compare as strings
// (never as floats), bools pair numerically only with numbers, and
// a non-finite number equals nothing — not even itself.
func TestEqualityCoercion(t *testing.T) {
	nan := math.NaN()
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		// non-finite floats: IEEE — unequal to everything.
		{"nan==nan false", deepEq(nan, nan), false},
		{"numEq nan 1", numEq(nan, int64(1)), false},
		{"numEq nan string", numEq(nan, "nan"), false},
		{"numEq inf inf", numEq(math.Inf(1), math.Inf(1)), false},
		// strings never coerce numerically against strings.
		{"'0'=='00'", deepEq("0", "00"), false},
		{"'1e2'=='100'", deepEq("1e2", "100"), false},
		{"'1'=='1'", deepEq("1", "1"), true},
		{"'nan'=='nan' (strings)", deepEq("nan", "nan"), true},
		// bool vs string never equal; bool vs number is numeric.
		{"false=='0'", deepEq(false, "0"), false},
		{"true=='1'", deepEq(true, "1"), false},
		{"true=='True'", deepEq(true, "True"), false},
		{"true==1", deepEq(true, int64(1)), true},
		{"false==0", deepEq(false, int64(0)), true},
		{"true==1.0", deepEq(true, 1.0), true},
		{"true==true", deepEq(true, true), true},
		// number vs numeric string stays numeric.
		{"1=='1'", deepEq(int64(1), "1"), true},
		{"1==1.0", deepEq(int64(1), 1.0), true},
		{"1=='2'", deepEq(int64(1), "2"), false},
		// number vs non-numeric string is plain unequal.
		{"1=='abc'", deepEq(int64(1), "abc"), false},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s = %v want %v", tc.name, tc.got, tc.want)
		}
	}

	// The same semantics through templates.
	tplCases := map[string]string{
		`{{ '0' == '00' }}`:    "False",
		`{{ '1e2' == '100' }}`: "False",
		`{{ false == '0' }}`:   "False",
		`{{ true == 1 }}`:      "True",
		`{{ false == 0 }}`:     "True",
		`{{ 1 == 1.0 }}`:       "True",
		`{{ 'a' == 'a' }}`:     "True",
		`{{ 'x' == 'y' }}`:     "False",
		`{{ nan == nan }}`:     "False",
		`{{ nan == 1 }}`:       "False",
		`{{ [1,2] == [1,2] }}`: "True",
		`{{ [1,2] == [1,3] }}`: "False",
	}
	for tpl, want := range tplCases {
		got, err := renderBounded(t, tpl, map[string]any{"nan": nan})
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// // and % are python-floored: the quotient takes the floor and the
// remainder takes the DIVISOR's sign.
func TestFloorDivisionAndModulo(t *testing.T) {
	i := func(v int64) any { return v }
	cases := []struct {
		op   string
		l, r any
		want any
	}{
		{"//", i(-7), i(2), i(-4)},
		{"//", i(7), i(-2), i(-4)},
		{"//", i(-7), i(-2), i(3)},
		{"//", i(7), i(2), i(3)},
		{"%", i(-7), i(2), i(1)},
		{"%", i(7), i(-2), i(-1)},
		{"%", i(-7), i(-2), i(-1)},
		{"%", i(7), i(2), i(1)},
		// float path (non-int-representable operands): // floors.
		{"//", "7.5", "2", 3.0},
		{"//", "-7.5", "2", -4.0},
		{"//", "0.5", "0.25", 2.0},
		// float % keeps its existing floored (divisor-sign) form.
		{"%", "-7.5", "2", 0.5},
		{"%", "7.5", "-2", -0.5},
	}
	for _, tc := range cases {
		got, err := binOp(tc.op, tc.l, tc.r)
		if err != nil {
			t.Fatalf("%v %s %v: %v", tc.l, tc.op, tc.r, err)
		}
		want := tc.want
		if lf, ok := got.(float64); ok {
			wf, wok := want.(float64)
			if !wok || lf != wf {
				t.Fatalf("%v %s %v = %#v want %#v", tc.l, tc.op, tc.r, got, want)
			}
			continue
		}
		if got != want {
			t.Fatalf("%v %s %v = %#v want %#v", tc.l, tc.op, tc.r, got, want)
		}
	}
	// Through the renderer (integer literals keep the integer
	// fast-path — same results as the binOp cases above).
	tplCases := map[string]string{
		`{{ -7 // 2 }}`: "-4",
		`{{ 7 // -2 }}`: "-4",
		`{{ -7 % 2 }}`:  "1",
		`{{ 7 % -2 }}`:  "-1",
		`{{ -7 % -2 }}`: "-1",
		`{{ 7 // 2 }}`:  "3",
	}
	for tpl, want := range tplCases {
		got, err := renderBounded(t, tpl, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
	// Zero divisors still error.
	for _, tpl := range []string{`{{ 7 // 0 }}`, `{{ 7 % 0 }}`, `{{ "7.5" % "0" }}`} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("render %q succeeded — want division-by-zero error", tpl)
		}
	}
}

// ---- parser strictness ----

// A block opened but never closed must be a parse error — the
// render used to silently truncate.
func TestUnclosedBlockErrors(t *testing.T) {
	for _, tpl := range []string{
		"{% if x %}a",
		"{% if x %}a{% elif y %}b",
		"{% if x %}a{% else %}b",
		"{% for i in [1] %}a",
		"{% if a %}{% for i in [1] %}{% endfor %}", // inner frame closed, if left open
		"{% if a %}{% for i in [1] %}x",            // innermost (for) reported
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("render %q succeeded — want missing end-block error", tpl)
		} else if !strings.Contains(err.Error(), "missing {% end") {
			t.Fatalf("render %q err = %v — want missing end-block message", tpl, err)
		}
	}
	// Well-formed blocks still parse and render.
	got, err := renderBounded(t, "{% if x %}a{% elif y %}b{% else %}c{% endif %}", map[string]any{"y": true})
	if err != nil || got != "b" {
		t.Fatalf("elif chain = %q, %v", got, err)
	}
}

// {% else %} takes no arguments, and nothing may follow the else
// arm.
func TestElseArmStrictness(t *testing.T) {
	for _, tpl := range []string{
		"{% if x %}a{% else if y %}b{% endif %}", // else-if typo class
		"{% if x %}a{% else %}b{% else %}c{% endif %}",
		"{% if x %}a{% else %}b{% elif y %}c{% endif %}",
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("render %q succeeded — want else-arm error", tpl)
		}
	}
}

// {% set %}: the '=' splitter must ignore !=/<=/>=/==, and the
// target must be a plain identifier.
func TestSetTagStrictness(t *testing.T) {
	// Comparisons in the VALUE survive the '=' scan.
	ctx := map[string]any{"a": int64(1), "b": int64(2)}
	cases := map[string]string{
		`{% set ok = a != b %}{{ ok }}`: "True",
		`{% set ok = a == b %}{{ ok }}`: "False",
		`{% set ok = a <= b %}{{ ok }}`: "True",
		`{% set ok = a >= b %}{{ ok }}`: "False",
		`{% set ok = a < b %}{{ ok }}`:  "True",
		`{% set x=1 %}{{ x }}`:          "1",
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
	// Typos / bad targets must error, not bind garbage.
	for _, tpl := range []string{
		"{% set x != 1 %}",  // '=' lives inside !=
		"{% set x == 1 %}",  // '=' lives inside ==
		"{% set x <= 1 %}",  //
		"{% set 1x = 2 %}",  // leading digit
		"{% set x.y = 2 %}", // dotted target (namespace unsupported)
		"{% set = 2 %}",     // no name at all
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("render %q succeeded — want set error", tpl)
		}
	}
}

// '.' and '|' must be followed by a name token.
func TestPostfixNameTokenRequired(t *testing.T) {
	ctx := map[string]any{"d": NewOMap()}
	for _, tpl := range []string{
		"{{ x | }}",
		"{{ x | 1 }}",
		"{{ x | (a) }}",
		"{{ d. }}",
		"{{ d.1 }}",
		`{{ d."k" }}`,
	} {
		if _, err := renderBounded(t, tpl, ctx); err == nil {
			t.Fatalf("render %q succeeded — want postfix name error", tpl)
		}
	}
	// Real postfix chains still parse.
	cases := map[string]string{
		`{{ 'a' | upper }}`:          "A",
		`{{ 'a b' | trim | upper }}`: "A B",
		`{{ 'x' | default('y') }}`:   "x",
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
	d := NewOMap()
	d.Set("k", "value")
	got, err := renderBounded(t, "{{ d.k }}", map[string]any{"d": d})
	if err != nil || got != "value" {
		t.Fatalf("attr postfix = %q, %v", got, err)
	}
}

// ---- map filter ----

// map(attribute=..., default=none): presence decides — default=none
// must map missing attributes to a literal None, not stay undefined.
func TestMapAttributeDefaultNone(t *testing.T) {
	items, err := DecodeYAML([]byte("- k: 1\n- other: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`{{ items | map(attribute='k') | join(',') }}`:               "1,", // undefined renders ""
		`{{ items | map(attribute='k', default='x') | join(',') }}`:  "1,x",
		`{{ items | map(attribute='k', default=none) | join(',') }}`: "1,None",
	}
	for tpl, want := range cases {
		got, err := renderBounded(t, tpl, map[string]any{"items": items})
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// map('filter', ...): kwargs travel into the applied filter, and
// only an UNKNOWN filter falls back to the attribute read — a
// runtime error inside a known filter must surface.
func TestMapFilterErrorAndKwargHandling(t *testing.T) {
	// kw propagation: the applied filter sees the keyword args.
	got, err := renderBounded(t, `{{ [none, 5] | map('default', 'x') | join(',') }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "x,5" {
		t.Fatalf("map('default') = %q want \"x,5\"", got)
	}

	// A known filter's runtime error now propagates (bad JSON used
	// to be swallowed into Undefined attribute reads).
	if _, err := renderBounded(t, `{{ ['{oops'] | map('from_json') | join(',') }}`, nil); err == nil {
		t.Fatal("map('from_json') on bad JSON succeeded — want error")
	}
	if _, err := renderBounded(t, `{{ ['a'] | map('regex_replace', '(', 'x') | join(',') }}`, nil); err == nil {
		t.Fatal("map('regex_replace') with bad pattern succeeded — want error")
	}

	// Unknown filters still degrade to the attribute/method read.
	got, err = renderBounded(t, `{{ [{'nope': 1}] | map('notafilter') | join(',') }}`, nil)
	if err != nil {
		t.Fatalf("map with unknown filter errored: %v", err)
	}
	if got != "" {
		t.Fatalf("map with unknown filter = %q want \"\"", got)
	}
}

// ---- printf specs ----

// %s/%v/%r and %c run the same flags→width→.precision validator as
// the numeric conversions.
func TestPyFormatSpecValidation(t *testing.T) {
	cases := map[string]string{
		`{{ '%s %v' | format('a', 1) }}`: "a 1",
		`{{ '%-5s!' | format('a') }}`:    "a    !",
		`{{ '%5s!' | format('a') }}`:     "    a!",
		`{{ '%c' | format(65) }}`:        "A",
		`{{ '%5c' | format(65) }}`:       "A",
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
	for _, tpl := range []string{
		`{{ '%5-2s' | format('a') }}`, // '-' mid-spec
		`{{ '%5-2v' | format('a') }}`,
		`{{ '%5-2r' | format('a') }}`,
		`{{ '%.2c' | format(65) }}`, // %c takes no precision
		`{{ '%5-2c' | format(65) }}`,
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("render %q succeeded — want spec-validation error", tpl)
		}
	}
}

// binOp's integer fast-path used to capture float operands: ToInt
// truncates every float64 (5.5 → 5, ok=true), so `5.5 * 2.0` ran
// int64 math and lost the fraction (10 instead of 11), and
// `5.5 % 2.0` gave 1 instead of 1.5. The fast-path now requires
// genuinely integer-typed operands; any float64 takes the float
// path. The integer path also guards the one int64 division whose
// quotient overflows (MinInt64 // -1, % -1) — the hardware divide
// would raise SIGFPE there.
func TestBinOpIntegerFastPathExcludesFloats(t *testing.T) {
	i := func(v int64) any { return v }
	cases := []struct {
		op   string
		l, r any
		want any
	}{
		// floats keep their fraction — and their TYPE: every
		// result below must be float64, not a truncated int64.
		{"*", 5.5, 2.0, 11.0},
		{"*", 5.5, i(2), 11.0}, // mixed float/int → float path
		{"+", 5.5, 2.0, 7.5},
		{"-", 5.5, 2.0, 3.5},
		{"/", 5.5, 2.0, 2.75},
		{"//", 5.5, 2.0, 2.0},  // floored
		{"//", 5.5, 2.25, 2.0}, // floor(2.44)
		{"%", 5.5, 2.0, 1.5},
		{"%", -5.5, 2.0, 0.5}, // remainder takes divisor's sign
		{"%", 5.5, -2.0, -0.5},
		// int64 operands stay on the integer fast-path — and keep
		// returning int64 (pinned by TestFloorDivisionAndModulo
		// through the renderer too).
		{"*", i(3), i(4), i(12)},
		{"+", i(3), i(4), i(7)},
		{"-", i(3), i(4), i(-1)},
		{"//", i(7), i(2), i(3)},
		{"//", i(-7), i(2), i(-4)},
		{"%", i(-7), i(2), i(1)},
		// bools count as integer-typed (python True == 1).
		{"*", true, i(4), i(4)},
		// comparisons never used ToInt — float order is exact.
		{"<", 5.5, 2.0, false},
		{">=", 5.5, 2.0, true},
		{"<", i(5), 5.5, true},
	}
	for _, tc := range cases {
		got, err := binOp(tc.op, tc.l, tc.r)
		if err != nil {
			t.Fatalf("%v %s %v: %v", tc.l, tc.op, tc.r, err)
		}
		var ok bool
		switch w := tc.want.(type) {
		case float64:
			var f float64
			f, ok = got.(float64)
			if ok && f != w {
				t.Fatalf("%v %s %v = %v want %v", tc.l, tc.op, tc.r, f, w)
			}
		case int64:
			var n int64
			n, ok = got.(int64)
			if ok && n != w {
				t.Fatalf("%v %s %v = %v want %v", tc.l, tc.op, tc.r, n, w)
			}
		case bool:
			var b bool
			b, ok = got.(bool)
			if ok && b != w {
				t.Fatalf("%v %s %v = %v want %v", tc.l, tc.op, tc.r, b, w)
			}
		}
		if !ok {
			t.Fatalf("%v %s %v = %T(%#v), want %T", tc.l, tc.op, tc.r, got, got, tc.want)
		}
	}

	// MinInt64 // -1 and % -1: the quotient overflows int64 and the
	// hardware divide raises SIGFPE — no panic, exact answers.
	mi := int64(math.MinInt64)
	q, err := binOp("//", mi, i(-1))
	if err != nil {
		t.Fatalf("MinInt64 // -1: %v", err)
	}
	qf, ok := q.(float64)
	if !ok || qf != 9223372036854775808.0 {
		t.Fatalf("MinInt64 // -1 = %#v, want float64 9223372036854775808", q)
	}
	m, err := binOp("%", mi, i(-1))
	if err != nil {
		t.Fatalf("MinInt64 %% -1: %v", err)
	}
	if m != i(0) {
		t.Fatalf("MinInt64 %% -1 = %#v, want int64 0", m)
	}

	// Through the renderer: float literals take the float path,
	// integer literals the integer path, and the guard survives
	// context-fed int64 values.
	tplCases := map[string]string{
		`{{ 5.5 * 2.0 }}`:  "11",
		`{{ 5.5 + 2.0 }}`:  "7.5",
		`{{ 5.5 - 2.0 }}`:  "3.5",
		`{{ 5.5 // 2.0 }}`: "2",
		`{{ 5.5 % 2.0 }}`:  "1.5",
		`{{ 5.5 * 2 }}`:    "11", // mixed operands → float path
		`{{ 2 * 3 }}`:      "6",
		`{{ 7 // 2 }}`:     "3",
		`{{ -7 // 2 }}`:    "-4",
		`{{ -7 % 2 }}`:     "1",
		`{{ a % b }}`:      "0", // MinInt64 % -1 via context
	}
	for tpl, want := range tplCases {
		ctx := map[string]any{"a": mi, "b": i(-1)}
		got, err := renderBounded(t, tpl, ctx)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}
