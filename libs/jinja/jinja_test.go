package jinja

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestJinjaEngine(t *testing.T) {
	nodes, _ := DecodeYAML([]byte("a: {x: 1}\nb: {x: 2}\n"))
	ctx := map[string]any{"d": nodes, "sep": "-"}
	cases := map[string]string{
		"{{ d | dict2items | map(attribute='key') | join(',') }}": "a,b",
		"{{ [1,2,3] | join('-') }}":                               "1-2-3",
		"{{ 'x' ~ sep ~ 'y' }}":                                   "x-y",
		"{% set l = [] %}{% for i in [1,2] %}{% set _ = l.append(i) %}{% endfor %}{{ l | join(',') }}": "1,2",
		"{{ 'abc' | regex_replace('b', 'X') }}":                                                        "aXc",
		"{{ [3,1,2] | sort | join(',') }}":                                                             "1,2,3",
		"{{ 5 if d is defined else 0 }}":                                                               "5",
	}
	for in, want := range cases {
		got, err := Render(in, ctx, nil)
		if err != nil {
			t.Fatalf("render %q: %v", in, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", in, got, want)
		}
	}
}

// `for x in seq if cond` — the api-local-lb.haproxy.cfg.j2 clause
// shape: filter cond contains its own `in` test which must NOT split
// the loop header (previously misparsed into a garbage loop var).
func TestForIfFilteredLoop(t *testing.T) {
	be, err := DecodeYAML([]byte(`
- name: a
  addr: 10.0.0.1:6443
- name: b
  addr: 10.0.0.2:6443
  probe: true
- name: c
  addr: 10.0.0.3:6443
  probe: true
  backup: true
`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{
		"api_lb_backends":        be,
		"api_lb_probe_reachable": &List{[]any{"b"}},
	}
	tpl := `{% for b in api_lb_backends
   if not (b.probe | default(false)) or b.name in (api_lb_probe_reachable | default([])) %}
    server {{ b.name }} {{ b.addr }} check inter 5s fall 2 rise 2{{ ' backup' if b.backup | default(false) }}
{% endfor %}`
	got, err := Render(tpl, ctx, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// a: no probe -> always rendered. b: probe + reachable -> rendered.
	// c: probe + NOT reachable -> skipped (backup flag irrelevant).
	if strings.Contains(got, "server c ") {
		t.Fatalf("probed unreachable backend rendered:\n%s", got)
	}
	if !strings.Contains(got, "server a 10.0.0.1:6443 check") {
		t.Fatalf("default backend missing:\n%s", got)
	}
	if !strings.Contains(got, "server b 10.0.0.2:6443 check inter 5s fall 2 rise 2") {
		t.Fatalf("reachable probe backend missing:\n%s", got)
	}
}

func TestForIfMultipleConds(t *testing.T) {
	got, err := Render("{% for i in [1,2,3,4] if i > 1 if i < 4 %}{{ i }}{% endfor %}",
		map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "23" {
		t.Fatalf("got %q", got)
	}
}

// A for-clause that cannot be parsed must error out — never silently
// produce a garbage loop variable again.
func TestForUnparseableHardError(t *testing.T) {
	if _, err := Render("{% for x in [1,2] if ( %}{{ x }}{% endfor %}", nil, nil); err == nil {
		t.Fatal("expected parse error")
	}
}

// ---- audit-fix coverage: one test per verified finding ----

// A template ending in a bare 2-char opener must be a parse error,
// not an index panic (text[j:j+3] overran EOF).
func TestBareOpenerAtEOF(t *testing.T) {
	for _, tpl := range []string{"a{{", "b{%", "c{#", "{{", "{%", "{#"} {
		if _, err := Render(tpl, nil, nil); err == nil {
			t.Fatalf("render %q succeeded — want unclosed-tag error", tpl)
		}
	}
}

// `{{ x is }}` / `{{ x is not }}` — the missing test name consumed
// the eof token, then the "(" probe indexed past the slice.
func TestIsMissingTestName(t *testing.T) {
	ctx := map[string]any{"x": int64(1)}
	for _, tpl := range []string{"{{ x is }}", "{{ x is not }}"} {
		if _, err := Render(tpl, ctx, nil); err == nil {
			t.Fatalf("render %q succeeded — want missing-test-name error", tpl)
		}
	}
}

// Bound methods must not panic on missing args / out-of-range
// indices — same guard class as startswith/endswith.
func TestBoundMethodArgGuards(t *testing.T) {
	d, _ := DecodeYAML([]byte("k: v\n"))
	ctx := map[string]any{"d": d, "l": &List{[]any{"a", "b"}}}
	for _, tpl := range []string{
		"{{ d.get() }}",   // missing key arg
		"{{ l.index() }}", // missing needle arg
		"{{ l.pop(5) }}",  // out of range
		"{{ l.pop(-3) }}", // negative, still out of range
		"{{ l.pop() | string + l.pop() | string + l.pop() | string }}", // empty after 3 pops
	} {
		if _, err := Render(tpl, ctx, nil); err == nil {
			t.Fatalf("render %q succeeded — want error", tpl)
		}
	}
	// python-parity: pop() pops last, pop(-1) same via negative idx.
	l := &List{[]any{"a", "b", "c"}}
	got, err := Render("{% set _ = l.pop(-1) %}{{ l | join(',') }}",
		map[string]any{"l": l}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a,b" {
		t.Fatalf("pop(-1) rest=%q want \"a,b\"", got)
	}
}

// range() with step 0 used to spin an unbounded append; negative
// step silently yielded [] instead of descending.
func TestRangeStep(t *testing.T) {
	if _, err := Render("{{ range(1, 5, 0) }}", nil, nil); err == nil {
		t.Fatal("range step=0 want error")
	}
	got, err := Render("{{ range(5, 0, -1) | join(',') }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "5,4,3,2,1" {
		t.Fatalf("descending range=%q", got)
	}
	got, err = Render("{{ range(0, 5, 2) | join(',') }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0,2,4" {
		t.Fatalf("step-2 range=%q", got)
	}
}

// flatten must only recurse into real lists — strings used to be
// char-split via toIter, dicts dumped as keys.
func TestFlattenAtoms(t *testing.T) {
	cases := map[string]string{
		`{{ ['ab','cd'] | flatten | join(',') }}`:         "ab,cd",
		`{{ [[1,[2,[3]]], 'xy'] | flatten | join(',') }}`: "1,2,3,xy",
		`{{ [{'a':1}] | flatten | length }}`:              "1",
		`{{ 'plain' | flatten | join(',') }}`:             "plain",
		`{{ [[['x']], [[]], []] | flatten | join(',') }}`: "x",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
	// A self-referential list must terminate via the depth cap.
	l := &List{}
	l.V = []any{l, "z"}
	got, err := Render("{{ l | flatten | length }}",
		map[string]any{"l": l}, nil)
	if err != nil {
		t.Fatalf("cyclic flatten: %v", err)
	}
	if got == "" {
		t.Fatal("cyclic flatten rendered empty")
	}
}

// min/max on non-numeric lists must compare lexically — they used
// to return the first element untouched.
func TestMinMaxLexical(t *testing.T) {
	cases := map[string]string{
		`{{ ['b','a','c'] | min }}`: "a",
		`{{ ['b','a','c'] | max }}`: "c",
		`{{ [3,1,2] | min }}`:       "1",
		`{{ [3,1,2] | max }}`:       "3",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// select/reject without a test arg filter on truthiness — they used
// to pass the whole list through unchanged.
func TestSelectRejectTruthiness(t *testing.T) {
	cases := map[string]string{
		`{{ [0, 1, '', 'x', none] | select | join(',') }}`: "1,x",
		`{{ [0, 1, '', 'x'] | reject | join(',') }}`:       "0,",
		`{{ [] | select | join(',') }}`:                    "",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// regex_findall with multiple groups must emit all groups (python
// findall tuple semantics), not just group 1.
func TestRegexFindallMultiGroup(t *testing.T) {
	// NOTE: \d needs a doubled backslash — the template lexer
	// processes \\ escapes inside quoted strings.
	got, err := Render(`{{ 'a1b2' | regex_findall('([a-z])(\\d)') | first | join('-') }}`,
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a-1" {
		t.Fatalf("multi-group findall=%q want \"a-1\"", got)
	}
	// single group still unwraps to the bare capture.
	got, err = Render(`{{ 'a1b2' | regex_findall('(\\d)') | join(',') }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1,2" {
		t.Fatalf("single-group findall=%q", got)
	}
	// no group → the whole match.
	got, err = Render(`{{ 'a1b2' | regex_findall('[a-z]\\d') | join(',') }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a1,b2" {
		t.Fatalf("group-less findall=%q", got)
	}
}

// toInt on a zero-padded string must NOT read octal — "010" is 10,
// not 8, and "08" is a real number, not a parse failure.
func TestToIntNotOctal(t *testing.T) {
	got, err := Render("{{ range('010') | length }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10" {
		t.Fatalf("range('010') len=%q want 10", got)
	}
	got, err = Render("{{ range('08') | length }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "8" {
		t.Fatalf("range('08') len=%q want 8", got)
	}
}

// String indexing must honour negatives like the []any branch.
func TestStringNegativeIndex(t *testing.T) {
	cases := map[string]string{
		`{{ 'abc'[-1] }}`: "c",
		`{{ 'abc'[-3] }}`: "a",
		`{{ 'abc'[-4] }}`: "", // out of range → Undefined → ""
		`{{ 'abc'[1] }}`:  "b",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// An unknown `is <test>` name is almost always a typo — it must
// ERROR (jinja's "no test named"), never evaluate: `is not defind`
// used to compute false then negate to TRUE, silently opening a
// gate on a truthy subject.
func TestUnknownTestErrors(t *testing.T) {
	for _, tpl := range []string{
		"{{ 'y' if d is defind else 'n' }}",
		"{{ 'y' if d is not defind else 'n' }}",
		"{{ [1] | select('defind') | join(',') }}",
		"{{ [1] | reject('defind') | join(',') }}",
		"{{ [{'k': 1}] | selectattr('k', 'defind') | length }}",
		"{{ [{'k': 1}] | rejectattr('k', 'defind') | length }}",
	} {
		if out, err := Render(tpl, map[string]any{"d": int64(1)}, nil); err == nil {
			t.Fatalf("render %q = %q — want unknown-test error", tpl, out)
		}
	}
	// A real test still resolves.
	got, err := Render("{{ 'y' if d is defined else 'n' }}",
		map[string]any{"d": int64(1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "y" {
		t.Fatalf("defined test = %q", got)
	}
}

// str + number must error (python TypeError) — it used to silently
// concatenate "5"+3 → "53". str+str still concatenates; use ~ to
// coerce.
func TestStringPlusNumberErrors(t *testing.T) {
	for _, tpl := range []string{`{{ '5' + 3 }}`, `{{ 3 + '5' }}`} {
		if _, err := Render(tpl, nil, nil); err == nil {
			t.Fatalf("render %q succeeded — want concat type error", tpl)
		}
	}
	got, err := Render(`{{ 'a' + 'b' }}{{ 5 + 3 }}{{ 'x' ~ 3 }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ab8x3" {
		t.Fatalf("concat/numeric/coerce = %q want \"ab8x3\"", got)
	}
	// The error must name the NON-string operand — reporting r's
	// type blamed "string" when r WAS the string.
	if _, err := Render(`{{ 3 + 'a' }}`, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "int64") {
		t.Fatalf("3+'a' err=%v want the int64 side named", err)
	}
	// list+num / dict+num fell through to a silent stringify-concat.
	for _, tpl := range []string{`{{ [1] + 2 }}`, `{{ {'a': 1} + 2 }}`, `{{ none + 2 }}`} {
		if _, err := Render(tpl, nil, nil); err == nil {
			t.Fatalf("render %q succeeded — want + type error", tpl)
		}
	}
}

// A }} or %} inside a quoted literal is text, not the tag close —
// the naive strings.Index cut the tag early.
func TestTagCloseInsideQuotedLiteral(t *testing.T) {
	cases := map[string]string{
		`{{ 'a}}b' }}`:                "a}}b",
		`{% set x = 'a%}b' %}{{ x }}`: "a%}b",
		`{{ "a}}b" }}`:                "a}}b",
		`{{ 'it\'s' ~ '}}' }}`:        "it's}}",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
}

// selectattr path resolution must evaluate through a boundMethod —
// the self-assign used to no-op the remaining segments.
func TestSelectAttrThroughMethodName(t *testing.T) {
	items, _ := DecodeYAML([]byte("- k: 1\n- k: 2\n"))
	got, err := Render("{{ items | selectattr('items.x') | length }}",
		map[string]any{"items": items}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 'items' on a dict without that key resolves to the bound
	// items() method; '.x' on it is Undefined → both items dropped.
	if got != "0" {
		t.Fatalf("selectattr through method name = %q want 0", got)
	}
	// ...while a real attribute path still works.
	got, err = Render("{{ items | selectattr('k', 'equalto', 2) | length }}",
		map[string]any{"items": items}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1" {
		t.Fatalf("selectattr real path = %q want 1", got)
	}
}

// `for k,v in omap` iterates KEYS as strings and used to
// char-split them — it must error instead (use .items()).
func TestForOverMappingTupleUnpackErrors(t *testing.T) {
	m, _ := DecodeYAML([]byte("alpha: 1\nbeta: 2\n"))
	if _, err := Render("{% for k, v in m %}{{ k }}={{ v }};{% endfor %}",
		map[string]any{"m": m}, nil); err == nil {
		t.Fatal("for k,v in mapping succeeded — want unpack error")
	}
	// The .items() idiom keeps working.
	got, err := Render("{% for k, v in m.items() %}{{ k }}={{ v }};{% endfor %}",
		map[string]any{"m": m}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alpha=1;beta=2;" {
		t.Fatalf("items() loop = %q", got)
	}
}

// Jinja scopes a for body: the loop var and {% set %}s inside do
// not leak past {% endfor %}.
func TestForLoopBlockScoping(t *testing.T) {
	got, err := Render(
		"{% set z = 0 %}{% for i in [1,2] %}{% set z = i %}{% endfor %}[{{ z }}][{{ i }}]",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// outer z untouched by the in-loop rebinding; i undefined after.
	if got != "[0][]" {
		t.Fatalf("block scoping = %q want \"[0][]\"", got)
	}
	// ...but a var set inside IS visible in later iterations
	// (the block scope spans the whole loop).
	got, err = Render(
		"{% for i in [1,2,3] %}{{ prev | default('-') }}{% set prev = i %}{% endfor %}",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "-12" {
		t.Fatalf("cross-iteration visibility = %q want \"-12\"", got)
	}
	// ...and mutation through a shared *List still escapes the
	// scope (that's the append idiom, not a leak).
	l := &List{}
	got, err = Render(
		"{% for i in [1,2] %}{% set _ = l.append(i) %}{% endfor %}{{ l | join(',') }}",
		map[string]any{"l": l}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1,2" {
		t.Fatalf("append-in-loop = %q want \"1,2\"", got)
	}
}

// pyFormat must honour precision/hex/float conversions — %5.2f,
// %x used to pass the arg through unformatted.
func TestPyFormatConversions(t *testing.T) {
	cases := map[string]string{
		`{{ '%5.2f' | format(3.14159) }}`: " 3.14",
		`{{ '%x' | format(255) }}`:        "ff",
		`{{ '%04x' | format(255) }}`:      "00ff",
		`{{ '%X' | format(255) }}`:        "FF",
		`{{ '%d-%s' | format(7, 'w') }}`:  "7-w",
		`{{ '%e' | format(1000) }}`:       "1.000000e+03",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
	// A non-numeric arg for a numeric conversion errors now.
	if _, err := Render(`{{ '%d' | format('abc') }}`, nil, nil); err == nil {
		t.Fatal("format %!d(MISSING) on non-number want error")
	}
}

// A second --- document must error, not be silently dropped.
func TestDecodeYAMLRejectsSecondDocument(t *testing.T) {
	if _, err := DecodeYAML([]byte("a: 1\n---\nb: 2\n")); err == nil {
		t.Fatal("multi-document yaml decoded — want error")
	}
	if _, err := DecodeYAML([]byte("a: 1\n")); err != nil {
		t.Fatalf("single doc: %v", err)
	}
}

// ---- round-2 audit coverage: DoS bounds + arity/arity-error fixes ----

// A self-referential list is constructible in-template
// ({% set _ = l.append(l) %}) — stringify, ==, to_json and
// to_yaml must all terminate under the recursion budget instead
// of bursting the goroutine stack.
func TestCyclicListTerminates(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		out, err := Render(
			"{% set l = [] %}{% set _ = l.append(l) %}{{ l }}{{ l == l }}{{ l | to_json }}{{ l | to_yaml }}",
			nil, nil)
		if err != nil {
			done <- err
			return
		}
		if !strings.Contains(out, "...") {
			done <- fmt.Errorf("cyclic render %q missing [...] marker", out)
			return
		}
		// l == l stays true via the pointer short-circuit.
		if !strings.Contains(out, "True") {
			done <- fmt.Errorf("cyclic l == l = %q want True", out)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cyclic list render did not terminate")
	}
}

// flatten's depth cap alone didn't stop a BRANCHING cycle —
// l.V=[l,l] doubles output every level while never deepening past
// the cap; the total-element budget must error instead of
// exploding to ~2^100 appends.
func TestFlattenBranchingCycleBudget(t *testing.T) {
	l := &List{}
	l.V = []any{l, l}
	done := make(chan error, 1)
	go func() {
		_, err := Render("{{ l | flatten }}", map[string]any{"l": l}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("branching cyclic flatten succeeded — want output-budget error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("branching cyclic flatten did not terminate")
	}
}

// range() materializes eagerly — an open-ended range must fail at
// the cap rather than OOM, and a step near MinInt64 wraps the
// counter (i>hi stays true after wrap → unbounded append) unless
// the length is computed arithmetically first.
func TestRangeOutputCap(t *testing.T) {
	if _, err := Render("{{ range(0, 2000000) | length }}", nil, nil); err == nil {
		t.Fatal("oversize range succeeded — want cap error")
	}
	// -9223372036854775808 lexes as -(float) → int64 MinInt64 step:
	// i=-1 wraps to MaxInt64 which still satisfies i>hi. Exact
	// length is 1 — the precomputed count must bound the loop.
	got, err := Render("{{ range(-1, -2, -9223372036854775808) | join(',') }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "-1" {
		t.Fatalf("wrapping-step range=%q want \"-1\"", got)
	}
	// An exact-cap range still materializes.
	got, err = Render("{{ range(3) | join(',') }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0,1,2" {
		t.Fatalf("range(3)=%q", got)
	}
}

// Tuple unpacking in {% for a,b[,c] in x %} must match the item
// arity EXACTLY — the loose match bound literal "key"/"value"
// strings off dict2items pairs and dropped extra elements.
func TestForBindArity(t *testing.T) {
	m, _ := DecodeYAML([]byte("alpha: 1\nbeta: 2\n"))
	for _, tpl := range []string{
		// dict2items yields {key,value} mappings — unpacking bound
		// the literal strings "key"/"value".
		"{% for k, v in m | dict2items %}{{ k }}={{ v }}{% endfor %}",
		"{% for a, b, c in [[1, 2], [3, 4]] %}{{ a }}{% endfor %}", // 3 names, 2-value items
		"{% for a, b in [[1, 2, 3]] %}{{ a }}{% endfor %}",         // 2 names, 3-value item
		"{% for a, b in [5] %}{{ a }}{% endfor %}",                 // non-iterable item
	} {
		if out, err := Render(tpl, map[string]any{"m": m}, nil); err == nil {
			t.Fatalf("render %q = %q — want unpack arity error", tpl, out)
		}
	}
	// Matching arity still binds; a 2-char string item also
	// unpacks (python `a,b = 'xy'` parity).
	got, err := Render("{% for a, b, c in [[1, 2, 3]] %}{{ a }}{{ b }}{{ c }}{% endfor %}",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "123" {
		t.Fatalf("3-name unpack = %q", got)
	}
	// ...and the single-var dict2items idiom (x.key/x.value).
	got, err = Render("{% for p in m | dict2items %}{{ p.key }}={{ p.value }};{% endfor %}",
		map[string]any{"m": m}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alpha=1;beta=2;" {
		t.Fatalf("dict2items single-var loop = %q", got)
	}
}

// pyFormat holes: %F was a dead case (missing from the conversion
// set), unknown conversions passed through literally, arg-count
// mismatches were ignored, %.Ns didn't truncate, %c split
// multi-byte chars, and '-' mid-spec passed validation.
func TestPyFormatStrict(t *testing.T) {
	cases := map[string]string{
		`{{ '%F' | format(3.5) }}`:       "3.500000",
		`{{ '%.2s' | format('abcd') }}`:  "ab",
		`{{ '%5.1s' | format('abcd') }}`: "    a",
		`{{ '%c' | format('éx') }}`:      "é",
		`{{ '%%' | format }}`:            "%",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
	for _, tpl := range []string{
		`{{ '%o' | format(8) }}`,      // unsupported conversion
		`{{ '%u' | format(8) }}`,      //
		`{{ '%p' | format(8) }}`,      //
		`{{ '%d %d' | format(1) }}`,   // too few args
		`{{ '%d' | format(1, 2) }}`,   // too many args
		`{{ '%5-2f' | format(1.5) }}`, // '-' mid-spec
	} {
		if out, err := Render(tpl, nil, nil); err == nil {
			t.Fatalf("render %q = %q — want format error", tpl, out)
		}
	}
}

// A trailing bare --- decodes to an empty (nil) document — legal
// YAML, must NOT trip the multi-document guard. A real second
// document still errors (TestDecodeYAMLRejectsSecondDocument).
func TestDecodeYAMLTrailingSeparator(t *testing.T) {
	v, err := DecodeYAML([]byte("a: 1\n---\n"))
	if err != nil {
		t.Fatalf("trailing --- : %v", err)
	}
	if m, _ := v.(*OMap); m == nil {
		t.Fatalf("trailing --- doc = %T want *OMap", v)
	}
	// Recursive anchors form a node-graph cycle (&x → *x) — the
	// depth cap must error instead of recursing forever.
	if _, err := DecodeYAML([]byte("x: &x\n  self: *x\n")); err == nil {
		t.Fatal("recursive anchor decoded — want depth-cap error")
	}
	// A non-recursive anchor still resolves.
	v, err = DecodeYAML([]byte("def: &d\n  a: 1\nuse: *d\n"))
	if err != nil {
		t.Fatalf("plain anchor: %v", err)
	}
	om, _ := v.(*OMap)
	use, _ := om.Get("use")
	if um, _ := use.(*OMap); um == nil {
		t.Fatalf("aliased value = %T want *OMap", use)
	}
}

// The float-% branch truncated operands through int64 — a sub-1 or
// non-int-representable divisor (a float-string like "0.5") became
// int64(rf)==0 → integer divide-by-zero PANIC. math.Mod is the
// float modulo; the result takes the divisor's sign like python.
func TestFloatModuloNoPanic(t *testing.T) {
	cases := map[string]string{
		`{{ "5.5" % "0.5" }}`: "0",
		`{{ 5 % "0.5" }}`:     "0",
		`{{ "5.5" % "2" }}`:   "1.5",
		`{{ "-5.5" % "2" }}`:  "0.5", // floored (divisor's sign)
		`{{ "5.5" % "-2" }}`:  "-0.5",
		`{{ 5.5 % 2.0 }}`:     "1.5", // float operands take the float path
		`{{ "10" % "0.25" }}`: "0",
	}
	for tpl, want := range cases {
		got, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatalf("render %q: %v", tpl, err)
		}
		if got != want {
			t.Fatalf("render %q = %q want %q", tpl, got, want)
		}
	}
	// A real zero divisor still errors.
	if _, err := Render(`{{ "5.5" % "0" }}`, nil, nil); err == nil {
		t.Fatal("x % \"0\" succeeded — want modulo-by-zero error")
	}
}

// indent with a negative width fed strings.Repeat a negative count —
// a panic. Python's ' ' * -n is ” so the value renders unindented.
func TestIndentNegativeWidth(t *testing.T) {
	got, err := Render("{{ 'a\\nb' | indent(-3) }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a\nb" {
		t.Fatalf("indent(-3) = %q want unindented", got)
	}
	// Positive widths still pad.
	got, err = Render("{{ 'a\\nb' | indent(2) }}", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "  a\n  b" {
		t.Fatalf("indent(2) = %q", got)
	}
}
