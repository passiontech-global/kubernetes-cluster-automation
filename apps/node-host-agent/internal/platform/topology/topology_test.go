package topology

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeVars(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	files := map[string]string{
		"interdc_nodes.yaml": `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  hub: false
  marker_octet: 7
  relay:
    - ip: 203.0.113.5
      sites: [s1]
      mode: always
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
  hub: false
  relay:
    - ip: 198.51.100.9
      mode: fallback
      probe: "9443"
`,
		"defaults.yaml": `interdc_nebula_enabled: true
interdc_marker_base: "172.29.0"
cp_endpoint: api.example.internal
cp_endpoint_fallback_names: [api2.example.internal]
fallback_dns: "1.1.1.1 9.9.9.9"
interdc_nebula_port: 45670
interdc_nebula_dev: neb1
interdc_nebula_mtu: 1300
interdc_nebula_table_pub: 100
interdc_nebula_table_marker: 101
interdc_nebula_net: interdc
interdc_nebula_version: "1.11.2"
api_lb_enabled: true
interdc_far_sites: []
`,
		"cluster.yaml": `api_lb_backends:
  - addr: "{{ interdc_nodes['node-a'].ip }}:6443"
    probe: true
`,
		"interdc_dns_zone.yaml": `internal:
  records:
    api: 10.0.1.10
`,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestDeriveMultiSite(t *testing.T) {
	dir := writeVars(t)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if !topo.Found || topo.MeshName != "b" {
		t.Fatalf("node lookup failed: %+v", topo)
	}
	if topo.Overlay != "nebula" {
		t.Fatalf("overlay=%s", topo.Overlay)
	}
	// marker octet override for node-b → .7
	if topo.Markers["b"] != "172.29.0.7" {
		t.Fatalf("marker b=%s", topo.Markers["b"])
	}
	// node-a/site s2? no — a is s1, b is s2 → targets = a.ip + relay 203.0.113.5
	// 203.0.113.5 relay is sites:[s1] — b (site s2) does not consume it.
	if len(topo.Targets) != 2 || topo.Targets[0] != "10.0.1.10" || topo.Targets[1] != "10.0.1.30" {
		t.Fatalf("targets=%v", topo.Targets)
	}
	if len(topo.EgressRelays) != 1 || topo.EgressRelays[0] != "198.51.100.9" {
		t.Fatalf("egress=%v", topo.EgressRelays)
	}
	if len(topo.EgressProbes) != 1 || topo.EgressProbes[0] != "198.51.100.9:9443" {
		t.Fatalf("egressProbes=%v", topo.EgressProbes)
	}
	if len(topo.ProbeMarkers) != 2 || topo.ProbeMarkers[0] != "172.29.0.10" || topo.ProbeMarkers[1] != "172.29.0.30" {
		t.Fatalf("probeMarkers=%v", topo.ProbeMarkers)
	}
	if len(topo.SiteMarkers) != 0 {
		t.Fatalf("siteMarkers=%v", topo.SiteMarkers)
	}
	// hub lighthouse: only node-a
	if len(topo.Lighthouses) != 1 || topo.Lighthouses[0].Name != "a" || topo.AmLighthouse {
		t.Fatalf("lighthouses=%+v", topo.Lighthouses)
	}
	// unsafe routes: b's targets routed via remote markers (a marker, b's own relays excluded via site check s1 match → relay included)
	if len(topo.UnsafeRoutes) == 0 {
		t.Fatal("no unsafe routes")
	}
	// cert subnets: own ip + self relays (/32)
	if len(topo.CertSubnets) != 2 {
		t.Fatalf("certSubnets=%v", topo.CertSubnets)
	}
	// DNS resolvers = own-site hubs = a marker
	if len(topo.DNSResolvers) != 1 || topo.DNSResolvers[0] != "172.29.0.10" {
		t.Fatalf("resolvers=%v", topo.DNSResolvers)
	}
	// fallback map: cp_endpoint + fallback name, ips sorted unique
	want := "api.example.internal:6443=10.0.1.10,172.29.0.10 api2.example.internal:6443=10.0.1.10,172.29.0.10"
	if topo.DNSFallbackMap != want {
		t.Fatalf("fallbackMap=%q want %q", topo.DNSFallbackMap, want)
	}
	// lazy jinja: cluster.yaml referencing interdc_nodes
	if got := topo.Vars.StrList("api_lb_backends"); len(got) != 0 {
		// it's a list of maps — check via List accessor instead
	}
	be := topo.Vars.List("api_lb_backends")
	if len(be) != 1 {
		t.Fatalf("api_lb_backends=%v", be)
	}
}

func TestMarkerDupAssert(t *testing.T) {
	dir := writeVars(t)
	// break uniqueness: node-a octet 7 collides with b.
	nodes := `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  marker_octet: 7
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  marker_octet: 7
`
	os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(topo.Errors) == 0 {
		t.Fatal("expected duplicate marker error")
	}
}

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

// Vars resolution is fail-closed: a broken jinja var returns
// Undefined (stringifies to "") and lands in Errors — previously the
// raw {{...}} text leaked into rendered config files.
func TestVarsResolveFailClosed(t *testing.T) {
	dir := writeVars(t)
	os.WriteFile(filepath.Join(dir, "cluster.yaml"),
		[]byte("broken: '{{ no_such_func(1) }}'\n"), 0o644)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := topo.Vars.Str("broken"); got != "" {
		t.Fatalf("broken var rendered as %q — must be Undefined", got)
	}
	found := false
	for _, e := range topo.Vars.Errors() {
		if strings.Contains(e, "broken") {
			found = true
		}
	}
	if !found {
		t.Fatalf("eval failure not recorded: %v", topo.Vars.Errors())
	}
}

// lookup() is fail-loud: unsupported plugins, missing terms and
// absent env hooks all error the render — never silently emit "".
func TestLookupFailLoud(t *testing.T) {
	cases := []string{
		"{{ lookup('env', 'HOME') }}",      // unsupported plugin
		"{{ lookup('file', 'x', 'y') }}",   // file kind, nil env
		"{{ lookup('file') }}",             // missing term
		"{{ lookup('pipe', 'date +%s') }}", // pipe kind, nil env
		"{{ lookup() }}",                   // no plugin name
	}
	for _, tpl := range cases {
		if out, err := Render(tpl, map[string]any{}, nil); err == nil {
			t.Fatalf("render %q succeeded with %q — must error", tpl, out)
		}
	}
	// Unsupported plugin errors even when an env is wired.
	env := NewEnv(t.TempDir(), nil)
	if _, err := Render("{{ lookup('url', 'http://x') }}", nil, env); err == nil {
		t.Fatal("unsupported plugin must error with env set")
	}
}

// lookup('file', ...) resolves via Env.FileLookup — here the
// vars-dir-rooted env Load/NewEnv build.
func TestLookupFileViaEnv(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s3cr3t\n"), 0o644)
	got, err := Render("{{ lookup('file', 'secret.txt') | trim }}",
		map[string]any{}, NewEnv(dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cr3t" {
		t.Fatalf("lookup file = %q", got)
	}
	// Missing file → render error (was silently "" when env was nil).
	if _, err := Render("{{ lookup('file', 'nope.txt') }}",
		map[string]any{}, NewEnv(dir, nil)); err == nil {
		t.Fatal("missing file must error")
	}
	// 'date +%s' pipe lookup honours the injected clock.
	got, err = Render("{{ lookup('pipe', 'date +%s') }}", map[string]any{},
		NewEnv(dir, func() time.Time { return time.Unix(123, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	if got != "123" {
		t.Fatalf("pipe date = %q", got)
	}
	// Any other pipe command errors.
	if _, err := Render("{{ lookup('pipe', 'rm -rf /') }}",
		map[string]any{}, NewEnv(dir, nil)); err == nil {
		t.Fatal("unsupported pipe command must error")
	}
}

// A vars-file value using lookup('file', ...) resolves against the
// vars dir through the env Load wires — end-to-end coverage.
func TestVarsFileLookup(t *testing.T) {
	dir := writeVars(t)
	os.WriteFile(filepath.Join(dir, "mesh_token"), []byte("tok-1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "cluster.yaml"),
		[]byte("token: \"{{ lookup('file', 'mesh_token') | trim }}\"\n"), 0o644)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := topo.Vars.Str("token"); got != "tok-1" {
		t.Fatalf("token=%q errors=%v", got, topo.Vars.Errors())
	}
}

func TestVarsCycleLogged(t *testing.T) {
	dir := writeVars(t)
	os.WriteFile(filepath.Join(dir, "cluster.yaml"),
		[]byte("a: '{{ b }}'\nb: '{{ a }}'\n"), 0o644)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	_ = topo.Vars.Str("a")
	found := false
	for _, e := range topo.Vars.Errors() {
		if strings.Contains(e, "cycle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reference cycle not recorded: %v", topo.Vars.Errors())
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

// A registry/zone value embedding jinja goes through resolve() now
// — extras used to bypass it entirely.
func TestRegistryValuesResolveJinja(t *testing.T) {
	dir := writeVars(t)
	nodes := `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  ip: "{{ node_b_ip }}"
  site: s2
`
	if err := os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644); err != nil {
		t.Fatal(err)
	}
	defaults, err := os.ReadFile(filepath.Join(dir, "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defaults = append(defaults, []byte("node_b_ip: 10.0.2.20\n")...)
	if err := os.WriteFile(filepath.Join(dir, "defaults.yaml"), defaults, 0o644); err != nil {
		t.Fatal(err)
	}
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	// Resolved registry ip → marker derives from last octet .20.
	if topo.Markers["b"] != "172.29.0.20" {
		t.Fatalf("marker b=%q errors=%v — registry jinja unresolved", topo.Markers["b"], topo.Errors)
	}
	if ip := mapStr(topo.Node, "ip"); ip != "10.0.2.20" {
		t.Fatalf("node ip=%q — registry jinja unresolved", ip)
	}
}

// An empty registry ip must not produce a literal "/32" cert
// subnet — it errors out naming the node.
func TestCertSubnetsSkipsEmptyIP(t *testing.T) {
	dir := writeVars(t)
	nodes := `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  site: s2
`
	if err := os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644); err != nil {
		t.Fatal(err)
	}
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range topo.CertSubnets {
		if s == "/32" || s == "" {
			t.Fatalf("certSubnets=%v — literal /32 from empty ip", topo.CertSubnets)
		}
	}
	found := false
	for _, e := range topo.Errors {
		if strings.Contains(e, "node-b") && strings.Contains(e, "ip") {
			found = true
		}
	}
	if !found {
		t.Fatalf("empty-ip node not reported: %v", topo.Errors)
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

// An empty relay ip must not mint a literal "/32" — same guard
// class as the empty registry ip (UnsafeRoutes + CertSubnets).
func TestRelayEmptyIPNoSlash32(t *testing.T) {
	dir := writeVars(t)
	writeNodes := func(s string) {
		if err := os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// SELF relay without ip → cert subnet skipped + error note.
	writeNodes(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  relay:
    - ip: 203.0.113.5
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  relay:
    - mode: always
`)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range topo.CertSubnets {
		if s == "/32" || s == "" {
			t.Fatalf("certSubnets=%v — literal /32 from empty relay ip", topo.CertSubnets)
		}
	}
	found := false
	for _, e := range topo.Errors {
		if strings.Contains(e, "relay") && strings.Contains(e, "cert SAN") {
			found = true
		}
	}
	if !found {
		t.Fatalf("empty self-relay ip not reported: %v", topo.Errors)
	}

	// REMOTE relay without ip (self has none, so selfwin[""] can't
	// pre-skip it) → unsafe route skipped + error note.
	writeNodes(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  relay:
    - mode: always
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
`)
	topo, err = Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range topo.UnsafeRoutes {
		if strings.HasPrefix(r.Route, "/") {
			t.Fatalf("unsafeRoutes=%v — literal /32 from empty relay ip", topo.UnsafeRoutes)
		}
	}
	found = false
	for _, e := range topo.Errors {
		if strings.Contains(e, "relay") && strings.Contains(e, "unsafe route") {
			found = true
		}
	}
	if !found {
		t.Fatalf("empty remote-relay ip not reported: %v", topo.Errors)
	}
}
