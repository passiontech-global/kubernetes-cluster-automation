package topology

import (
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
