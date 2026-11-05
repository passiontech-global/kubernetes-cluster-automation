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
	// lazy jinja: cluster.yaml referencing interdc_nodes — the list
	// holds maps, so it must come through the List accessor.
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
	_ = os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644)
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(topo.Errors) == 0 {
		t.Fatal("expected duplicate marker error")
	}
}

// Vars resolution is fail-closed: a broken jinja var returns
// Undefined (stringifies to "") and lands in Errors — previously the
// raw {{...}} text leaked into rendered config files.
func TestVarsResolveFailClosed(t *testing.T) {
	dir := writeVars(t)
	_ = os.WriteFile(filepath.Join(dir, "cluster.yaml"),
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
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s3cr3t\n"), 0o644)
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
	_ = os.WriteFile(filepath.Join(dir, "mesh_token"), []byte("tok-1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "cluster.yaml"),
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
	_ = os.WriteFile(filepath.Join(dir, "cluster.yaml"),
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
