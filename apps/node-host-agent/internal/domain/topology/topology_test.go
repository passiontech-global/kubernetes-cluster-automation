package topology

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
		if out, err := jinja.Render(tpl, map[string]any{}, nil); err == nil {
			t.Fatalf("render %q succeeded with %q — must error", tpl, out)
		}
	}
	// Unsupported plugin errors even when an env is wired.
	env := NewEnv(t.TempDir(), nil)
	if _, err := jinja.Render("{{ lookup('url', 'http://x') }}", nil, env); err == nil {
		t.Fatal("unsupported plugin must error with env set")
	}
}

// lookup('file', ...) resolves via jinja.Env.FileLookup — here the
// vars-dir-rooted env Load/NewEnv build.
func TestLookupFileViaEnv(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s3cr3t\n"), 0o644)
	got, err := jinja.Render("{{ lookup('file', 'secret.txt') | trim }}",
		map[string]any{}, NewEnv(dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cr3t" {
		t.Fatalf("lookup file = %q", got)
	}
	// Missing file → render error (was silently "" when env was nil).
	if _, err := jinja.Render("{{ lookup('file', 'nope.txt') }}",
		map[string]any{}, NewEnv(dir, nil)); err == nil {
		t.Fatal("missing file must error")
	}
	// 'date +%s' pipe lookup honours the injected clock.
	got, err = jinja.Render("{{ lookup('pipe', 'date +%s') }}", map[string]any{},
		NewEnv(dir, timex.NewCell(func() time.Time { return time.Unix(123, 0) })))
	if err != nil {
		t.Fatal(err)
	}
	if got != "123" {
		t.Fatalf("pipe date = %q", got)
	}
	// Any other pipe command errors.
	if _, err := jinja.Render("{{ lookup('pipe', 'rm -rf /') }}",
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
	if ip := topo.Node.Str("ip"); ip != "10.0.2.20" {
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

// Golden-shape test locking the full derive() output surface for a
// multi-site registry: legacy markers, relay map + per-entry modes/
// sites/weights, self relay ips + selfwin, site peers, probe
// targets/markers, slowpath markers (far_sites), DNS fallback +
// resolvers (own-site-first hub walk), lighthouses, unsafe routes,
// cert subnets and the T11 bw-audit target list.
func TestDeriveGoldenShape(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"interdc_nodes.yaml": `hub1:
  name: h1
  ip: 10.0.1.10
  site: s1
  hub: true
  relay_mode: always
  relay_sites: [s2]
  relay:
    - ip: 203.0.113.1
edge:
  name: e1
  ip: 10.0.2.20
  site: s2
  overlay: tinc
  relay:
    - ip: 203.0.113.1
      weight: 5
    - ip: 203.0.113.2
      mode: fallback
      probe: "9443"
hub2:
  name: h2
  ip: 10.0.3.30
  site: s1
  hub: true
peer1:
  name: p1
  ip: 10.0.2.40
  site: s2
`,
		"defaults.yaml": `interdc_nebula_enabled: true
interdc_marker_base: "172.29.0"
interdc_marker_base_legacy: "172.30.0"
interdc_far_sites: [s3]
cp_endpoint: api.x
`,
	}
	files["cluster.yaml"] = "placeholder: true\n"
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	topo, err := Load(Config{VarsDir: dir, NodeName: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	if topo.Overlay != "tinc" || !topo.Found || topo.MeshName != "e1" {
		t.Fatalf("identity: overlay=%s found=%v mesh=%s", topo.Overlay, topo.Found, topo.MeshName)
	}
	wantMarkers := map[string]string{
		"h1": "172.29.0.10", "e1": "172.29.0.20", "h2": "172.29.0.30", "p1": "172.29.0.40",
	}
	for n, m := range wantMarkers {
		if topo.Markers[n] != m {
			t.Fatalf("marker %s=%s want %s", n, topo.Markers[n], m)
		}
	}
	wantLegacy := map[string]string{
		"h1": "172.30.0.10", "e1": "172.30.0.20", "h2": "172.30.0.30", "p1": "172.30.0.40",
	}
	for n, m := range wantLegacy {
		if topo.MarkersLegacy[n] != m {
			t.Fatalf("legacy marker %s=%s want %s", n, topo.MarkersLegacy[n], m)
		}
	}
	if len(topo.RelayMap["h1"]) != 1 {
		t.Fatalf("h1 relays=%+v", topo.RelayMap["h1"])
	}
	r := topo.RelayMap["h1"][0]
	if r.IP != "203.0.113.1" || r.Mode != "always" || len(r.Sites) != 1 || r.Sites[0] != "s2" || r.Weight != 0 {
		t.Fatalf("h1 relay=%+v — node-level defaults not applied", r)
	}
	if len(topo.RelayMap["e1"]) != 2 || topo.RelayMap["e1"][1].Mode != "fallback" ||
		topo.RelayMap["e1"][1].Probe != "9443" {
		t.Fatalf("e1 relays=%+v", topo.RelayMap["e1"])
	}
	if len(topo.SelfRelayIPs) != 2 || topo.SelfRelayIPs[0] != "203.0.113.1" {
		t.Fatalf("selfRelayIPs=%v", topo.SelfRelayIPs)
	}
	// e1's weight-5 beats h1's unset (10) on 203.0.113.1; .2 is e1-only.
	if len(topo.SelfWinRelays) != 2 || topo.SelfWinRelays[0] != "203.0.113.1" ||
		topo.SelfWinRelays[1] != "203.0.113.2" {
		t.Fatalf("selfWinRelays=%v", topo.SelfWinRelays)
	}
	if len(topo.SitePeers) != 1 || topo.SitePeers[0] != "p1" {
		t.Fatalf("sitePeers=%v", topo.SitePeers)
	}
	wantTargets := []string{"10.0.1.10", "10.0.3.30"}
	for i, w := range wantTargets {
		if len(topo.Targets) != len(wantTargets) || topo.Targets[i] != w {
			t.Fatalf("targets=%v want %v", topo.Targets, wantTargets)
		}
		if topo.ProbeTargets[i] != w {
			t.Fatalf("probeTargets=%v want %v", topo.ProbeTargets, wantTargets)
		}
	}
	// h1's always-relay .1 is a target candidate but selfwin excludes it;
	// no remote fallback relays → empty egress.
	if len(topo.EgressRelays) != 0 || len(topo.EgressProbes) != 0 {
		t.Fatalf("egress=%v probes=%v", topo.EgressRelays, topo.EgressProbes)
	}
	if len(topo.ProbeMarkers) != 2 || topo.ProbeMarkers[0] != "172.29.0.10" ||
		topo.ProbeMarkers[1] != "172.29.0.30" {
		t.Fatalf("probeMarkers=%v", topo.ProbeMarkers)
	}
	// s2 is not a far site and neither remote site s1 is → both slow.
	if len(topo.SlowpathMkrs) != 2 || topo.SlowpathMkrs[1] != "172.29.0.30" {
		t.Fatalf("slowpathMkrs=%v", topo.SlowpathMkrs)
	}
	if len(topo.SiteMarkers) != 1 || topo.SiteMarkers[0] != "172.29.0.40" {
		t.Fatalf("siteMarkers=%v", topo.SiteMarkers)
	}
	// No own-site hubs → fallback ips come from the other-site pass only.
	want := "api.x:6443=10.0.1.10,10.0.3.30,172.29.0.10,172.29.0.30"
	if topo.DNSFallbackMap != want {
		t.Fatalf("fallbackMap=%q want %q", topo.DNSFallbackMap, want)
	}
	if len(topo.DNSResolvers) != 2 || topo.DNSResolvers[0] != "172.29.0.10" ||
		topo.DNSResolvers[1] != "172.29.0.30" {
		t.Fatalf("resolvers=%v", topo.DNSResolvers)
	}
	if len(topo.Lighthouses) != 2 || topo.Lighthouses[0].Name != "h1" ||
		topo.Lighthouses[1].Marker != "172.29.0.30" || topo.AmLighthouse {
		t.Fatalf("lighthouses=%+v am=%v", topo.Lighthouses, topo.AmLighthouse)
	}
	wantRoutes := []UnsafeRoute{
		{"10.0.1.10/32", "172.29.0.10", 100},
		{"10.0.3.30/32", "172.29.0.30", 100},
	}
	if len(topo.UnsafeRoutes) != 2 || topo.UnsafeRoutes[0] != wantRoutes[0] ||
		topo.UnsafeRoutes[1] != wantRoutes[1] {
		t.Fatalf("unsafeRoutes=%+v — h1's selfwin relay must be excluded", topo.UnsafeRoutes)
	}
	wantSubnets := []string{"10.0.2.20/32", "203.0.113.1/32", "203.0.113.2/32"}
	if len(topo.CertSubnets) != 3 {
		t.Fatalf("certSubnets=%v want %v", topo.CertSubnets, wantSubnets)
	}
	for i, s := range wantSubnets {
		if topo.CertSubnets[i] != s {
			t.Fatalf("certSubnets=%v want %v", topo.CertSubnets, wantSubnets)
		}
	}
	wantAudit := []AuditTarget{
		{"h1", "10.0.1.10"}, {"h1-marker", "172.29.0.10"},
		{"relay-203.0.113.1", "203.0.113.1"},
		{"h2", "10.0.3.30"}, {"h2-marker", "172.29.0.30"},
		{"p1", "10.0.2.40"}, {"p1-marker", "172.29.0.40"},
	}
	if len(topo.BwAuditTargets) != len(wantAudit) {
		t.Fatalf("bwAudit=%+v want %+v", topo.BwAuditTargets, wantAudit)
	}
	for i, a := range wantAudit {
		if topo.BwAuditTargets[i] != a {
			t.Fatalf("bwAudit[%d]=%+v want %+v", i, topo.BwAuditTargets[i], a)
		}
	}
	if len(topo.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", topo.Errors)
	}
}

// TestDeriveAmLighthouseAndRelayMetric pins the two derive surfaces
// the golden fixture can't see from a non-hub self node: the self
// node's "hub" flag (AmLighthouse — nebula derive parity: hub IS the
// am-lighthouse decision) and the unsafe-route METRIC of a remote
// relay (explicit weight beats the default 10).
func TestDeriveAmLighthouseAndRelayMetric(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"interdc_nodes.yaml": `hub1:
  name: h1
  ip: 10.0.1.10
  site: s1
  hub: true
  relay_mode: always
  relay:
    - ip: 198.51.100.7
hub2:
  name: h2
  ip: 10.0.3.30
  site: s3
  hub: true
  relay_mode: always
  relay:
    - ip: 198.51.100.9
      weight: 7
edge:
  name: e1
  ip: 10.0.2.20
  site: s2
`,
		"defaults.yaml": `interdc_nebula_enabled: true
interdc_marker_base: "172.29.0"
cp_endpoint: api.x
`,
	}
	files["cluster.yaml"] = "placeholder: true\n"
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Self = hub: AmLighthouse true; the OTHER hub's relay keeps its
	// explicit weight 7 on the unsafe-route metric (its own relay is
	// self and excluded, h1's is selfwin).
	topo, err := Load(Config{VarsDir: dir, NodeName: "hub1"})
	if err != nil {
		t.Fatal(err)
	}
	if !topo.AmLighthouse {
		t.Fatal("hub self node did not set AmLighthouse")
	}
	wantRelay := UnsafeRoute{"198.51.100.9/32", "172.29.0.30", 7}
	found := false
	for _, r := range topo.UnsafeRoutes {
		if r == wantRelay {
			found = true
		}
	}
	if !found {
		t.Fatalf("unsafeRoutes=%+v — want explicit relay weight %v", topo.UnsafeRoutes, wantRelay)
	}
	// Self = edge: not a hub; the default-10 relay weight shows on the
	// same metric path.
	edge, err := Load(Config{VarsDir: dir, NodeName: "edge"})
	if err != nil {
		t.Fatal(err)
	}
	if edge.AmLighthouse {
		t.Fatal("non-hub self node set AmLighthouse")
	}
	wantDefault := UnsafeRoute{"198.51.100.7/32", "172.29.0.10", 10}
	found = false
	for _, r := range edge.UnsafeRoutes {
		if r == wantDefault {
			found = true
		}
	}
	if !found {
		t.Fatalf("edge unsafeRoutes=%+v — want default relay weight %v", edge.UnsafeRoutes, wantDefault)
	}
}

// Nebula protocol relay (>=1.6): nebula_am_relay flags the node as a
// relay; nebula_relays lists mesh names resolved to marker VPN IPs.
// Misconfigurations (self-listing, missing registry entry, target
// without am_relay, relay node listing relays) land in Errors.
func TestDeriveNebulaRelays(t *testing.T) {
	dir := writeVars(t)
	nodes := `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  nebula_am_relay: true
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  nebula_relays: [a, ghost]
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`
	_ = os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644)

	// spoke: resolves a's marker, skips the unknown "ghost" entry.
	topo, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if topo.AmRelay {
		t.Fatal("spoke node-b flagged AmRelay")
	}
	if len(topo.NebulaRelayIPs) != 1 || topo.NebulaRelayIPs[0] != "172.29.0.10" {
		t.Fatalf("relayIPs=%v", topo.NebulaRelayIPs)
	}
	found := false
	for _, e := range topo.Errors {
		if strings.Contains(e, `"ghost"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown relay entry not recorded: %v", topo.Errors)
	}

	// relay node: flag set, no relays of its own.
	relay, err := Load(Config{VarsDir: dir, NodeName: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !relay.AmRelay {
		t.Fatal("hub node-a missing AmRelay")
	}
	if len(relay.NebulaRelayIPs) != 0 {
		t.Fatalf("relay node leaked relayIPs=%v", relay.NebulaRelayIPs)
	}
}

// A relay target without nebula_am_relay and an am_relay node that
// lists relays are both registry errors.
func TestDeriveNebulaRelaysInvalid(t *testing.T) {
	dir := writeVars(t)
	nodes := `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  nebula_am_relay: true
  nebula_relays: [b]
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  nebula_relays: [c]
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`
	_ = os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"), []byte(nodes), 0o644)

	topo, err := Load(Config{VarsDir: dir, NodeName: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range topo.Errors {
		if strings.Contains(e, "relay-to-relay") {
			found = true
		}
	}
	if !found {
		t.Fatalf("am_relay+relays conflict not recorded: %v", topo.Errors)
	}

	spoke, err := Load(Config{VarsDir: dir, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(spoke.NebulaRelayIPs) != 0 {
		t.Fatalf("non-am_relay target resolved: %v", spoke.NebulaRelayIPs)
	}
	found = false
	for _, e := range spoke.Errors {
		if strings.Contains(e, "lacks nebula_am_relay") {
			found = true
		}
	}
	if !found {
		t.Fatalf("non-am_relay target not recorded: %v", spoke.Errors)
	}
}
