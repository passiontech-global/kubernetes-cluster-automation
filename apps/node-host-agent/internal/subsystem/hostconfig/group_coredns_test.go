// group_coredns_test.go — groupCoreDNS: worker stub Corefile,
// hub zone file + /etc/hosts zone pins, resolv.conf repoint
// gating, and the version-pin install path.
package hostconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// ---------- #6: worker stub Corefile vs ansible ----------

func TestCoreDNSWorkerStub(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
		"dig @127.0.0.1":                  "10.0.1.10",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()

	want := `# Managed by node-config-agent (T9) - local stub, domain-aware
# routing: test.internal -> mesh resolvers; "." -> public
# upstreams, then the mesh (rescue via tinc).
test.internal {
    bind 127.0.0.1
    forward . 172.29.0.10 {
        policy sequential
        health_check 10s
    }
    errors
}
. {
    bind 127.0.0.1
    forward . 1.1.1.1 8.8.8.8 172.29.0.10 {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`
	got := hostRead(t, r, "/etc/coredns/Corefile")
	if got != want {
		t.Fatalf("Corefile mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	rc := hostRead(t, r, "/etc/resolv.conf")
	if !strings.Contains(rc, "nameserver 127.0.0.1\nnameserver 1.1.1.1\nnameserver 172.29.0.10\noptions timeout:2 attempts:2") {
		t.Fatalf("resolv.conf not repointed per ansible:\n%s", rc)
	}
	unit := hostRead(t, r, "/etc/systemd/system/coredns.service")
	if !strings.Contains(unit, "After=network-online.target nebula@interdc.service") ||
		!strings.Contains(unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Fatalf("bad coredns unit:\n%s", unit)
	}
}

// TestCoreDNSInjectionFailsClosed: a quote/newline in an upstream,
// marker or resolver value would inject arbitrary Corefile
// directives (bind/forward interpolate the scalars verbatim). The
// group must fail CLOSED — counted error, warn, no Corefile/unit/
// resolv.conf write.
func TestCoreDNSInjectionFailsClosed(t *testing.T) {
	for name, poisoned := range map[string]string{
		"quote":   `interdc_stub_public_upstream: '1.1.1.1"; bad'`,
		"newline": "interdc_stub_public_upstream: |-\n  1.1.1.1\n  9.9.9.9",
	} {
		t.Run(name, func(t *testing.T) {
			vars := writeVarsDir(t, "")
			poisonVars(t, vars, poisoned)
			sr := newScripted(map[string]string{
				"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
			}, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				DownloadDir: t.TempDir()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			c.groupCoreDNS()
			if hostExists(r, "/etc/coredns/Corefile") {
				t.Fatalf("Corefile written despite refused %s value", name)
			}
			if c.errs == 0 {
				t.Fatal("refused value not counted as a cycle error")
			}
		})
	}
}

func TestCoreDNSSkipsResolvConfWhenDigFails(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{"/usr/local/bin/coredns -version": "CoreDNS-1.14.7"}, map[string]bool{"dig @127.0.0.1": true})
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/resolv.conf", "nameserver 8.8.8.8\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	if got := hostRead(t, r, "/etc/resolv.conf"); got != "nameserver 8.8.8.8\n" {
		t.Fatalf("resolv.conf repointed despite dig failure:\n%s", got)
	}
}

// ---------- #11: hub zone file + hosts pins ----------

func TestCoreDNSHubZoneFile(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
		"dig @127.0.0.1":                  "172.29.0.10",
	}, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-a")
	if !c.t.AmLighthouse {
		t.Fatal("node-a should be a hub")
	}
	c.groupCoreDNS()

	zf := hostRead(t, r, "/etc/coredns/db.test.internal")
	for _, want := range []string{
		"$TTL 60\n",
		"@   IN SOA ns1.test.internal. admin.test.internal. (\n",
		"    IN NS ns1.test.internal.\n",
		"api                            IN A 203.0.113.14",
		"db                             IN A 172.29.0.10", // node ref -> marker
		"a.node                         IN A 172.29.0.10",
		"b.node                         IN A 172.29.0.20",
		"c.node                         IN A 172.29.0.30",
	} {
		if !strings.Contains(zf, want) {
			t.Fatalf("zone file missing %q:\n%s", want, zf)
		}
	}
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "# BEGIN interdc-zone-pins managed block") ||
		!strings.Contains(hosts, "203.0.113.14 api.test.internal") ||
		!strings.Contains(hosts, "172.29.0.10 a.node.test.internal") {
		t.Fatalf("zone pins missing from /etc/hosts:\n%s", hosts)
	}
	rc := hostRead(t, r, "/etc/resolv.conf")
	if !strings.Contains(rc, "nameserver 127.0.0.1\nnameserver 1.1.1.1") {
		t.Fatalf("hub resolv.conf wrong:\n%s", rc)
	}
	// own marker is the only resolver -> excluded from "other" fallbacks
	if strings.Contains(rc, "nameserver 172.29.0.10") {
		t.Fatalf("hub should not fall back to its own marker:\n%s", rc)
	}
	corefile := hostRead(t, r, "/etc/coredns/Corefile")
	if !strings.Contains(corefile, "bind 172.29.0.10 127.0.0.1") ||
		!strings.Contains(corefile, "file /etc/coredns/db.test.internal") {
		t.Fatalf("bad hub Corefile:\n%s", corefile)
	}
}

// TestRenderZoneFileSkipsMarkerlessHub — a hub with no registry
// marker must not render `nsN IN A ` (empty rdata coredns rejects).
func TestRenderZoneFileSkipsMarkerlessHub(t *testing.T) {
	vars := writeVarsDir(t, "")
	if err := os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-z:
  name: z
  site: s1
  hub: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	zb, err := c.renderZoneFile()
	if err != nil {
		t.Fatal(err)
	}
	z := string(zb)
	if strings.Contains(z, "ns2") {
		t.Fatalf("markerless hub rendered NS records:\n%s", z)
	}
	if regexp.MustCompile(`IN A\s*\n`).MatchString(z) {
		t.Fatalf("empty A rdata rendered:\n%s", z)
	}
	if !strings.Contains(z, "IN NS ns1.test.internal.") ||
		!strings.Contains(z, "IN A 172.29.0.10") {
		t.Fatalf("marker hub records missing:\n%s", z)
	}
}

// TestCoreDNSBinarySwapRestartsService — same contract as nebula:
// a version-pin binary install must restart coredns.service even
// when the Corefile is unchanged. Phase A seeds with the probe at
// the pin; phase B flips it stale and serves a tarball.
func TestCoreDNSBinarySwapRestartsService(t *testing.T) {
	url, sum := tarballServer(t, map[string]string{
		"coredns": "#!/bin/sh\n# fake coredns\n",
	})
	vars := writeVarsDir(t, "")
	dp := filepath.Join(vars, "defaults.yaml")
	db, err := os.ReadFile(dp)
	if err != nil {
		t.Fatal(err)
	}
	db = []byte(strings.ReplaceAll(string(db),
		`interdc_coredns_url: "https://example/coredns.tgz"`,
		fmt.Sprintf(`interdc_coredns_url: "%s"`, url)))
	db = []byte(strings.ReplaceAll(string(db),
		`interdc_coredns_sha256: "deadbeef"`,
		fmt.Sprintf(`interdc_coredns_sha256: "%s"`, sum)))
	if err := os.WriteFile(dp, db, 0o644); err != nil {
		t.Fatal(err)
	}
	hostRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostRoot, "usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	dl := t.TempDir()

	srA := newScripted(map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
		"dig @127.0.0.1":                  "10.0.1.10",
	}, nil)
	rA, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, Runner: srA, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cA := loadCyc(t, rA, vars, "node-b")
	cA.groupCoreDNS()
	if !hostExists(rA, "/etc/coredns/Corefile") {
		t.Fatal("phase A did not seed the Corefile")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("phase A downloaded despite the pin matching")
	}

	srB := newScripted(map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-1.13.0",
		"dig @127.0.0.1":                  "10.0.1.10",
	}, nil)
	rB, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, Runner: srB, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cB := loadCyc(t, rB, vars, "node-b")
	cB.groupCoreDNS()
	if !hostExists(rB, "/usr/local/bin/coredns") {
		t.Fatal("coredns binary not installed under HostRoot")
	}
	if len(srB.CallsMatching("systemctl restart coredns.service")) == 0 {
		t.Fatalf("binary swap did not restart coredns.service: %v", srB.Calls())
	}
}

// TestCoreDNSEmptyVersionPinSkips — same contract for coredns.
func TestCoreDNSEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_coredns_version: \"\"\n")
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-9.9.9",
	}, nil)
	dl := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.corednsInstallBinary()
	if c.errs == 0 {
		t.Fatal("unpinned coredns install not counted")
	}
	if len(sr.CallsMatching("coredns -version")) > 0 {
		t.Fatal("version probe ran on an empty pin")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("download attempted without a version pin")
	}
}

// TestCoreDNSZoneNameFallback — no zone: key in interdc_dns_zone.yaml
// falls back to the ansible default zone.
func TestCoreDNSZoneNameFallback(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_dns_zone.yaml", "ttl: 60\nrecords: {}\n")
	sr := newScripted(map[string]string{
		"dig @127.0.0.1": "10.0.1.10",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if got := c.zoneName(); got != "passiontech.internal" {
		t.Fatalf("zoneName = %q, want the ansible default", got)
	}
}

// TestCoreDNSTincOverlayUnit — a tinc overlay moves the stub unit's
// After= off nebula onto tinc@.
func TestCoreDNSTincOverlayUnit(t *testing.T) {
	vars := writeVarsDir(t, "interdc_overlay_default: tinc\n")
	sr := newScripted(map[string]string{
		"dig @127.0.0.1": "10.0.1.10",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	unit := hostRead(t, r, "/etc/systemd/system/coredns.service")
	if !strings.Contains(unit, "After=network-online.target tinc@interdc.service") {
		t.Fatalf("stub unit not wired after tinc@interdc:\n%s", unit)
	}
	if strings.Contains(unit, "nebula@") {
		t.Fatalf("nebula ordering left on a tinc overlay:\n%s", unit)
	}
}

// TestCoreDNSHubFallbackResolverLine — a hub's static resolv.conf
// lists 127.0.0.1 first and ONE other hub's marker as the die-tired
// fallback resolver.
func TestCoreDNSHubFallbackResolverLine(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", twoHubNodes)
	sr := newScripted(map[string]string{
		"dig @127.0.0.1": "172.29.0.10",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	rc := hostRead(t, r, "/etc/resolv.conf")
	if !strings.Contains(rc, "nameserver 127.0.0.1") {
		t.Fatalf("hub resolv.conf missing the local stub:\n%s", rc)
	}
	if !strings.Contains(rc, "nameserver 172.29.0.10") {
		t.Fatalf("hub resolv.conf missing the OTHER hub's fallback marker:\n%s", rc)
	}
	if !hostExists(r, "/etc/coredns/db.test.internal") {
		t.Fatal("hub zone file not rendered")
	}
}

// TestCoreDNSWorkerFallbackNameProbeFails — the stub answers the
// cluster name but fails external recursion: resolv.conf must NOT
// repoint, and the failure counts.
func TestCoreDNSWorkerFallbackNameProbeFails(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"dig @127.0.0.1 api.test.internal": "203.0.113.14",
	}, nil)
	sr.FailOn("dig @127.0.0.1 api2.test.internal", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	if hostExists(r, "/etc/resolv.conf") {
		t.Fatal("resolv.conf written although the external-recursion probe failed")
	}
	if c.errs == 0 {
		t.Fatal("failed fallback-name probe did not count a cycle error")
	}
}

// TestCoreDNSHubDigRetryCtxCancel — a canceled context exits the
// hub's dig-until loop through the ctx.Done arm instead of hammering
// all 15 retries.
func TestCoreDNSHubDigRetryCtxCancel(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.ctx = ctx
	c.groupCoreDNS()
	if hostExists(r, "/etc/resolv.conf") {
		t.Fatal("resolv.conf repointed although the resolver never answered")
	}
	if c.errs == 0 {
		t.Fatal("dead resolver did not count a cycle error")
	}
}

// TestCoreDNSZoneFileVariants — zone-schema corners of the hub
// render: an explicit node_records: false suppresses the node-record
// section, a non-mapping records block and a scalar record entry are
// skipped without breaking the SOA/NS render, a registry holding
// scalar/list node entries neither panics nor poisons the pins, and a
// zone file WITHOUT the key defaults node records on.
func TestCoreDNSZoneFileVariants(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c: gateway-vm
node-d: [relay-a, relay-b]
`)
	patchVarsFile(t, vars, "interdc_dns_zone.yaml", `zone: test.internal
ttl: 60
records:
  api:
    ip: "203.0.113.14"
  db:
    node: node-a
  broken: just-a-string
node_records: false
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	zb, err := c.renderZoneFile()
	if err != nil {
		t.Fatalf("renderZoneFile: %v", err)
	}
	z := string(zb)
	for _, want := range []string{"SOA", "api", "203.0.113.14", "172.29.0.10"} {
		if !strings.Contains(z, want) {
			t.Fatalf("zone file missing %q:\n%s", want, z)
		}
	}
	// The literal header comment carries ".node." — assert on the
	// actual record form instead.
	if strings.Contains(z, "a.node") {
		t.Fatalf("node records rendered despite node_records: false:\n%s", z)
	}
	// Absent key → ansible default(true): node records render. The
	// zone is decoded at load time — re-load after patching the file.
	patchVarsFile(t, vars, "interdc_dns_zone.yaml", "zone: test.internal\nttl: 60\nrecords: {}\n")
	c = loadCyc(t, r, vars, "node-a")
	zb2, err := c.renderZoneFile()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zb2), "a.node") {
		t.Fatalf("node records missing by default:\n%s", zb2)
	}
	// pinZoneRecords tolerates the same mixed registry shapes.
	c.pinZoneRecords(c.zoneName())
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "BEGIN interdc-zone-pins managed block") {
		t.Fatalf("zone pins block missing:\n%s", hosts)
	}
	if c.errs != 0 {
		t.Fatalf("mixed-shape registry counted errors: %v", c.t.Errors)
	}
}

// TestCoreDNSInstallBadTarball — a served tarball without the
// `coredns` member fails the extraction with a counted error and
// installs nothing.
func TestCoreDNSInstallBadTarball(t *testing.T) {
	url, sum := tarballServer(t, map[string]string{"other": "#!/bin/sh\n"})
	cluster := fmt.Sprintf("interdc_coredns_url: %q\ninterdc_coredns_sha256: %q\n", url, sum)
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
		DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	if hostExists(r, "/usr/local/bin/coredns") {
		t.Fatal("coredns installed from a tarball without the member")
	}
	if c.errs == 0 {
		t.Fatal("failed coredns extraction did not count a cycle error")
	}
}

// jsonPlain flattens OMap/List into plain Go maps/slices for the
// zone-serial hash — a bare []any input (e.g. a decoded YAML list
// that never went through the jinja boxing) hits the same recursion.
func TestJSONPlainFlattens(t *testing.T) {
	inner := jinja.NewOMap()
	inner.Set("z", 1)
	om := jinja.NewOMap()
	om.Set("b", inner)
	om.Set("a", &jinja.List{V: []any{3, "x"}})

	got := jsonPlain(om).(map[string]any)
	if got["b"].(map[string]any)["z"] != 1 {
		t.Fatalf("nested OMap not flattened: %v", got)
	}
	if l := got["a"].([]any); l[0] != 3 || l[1] != "x" {
		t.Fatalf("List not flattened: %v", l)
	}

	// Plain []any — the untested branch: elements are still
	// recursively flattened.
	out := jsonPlain([]any{inner, "s"}).([]any)
	if out[0].(map[string]any)["z"] != 1 || out[1] != "s" {
		t.Fatalf("[]any input not flattened: %v", out)
	}
}
