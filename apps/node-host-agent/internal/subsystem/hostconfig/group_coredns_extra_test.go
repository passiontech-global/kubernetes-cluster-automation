// group_coredns_extra_test.go — T9 coverage beyond the stub suite:
// zone-name fallback, tinc overlay unit wiring, hub fallback-resolver
// resolv.conf line, dig verify failure paths (worker + hub retry
// ctx-cancel), zone-file schema variants, mixed-shape registry
// entries, and the coredns tarball install failure.
package hostconfig

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
	"strings"
	"testing"
)

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
