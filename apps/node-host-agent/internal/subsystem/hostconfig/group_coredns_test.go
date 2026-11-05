// group_coredns_test.go — groupCoreDNS: worker stub Corefile,
// hub zone file + /etc/hosts zone pins, resolv.conf repoint
// gating, and the version-pin install path.
package hostconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------- #6: worker stub Corefile vs ansible ----------

func TestCoreDNSWorkerStub(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res: map[string]string{
			"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
			"dig @127.0.0.1":                  "10.0.1.10",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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

func TestCoreDNSSkipsResolvConfWhenDigFails(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res:  map[string]string{"/usr/local/bin/coredns -version": "CoreDNS-1.14.7"},
		errs: map[string]bool{"dig @127.0.0.1": true},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	sr := &scriptedRunner{
		res: map[string]string{
			"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
			"dig @127.0.0.1":                  "172.29.0.10",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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

// TestCoreDNSEmptyVersionPinSkips — same contract for coredns.
func TestCoreDNSEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_coredns_version: \"\"\n")
	sr := &scriptedRunner{res: map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-9.9.9",
	}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.corednsInstallBinary()
	if c.errs == 0 {
		t.Fatal("unpinned coredns install not counted")
	}
	if len(sr.callsMatching("coredns -version")) > 0 {
		t.Fatal("version probe ran on an empty pin")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("download attempted without a version pin")
	}
}
