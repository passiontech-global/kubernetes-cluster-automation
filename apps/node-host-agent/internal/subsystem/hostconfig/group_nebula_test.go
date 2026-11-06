// group_nebula_test.go — nebula mesh converge: restart-vs-
// reload decision, hairpin route prune, version-pin install,
// routing var charset gating, and the disable-path cleanup.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- hub hairpin route prune ----------

func TestHairpinPruneOnlyOnLighthouse(t *testing.T) {
	vars := writeVarsDir(t, "")
	// node-a (hub, site s1): only cross-site target is node-b 10.0.2.20;
	// route get says it resolves via node-c's public IP => prune.
	sr := &scriptedRunner{res: map[string]string{
		"ip -o route get 10.0.2.20 mark 0x1000": "10.0.2.20 via 10.0.1.30 dev eth0 src 10.0.1.10 mark 0x1000",
	}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	if !c.t.AmLighthouse {
		t.Fatal("node-a should be a lighthouse")
	}
	c.nebulaRouting()
	if len(sr.callsMatching("ip -o route get 10.0.2.20 mark 0x1000")) == 0 {
		t.Fatal("route get not issued for target")
	}
	if len(sr.callsMatching("ip route del 10.0.2.20/32 table main")) == 0 {
		t.Fatalf("hairpin route not pruned: %v", sr.callsMatching("route del"))
	}

	// non-lighthouse node: no hairpin probing at all
	sr2 := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.nebulaRouting()
	if len(sr2.callsMatching("route get")) > 0 {
		t.Fatalf("hairpin probe ran on non-lighthouse: %v", sr2.callsMatching("route get"))
	}
}

// ---------- nebula restart-vs-reload decision ----------

func TestNebulaNeedsRestartDecision(t *testing.T) {
	c := &cyc{}
	base := `pki:
  ca: /etc/nebula/interdc/ca.crt
  cert: /etc/nebula/interdc/host.crt
  key: /etc/nebula/interdc/host.key
static_host_map:
  "172.29.0.10": ["10.0.1.10:4242"]
lighthouse:
  am_lighthouse: false
  hosts: ["172.29.0.10"]
tun:
  dev: neb1
  mtu: 1300
  unsafe_routes:
    - route: 10.99.0.0/24
      via: 172.29.0.10
listen:
  host: 0.0.0.0
  port: 45670
firewall:
  outbound:
    - port: any
      proto: any
      host: any
`
	rep := func(old, new string) string {
		return strings.Replace(base, old, new, 1)
	}
	for _, tc := range []struct {
		name string
		old  string
		new  string
		want bool
	}{
		{"identical", base, base, false},
		// SIGHUP-reloadable surfaces — reload only.
		{"firewall rule change", base,
			rep("- port: any\n      proto: any\n      host: any", "- port: 443\n      proto: tcp\n      host: any"), false},
		{"lighthouse.hosts change", base,
			rep(`hosts: ["172.29.0.10"]`, `hosts: ["172.29.0.10", "172.29.0.20"]`), false},
		{"tun.unsafe_routes change", base,
			rep("route: 10.99.0.0/24", "route: 10.98.0.0/24"), false},
		{"top-level key reorder",
			`firewall:
  outbound:
    - port: any
      proto: any
      host: any
` + base[:strings.Index(base, "firewall:")], base, false},
		// Non-reloadable surfaces — full restart.
		{"tun.mtu change", base, rep("mtu: 1300", "mtu: 1400"), true},
		{"tun.dev change", base, rep("dev: neb1", "dev: neb2"), true},
		{"listen.port change", base, rep("port: 45670", "port: 45671"), true},
		{"static_host_map change", base, rep("10.0.1.10:4242", "10.0.1.11:4242"), true},
		{"pki path change", base, rep("interdc/host.key", "interdc/host2.key"), true},
		{"am_lighthouse flip", base, rep("am_lighthouse: false", "am_lighthouse: true"), true},
		{"unparseable new config", base, "{", true},
		{"unparseable old config", "{", base, true},
		{"empty old config (first install)", "", base, true},
	} {
		if got := c.nebulaNeedsRestart([]byte(tc.old), []byte(tc.new)); got != tc.want {
			t.Errorf("%s: needsRestart=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestNebulaEmptyVersionPinSkips — an empty version pin is "not
// pinned": log+skip, never a vacuous version match, never download("").
func TestNebulaEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_version: \"\"\n")
	sr := &scriptedRunner{res: map[string]string{
		"/usr/local/bin/nebula -version": "nebula version 9.9.9",
	}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaInstallBinary()
	if c.errs == 0 {
		t.Fatal("unpinned nebula install not counted")
	}
	if len(sr.callsMatching("nebula -version")) > 0 {
		t.Fatal("version probe ran on an empty pin")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("download attempted without a version pin")
	}
}

// TestNebulaRoutingRefusesBadVar — a var carrying shell metachars
// must abort the routing converge before any sh -c is built.
func TestNebulaRoutingRefusesBadVar(t *testing.T) {
	vars := writeVarsDir(t, `interdc_marker_base: "172.29.0;rm -rf /"`)
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if c.errs == 0 {
		t.Fatal("injected var not counted")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with injected marker_base: %v", sr.callsMatching("sh -c"))
	}
}

// ---------- required-slot empty values ----------

// TestNebulaRoutingEmptyRequiredIPCounted — node-b has no ip, so the
// REQUIRED pub/marker slots resolve "". Empty cannot inject, but it
// emits `src <blank>`/`snat to <blank>` that only fail inside sh -c
// at Debug level — the *Req gates must count it instead.
func TestNebulaRoutingEmptyRequiredIPCounted(t *testing.T) {
	vars := writeVarsDir(t, "")
	if err := os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  site: s2
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if c.errs == 0 {
		t.Fatal("empty required ip not counted")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with an empty required ip: %v", sr.callsMatching("sh -c"))
	}
}

// ---------- groupNebula disable path ----------

// TestNebulaDisableRunsUnconditionalCleanup — a charset-refused var
// must only skip the INTERPOLATED sweep; the non-interpolated
// systemctl disable cleanup still runs.
func TestNebulaDisableRunsUnconditionalCleanup(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\ninterdc_marker_base: \"172.29.0;rm -rf /\"\n")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if len(sr.callsMatching("systemctl disable --now nebula@interdc.service")) == 0 {
		t.Fatal("nebula unit not disabled on the gate-refused path")
	}
	if len(sr.callsMatching("systemctl disable --now nebula-route-guard.service")) == 0 {
		t.Fatal("route-guard not disabled on the gate-refused path")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("interpolated sweep ran with a refused var: %v", sr.callsMatching("sh -c"))
	}
	if c.errs == 0 {
		t.Fatal("refused marker_base not counted")
	}
}
