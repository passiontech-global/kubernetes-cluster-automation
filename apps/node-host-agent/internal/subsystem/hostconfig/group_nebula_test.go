// group_nebula_test.go — nebula mesh converge: restart-vs-
// reload decision, hairpin route prune, version-pin install,
// routing var charset gating, and the disable-path cleanup.
package hostconfig

import (
	"fmt"
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
	sr := newScripted(map[string]string{
		"ip -o route get 10.0.2.20 mark 0x1000": "10.0.2.20 via 10.0.1.30 dev eth0 src 10.0.1.10 mark 0x1000",
	}, nil)
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
	if len(sr.CallsMatching("ip -o route get 10.0.2.20 mark 0x1000")) == 0 {
		t.Fatal("route get not issued for target")
	}
	if len(sr.CallsMatching("ip route del 10.0.2.20/32 table main")) == 0 {
		t.Fatalf("hairpin route not pruned: %v", sr.CallsMatching("route del"))
	}

	// non-lighthouse node: no hairpin probing at all
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.nebulaRouting()
	if len(sr2.CallsMatching("route get")) > 0 {
		t.Fatalf("hairpin probe ran on non-lighthouse: %v", sr2.CallsMatching("route get"))
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

// TestNebulaBinarySwapRestartsService — a version-pin binary install
// must restart nebula@interdc even when cert+config are unchanged:
// SIGHUP reloads config inside the OLD image; only exec picks up the
// new binary. Phase A seeds host state with the probe reporting the
// pin; phase B flips the probe stale and serves a tarball — the
// restart must come from binChanged alone.
func TestNebulaBinarySwapRestartsService(t *testing.T) {
	url, sum := tarballServer(t, map[string]string{
		"nebula":      "#!/bin/sh\n# fake nebula\n",
		"nebula-cert": "#!/bin/sh\n# fake nebula-cert\n",
	})
	vars := writeVarsDir(t, "")
	dp := filepath.Join(vars, "defaults.yaml")
	db, err := os.ReadFile(dp)
	if err != nil {
		t.Fatal(err)
	}
	db = append(db, []byte(fmt.Sprintf(`
interdc_nebula_tgz_url: "%s"
interdc_nebula_tgz_sha256: "%s"
interdc_nebula_tgz_file: "nebula.tgz"
`, url, sum))...)
	if err := os.WriteFile(dp, db, 0o644); err != nil {
		t.Fatal(err)
	}
	certs := t.TempDir()
	for name, content := range map[string]string{
		"nebula-ca.crt": "-----BEGIN NEBULA CA-----\nfake\n",
		"nebula-b.crt":  "-----BEGIN NEBULA CERT-----\nfake\n",
	} {
		if err := os.WriteFile(filepath.Join(certs, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hostRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostRoot, "usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	dl := t.TempDir()

	// Phase A — steady state: probe reports the pin so nothing
	// installs; certs/config/unit land so phase B sees zero drift.
	srA := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.11.2",
	}, nil)
	rA, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: srA, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cA := loadCyc(t, rA, vars, "node-b")
	cA.groupNebula()
	if !hostExists(rA, "/etc/nebula/interdc/config.yaml") {
		t.Fatal("phase A did not seed the nebula config")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("phase A downloaded despite the pin matching")
	}

	// Phase B — on-disk binary now mismatches the pin: install runs
	// while cert+config stay byte-identical and the daemon is active.
	srB := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.10.0",
		"is-active nebula@interdc":       "active",
	}, nil)
	rB, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: srB, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cB := loadCyc(t, rB, vars, "node-b")
	cB.groupNebula()
	if !hostExists(rB, "/usr/local/bin/nebula") {
		t.Fatal("nebula binary not installed under HostRoot")
	}
	if len(srB.CallsMatching("systemctl restart nebula@interdc.service")) == 0 {
		t.Fatalf("binary swap did not restart nebula@interdc: %v", srB.Calls())
	}
	if len(srB.CallsMatching("reload nebula@interdc.service")) > 0 {
		t.Fatal("binary swap took the SIGHUP reload path — old image keeps running")
	}
}

// TestNebulaEmptyVersionPinSkips — an empty version pin is "not
// pinned": log+skip, never a vacuous version match, never download("").
func TestNebulaEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_version: \"\"\n")
	sr := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "nebula version 9.9.9",
	}, nil)
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
	if len(sr.CallsMatching("nebula -version")) > 0 {
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
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with injected marker_base: %v", sr.CallsMatching("sh -c"))
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
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with an empty required ip: %v", sr.CallsMatching("sh -c"))
	}
}

// ---------- groupNebula disable path ----------

// TestNebulaDisableRunsUnconditionalCleanup — a charset-refused var
// must only skip the INTERPOLATED sweep; the non-interpolated
// systemctl disable cleanup still runs.
func TestNebulaDisableRunsUnconditionalCleanup(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\ninterdc_marker_base: \"172.29.0;rm -rf /\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if len(sr.CallsMatching("systemctl disable --now nebula@interdc.service")) == 0 {
		t.Fatal("nebula unit not disabled on the gate-refused path")
	}
	if len(sr.CallsMatching("systemctl disable --now nebula-route-guard.service")) == 0 {
		t.Fatal("route-guard not disabled on the gate-refused path")
	}
	if len(sr.CallsMatching("sh -c")) > 0 {
		t.Fatalf("interpolated sweep ran with a refused var: %v", sr.CallsMatching("sh -c"))
	}
	if c.errs == 0 {
		t.Fatal("refused marker_base not counted")
	}
}

// ---------- nebula.yaml render ----------

// TestNebulaConfigRendersSharedCtx — nebulaConfig renders
// nebula.yaml.j2 through the shared tplCtx: the mesh identity (pki
// paths, static_host_map underlay of the lighthouse, listen port/dev,
// stats listener, lighthouse role) must come out of the vars for hub
// and spoke alike.
func TestNebulaConfigRendersSharedCtx(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	b, err := c.nebulaConfig()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cfg := string(b)
	for _, want := range []string{
		"ca: /etc/nebula/interdc/ca.crt",
		// node-a is the hub → am lighthouse, own marker+underlay in
		// static_host_map (marker = base + last octet of 10.0.1.10).
		"am_lighthouse: True",
		`"172.29.0.10": ["10.0.1.10:45670"]`,
		"port: 45670",
		"dev: neb1",
		"listen: 127.0.0.1:9800",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("hub config missing %q:\n%s", want, cfg)
		}
	}

	// spoke: am_lighthouse flips and the hub marker lands in hosts.
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	b2, err := c2.nebulaConfig()
	if err != nil {
		t.Fatalf("render node-b: %v", err)
	}
	cfg2 := string(b2)
	if !strings.Contains(cfg2, "am_lighthouse: False") {
		t.Fatalf("spoke config must not be a lighthouse:\n%s", cfg2)
	}
	if !strings.Contains(cfg2, `- "172.29.0.10"`) {
		t.Fatalf("spoke hosts missing the hub marker:\n%s", cfg2)
	}
}
