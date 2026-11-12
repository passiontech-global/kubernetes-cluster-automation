// group_nebula_extra_test.go — T5b coverage beyond the swap/prune
// suites: keygen and cert-read fallbacks, the nebula -test abort,
// the disabled-but-valid-marker routing sweep, needsRestart schema
// corners (unparseable YAML, unsafe_routes lists), the tarball
// install flows (bad staged copy, download failure, missing
// companion member), and nebulaRouting's hub hairpin / worker
// node-ip / tinc rollback / relay branches.
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nebulaExtraFixture — certs + empty host root + fresh download dir,
// with the tgz pins pointed at the served tarball.
func nebulaExtraFixture(t *testing.T, members map[string]string) (vars, certs, hostRoot, dl string) {
	t.Helper()
	vars = writeVarsDir(t, "")
	certs = t.TempDir()
	for name, content := range map[string]string{
		"nebula-ca.crt": "-----BEGIN NEBULA CA-----\nfake\n",
		"nebula-b.crt":  "-----BEGIN NEBULA CERT-----\nfake\n",
	} {
		if err := os.WriteFile(filepath.Join(certs, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hostRoot = t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostRoot, "usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	plantTunDevice(t, hostRoot)
	dl = t.TempDir()
	url, sum := tarballServer(t, members)
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
	return vars, certs, hostRoot, dl
}

// TestNebulaKeygenFailureCounts — a fresh node without host.key: the
// keygen exec failing must count (nebula cannot start keyless) while
// the rest of the converge still lands.
func TestNebulaKeygenFailureCounts(t *testing.T) {
	vars, certs, hostRoot, dl := nebulaExtraFixture(t, map[string]string{"nebula": "#!/bin/sh\n"})
	sr := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.11.2",
	}, nil)
	sr.FailOn("nebula-cert keygen", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if c.errs == 0 {
		t.Fatal("failed nebula-cert keygen did not count a cycle error")
	}
	if !hostExists(r, "/etc/nebula/interdc/config.yaml") {
		t.Fatal("config not rendered despite the keygen failure")
	}
}

// TestNebulaCertUnreadableFallsBackToVars — an unreadable cert in the
// certs mount must not shadow the VarsDir fallback (the warn is
// best-effort; the signed cert still lands).
func TestNebulaCertUnreadableFallsBackToVars(t *testing.T) {
	vars, certs, hostRoot, dl := nebulaExtraFixture(t, map[string]string{"nebula": "#!/bin/sh\n"})
	// Make the certs-mount copy unreadable (owner loses read).
	if err := os.Chmod(filepath.Join(certs, "nebula-b.crt"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(certs, "nebula-b.crt"), 0o644) })
	// VarsDir carries the same cert — the CM-mount fallback source.
	if err := os.WriteFile(filepath.Join(vars, "nebula-b.crt"),
		[]byte("-----BEGIN NEBULA CERT-----\nfrom-vars\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.11.2",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if got := hostRead(t, r, "/etc/nebula/interdc/host.crt"); !strings.Contains(got, "from-vars") {
		t.Fatalf("host.crt not sourced from the VarsDir fallback:\n%s", got)
	}
	if c.errs != 0 {
		t.Fatalf("cert fallback counted errors: %d", c.errs)
	}
}

// TestNebulaTestFailureAbortsStart — `nebula -test` failing must
// abort before ensureService: no enable/start reaches systemctl.
func TestNebulaTestFailureAbortsStart(t *testing.T) {
	vars, certs, hostRoot, dl := nebulaExtraFixture(t, map[string]string{"nebula": "#!/bin/sh\n"})
	sr := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.11.2",
	}, nil)
	sr.FailOn("nebula -config", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if c.errs == 0 {
		t.Fatal("nebula -test failure did not count a cycle error")
	}
	for _, call := range sr.Calls() {
		if strings.Contains(call, "systemctl enable nebula@interdc") ||
			strings.Contains(call, "systemctl start nebula@interdc") {
			t.Fatalf("nebula started despite -test failure: %v", call)
		}
	}
}

// TestNebulaDisableValidMarkerSweeps — disabled nebula on a node with
// a well-formed marker base still runs the interpolated ip-rule/nft
// sweep after the unconditional systemctl cleanup.
func TestNebulaDisableValidMarkerSweeps(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	for _, want := range []string{
		"systemctl disable --now nebula-route-guard.service",
		"ip rule del pref 1490 to 172.29.0.0/24",
		"ip route flush table 100",
		"nft delete table ip nebnat",
	} {
		if len(sr.CallsMatching(want)) == 0 {
			t.Fatalf("disabled sweep missing %q: %v", want, sr.Calls())
		}
	}
}

// TestNebulaNeedsRestartSchemaCorners — unparseable YAML restarts
// (safe default) and a tun.unsafe_routes LIST edit walks the
// deep-compare (reloadable) without tripping a restart.
func TestNebulaNeedsRestartSchemaCorners(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if !c.nebulaNeedsRestart([]byte(":::: not yaml"), []byte("listen: {host: 0.0.0.0}")) {
		t.Fatal("unparseable old config must default to restart")
	}
	base := `pki:
  cert: /c.crt
tun:
  unsafe_routes:
    - route: 10.40.0.0/16
      via: 172.29.0.20
`
	routes := `pki:
  cert: /c.crt
tun:
  unsafe_routes:
    - route: 10.40.0.0/16
      via: 172.29.0.20
    - route: 10.50.0.0/16
      via: 172.29.0.20
`
	// unsafe_routes is reloadable via SIGHUP — a list edit must NOT
	// force a restart.
	if c.nebulaNeedsRestart([]byte(base), []byte(routes)) {
		t.Fatal("unsafe_routes list edit forced a restart (reloadable key)")
	}
	if c.nebulaNeedsRestart([]byte(base), []byte(base)) {
		t.Fatal("identical configs judged a restart")
	}
	// pki PATHS are NOT reloadable.
	moved := strings.Replace(base, "/c.crt", "/c2.crt", 1)
	if !c.nebulaNeedsRestart([]byte(base), []byte(moved)) {
		t.Fatal("pki path change judged reloadable")
	}
}

// TestNebulaInstallFlows — the shared tarball flow's failure arms at
// the nebula call site: refused staged copy, failed download, and a
// tarball missing the nebula-cert companion (warn-only).
func TestNebulaInstallFlows(t *testing.T) {
	t.Run("refused_bad_staged", func(t *testing.T) {
		vars, certs, hostRoot, dl := nebulaExtraFixture(t,
			map[string]string{"nebula": "#!/bin/sh\n", "nebula-cert": "#!/bin/sh\n"})
		// Staged copy that does NOT match the pin — tarballs refuse,
		// they never re-download over operator staging.
		if err := os.WriteFile(filepath.Join(dl, "nebula.tgz"), []byte("corrupted"), 0o644); err != nil {
			t.Fatal(err)
		}
		sr := newScripted(nil, nil)
		r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
			VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "node-b")
		c.groupNebula()
		if hostExists(r, "/usr/local/bin/nebula") {
			t.Fatal("installed from a corrupted staged tarball")
		}
		if c.errs == 0 {
			t.Fatal("refused staged tarball did not count a cycle error")
		}
		if _, err := os.Stat(filepath.Join(dl, "nebula.tgz")); err != nil {
			t.Fatal("refused staged tarball was deleted")
		}
	})
	t.Run("download_failure", func(t *testing.T) {
		vars, certs, hostRoot, dl := nebulaExtraFixture(t,
			map[string]string{"nebula": "#!/bin/sh\n"})
		// Cluster-level pins override the tarball server with a
		// closed port — download fails fast, version pin stays.
		patchVarsFile(t, vars, "cluster.yaml",
			"interdc_nebula_tgz_url: \"http://127.0.0.1:1/nebula.tgz\"\n"+
				"interdc_nebula_tgz_sha256: \"0000\"\n")
		sr := newScripted(nil, nil)
		r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
			VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "node-b")
		c.groupNebula()
		if c.errs == 0 {
			t.Fatal("failed nebula download did not count a cycle error")
		}
	})
	t.Run("missing_companion_member", func(t *testing.T) {
		vars, certs, hostRoot, dl := nebulaExtraFixture(t,
			map[string]string{"nebula": "#!/bin/sh\n"})
		sr := newScripted(map[string]string{
			"/usr/local/bin/nebula -version": "Version: 1.10.0",
		}, nil)
		r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
			VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "node-b")
		c.groupNebula()
		if !hostExists(r, "/usr/local/bin/nebula") {
			t.Fatal("main nebula binary not installed")
		}
		if hostExists(r, "/usr/local/bin/nebula-cert") {
			t.Fatal("nebula-cert extracted although the member is absent")
		}
	})
}

// TestNebulaRoutingHubHairpin — the hub hairpin prune: a failed
// `ip route get` probe skips the target; a probe reporting a route
// via another mesh node's IP prunes it (delete failure warns only).
func TestNebulaRoutingHubHairpin(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	t.Run("probe_failed", func(t *testing.T) {
		sr.FailOn("ip -o route get", nil)
		c.nebulaRouting()
		if len(sr.CallsMatching("ip route del")) > 0 {
			t.Fatal("pruned a target whose probe failed")
		}
	})
	t.Run("hairpin_via_mesh_ip", func(t *testing.T) {
		sr.ClearFails()
		// node-c's public IP is a registry mesh IP — a route to the
		// cross-site target via it hairpins through that node and
		// must be pruned from main.
		sr.On("ip -o route get 10.0.2.20", "route 10.0.2.20 via 10.0.1.30 dev eth0\n")
		c.nebulaRouting()
		if len(sr.CallsMatching("ip route del 10.0.2.20/32 table main")) == 0 {
			t.Fatalf("hairpin route via mesh IP not pruned: %v", sr.CallsMatching("ip route"))
		}
	})
	t.Run("via_non_mesh_kept", func(t *testing.T) {
		// Same probe with a non-registry next-hop — kept. Clear the
		// log first: the previous subtest's prune call would match.
		sr.ClearLog()
		sr.On("ip -o route get 10.0.2.20", "route 10.0.2.20 via 192.168.7.1 dev eth0\n")
		c.nebulaRouting()
		for _, call := range sr.CallsMatching("ip route del 10.0.2.20/32") {
			t.Fatalf("non-mesh via pruned: %v", call)
		}
	})
}

// TestNebulaRoutingWorkerNodeIPNonMarker — a worker whose --node-ip
// is NOT in the marker subnet drops the pref-1490 marker rule instead
// of adding it (the marker subnet is not local to this node).
func TestNebulaRoutingWorkerNodeIPNonMarker(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.9.9.9\n")
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if len(sr.CallsMatching("ip rule del pref 1490 to 172.29.0.0/24 lookup 101")) == 0 {
		t.Fatalf("foreign marker subnet not dropped: %v", sr.Calls())
	}
}

// TestNebulaRoutingTincRollback — overlay=tinc replaces the pref-1500
// converge with the rollback sweep and drops the pref-1499 bypass.
func TestNebulaRoutingTincRollback(t *testing.T) {
	vars := writeVarsDir(t, "interdc_overlay_default: tinc\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if len(sr.CallsMatching("ip rule del pref 1499 ipproto tcp dport")) == 0 {
		t.Fatal("tinc rollback kept the pref-1499 direct-underlay bypass")
	}
	if len(sr.CallsMatching("ip rule add pref 1500")) > 0 {
		t.Fatal("tinc overlay added nebula pref-1500 rules")
	}
}

// TestNebulaRoutingRelayBranches — self relay entries render the
// relay SNAT/forward lines; a remote site's fallback relay surfaces
// as an egress-relay conditional rule.
func TestNebulaRoutingRelayBranches(t *testing.T) {
	vars := writeVarsDir(t, `interdc_nebula_enabled: true
`)
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  relay:
    - ip: 198.18.0.1
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  relay:
    - ip: 198.18.0.2
      mode: fallback
      sites: [s1]
      probe: "9800"
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.nebulaRouting()
	// Self relay: ip_forward + per-relay return/SNAT rules.
	for _, want := range []string{
		"nft list chain ip nebnat post | grep -q \"saddr 198.18.0.1 return\"",
		"net.ipv4.ip_forward=1",
	} {
		if len(sr.CallsMatching(want)) == 0 {
			t.Fatalf("self-relay rule missing %q", want)
		}
	}
	// Remote fallback relay for our site: the watchdog-state-gated
	// egress rule appears in the pref-1500 script.
	if len(sr.CallsMatching("egress-state-198.18.0.2")) == 0 {
		t.Fatalf("egress relay rule missing for 198.18.0.2: %v", sr.Calls())
	}
}

// TestNebulaMissingCertCountsAndSkipsStart — neither the certs mount
// nor the vars dir carries the signed cert: counted, config+unit still
// converge, but the service is never started.
func TestNebulaMissingCertCountsAndSkipsStart(t *testing.T) {
	vars, certs, hostRoot, dl := nebulaExtraFixture(t, map[string]string{"nebula": "#!/bin/sh\n"})
	// Drop the signed cert everywhere; the CA alone is not enough.
	if err := os.Remove(filepath.Join(certs, "nebula-b.crt")); err != nil {
		t.Fatal(err)
	}
	sr := newScripted(map[string]string{
		"/usr/local/bin/nebula -version": "Version: 1.11.2",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if c.errs == 0 {
		t.Fatal("missing signed cert did not count a cycle error")
	}
	if !hostExists(r, "/etc/nebula/interdc/config.yaml") {
		t.Fatal("config not converged despite the missing cert")
	}
	for _, call := range sr.Calls() {
		if strings.Contains(call, "systemctl start nebula@interdc") {
			t.Fatalf("nebula started without a signed cert: %v", call)
		}
	}
}

// TestNebulaTarballWithoutMainMember — neither member present: the
// main extraction fails with a counted error and nothing installs.
func TestNebulaTarballWithoutMainMember(t *testing.T) {
	vars, certs, hostRoot, dl := nebulaExtraFixture(t, map[string]string{"other": "#!/bin/sh\n"})
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: hostRoot,
		VarsDir: vars, NebulaCertsDir: certs, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if hostExists(r, "/usr/local/bin/nebula") || hostExists(r, "/usr/local/bin/nebula-cert") {
		t.Fatal("binaries extracted from a tarball without their members")
	}
	if c.errs == 0 {
		t.Fatal("failed nebula extraction did not count a cycle error")
	}
}

// TestNebulaHairpinDeleteFailureWarns — the stale-route delete
// failing warns only (the live ip-rule converge below still routes).
func TestNebulaHairpinDeleteFailureWarns(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.On("ip -o route get 10.0.2.20", "route 10.0.2.20 via 10.0.1.30 dev eth0\n")
	sr.FailOn("ip route del 10.0.2.20/32 table main", nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.nebulaRouting()
	if c.errs != 0 {
		t.Fatalf("errs = %d — the hairpin prune is best-effort", c.errs)
	}
}
