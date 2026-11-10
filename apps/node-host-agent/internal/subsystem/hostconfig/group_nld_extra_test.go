// group_nld_extra_test.go — T4 coverage beyond the refuse/repoint
// suite: the failed ss probe, the already-correct symlink skip, the
// symlink create/rename failure arms, the allow-list's tolerance for
// scalar registry entries, and the host-internal-ports guard's
// explicit disable sweep.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// nldFixture — reconciler + cyc with runner rules per test.
func nldFixture(t *testing.T) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// TestNLDSSProbeFailureContinues — a failed `ss -lntu` leaves
// stubListening=false and the rest of T4 still converges (best-effort
// detection, not a gate).
func TestNLDSSProbeFailureContinues(t *testing.T) {
	r, sr, c := nldFixture(t)
	sr.FailOn("ss -lntu", nil)
	c.groupNLD()
	if c.errs != 0 {
		t.Fatalf("errs = %d — the failed probe is best-effort", c.errs)
	}
	if !hostExists(r, "/etc/nodelocaldns-guard.nft") {
		t.Fatal("guard nft not deployed despite the failed probe")
	}
}

// TestNLDResolvConfAlreadyCorrect — /etc/resolv.conf already the
// resolved real-source symlink: the repoint is skipped without a
// temp symlink dance.
func TestNLDResolvConfAlreadyCorrect(t *testing.T) {
	r, sr, c := nldFixture(t)
	sr.On("systemctl show systemd-resolved.service", "active")
	sr.On("ss -lntu", "LISTEN 127.0.0.53:53")
	hostWrite(t, r, "/run/systemd/resolve/resolv.conf", "nameserver 10.0.0.2\n")
	dst := filepath.Join(r.cfg.HostRoot, "etc/resolv.conf")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run/systemd/resolve/resolv.conf", dst); err != nil {
		t.Fatal(err)
	}
	c.groupNLD()
	if l, err := os.Readlink(dst); err != nil || l != "/run/systemd/resolve/resolv.conf" {
		t.Fatalf("correct symlink disturbed: %q %v", l, err)
	}
	if _, err := os.Lstat(dst + ".hostconfig.tmp"); !os.IsNotExist(err) {
		t.Fatal("temp symlink created although the target was already correct")
	}
}

// TestNLDRepointFailureArms — the atomic repoint's two failure arms:
// symlink creation failing (read-only etc dir) and the rename onto a
// non-empty dir failing; each counts and never leaves a tmp behind.
func TestNLDRepointFailureArms(t *testing.T) {
	t.Run("symlink_create_failed", func(t *testing.T) {
		r, sr, c := nldFixture(t)
		sr.On("systemctl show systemd-resolved.service", "active")
		sr.On("ss -lntu", "LISTEN 127.0.0.53:53")
		hostWrite(t, r, "/run/systemd/resolve/resolv.conf", "nameserver 10.0.0.2\n")
		hostWrite(t, r, "/etc/resolv.conf", "nameserver 8.8.8.8\n")
		// Remove the owner's write bit on etc/ — symlink creation in
		// it fails with EACCES.
		etc := filepath.Join(r.cfg.HostRoot, "etc")
		if err := os.Chmod(etc, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(etc, 0o755) })
		c.groupNLD()
		if c.errs == 0 {
			t.Fatal("failed symlink creation did not count a cycle error")
		}
		if _, err := os.Lstat(filepath.Join(etc, "resolv.conf.hostconfig.tmp")); !os.IsNotExist(err) {
			t.Fatal("temp symlink lingered after the failure")
		}
	})
	t.Run("rename_onto_dir_failed", func(t *testing.T) {
		r, sr, c := nldFixture(t)
		sr.On("systemctl show systemd-resolved.service", "active")
		sr.On("ss -lntu", "LISTEN 127.0.0.53:53")
		hostWrite(t, r, "/run/systemd/resolve/resolv.conf", "nameserver 10.0.0.2\n")
		// /etc/resolv.conf as a non-empty dir: the rename over it
		// fails after the temp symlink was created.
		hostWrite(t, r, "/etc/resolv.conf/inner", "x\n")
		c.groupNLD()
		if c.errs == 0 {
			t.Fatal("failed rename did not count a cycle error")
		}
		if _, err := os.Lstat(filepath.Join(r.cfg.HostRoot, "/etc/resolv.conf.hostconfig.tmp")); !os.IsNotExist(err) {
			t.Fatal("temp symlink lingered after the rename failure")
		}
	})
}

// TestNLDAllowSourcesScalarNode — a scalar (non-mapping) registry
// entry is skipped when collecting the nft allow list, not a panic.
func TestNLDAllowSourcesScalarNode(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c: gateway-vm
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	allow := c.guardAllowSources()
	// defaults fixture contributes nodelocaldns_guard_allow_private
	// (10.0.0.0/8); the scalar gateway entry contributes nothing.
	want := []string{"10.0.0.0/8", "10.0.1.10", "10.0.2.20"}
	if len(allow) != len(want) || allow[0] != want[0] || allow[1] != want[1] || allow[2] != want[2] {
		t.Fatalf("guardAllowSources = %v, want %v", allow, want)
	}
}

// TestNLDHostPortsGuardDisabledSweep — an explicit
// host_internal_ports_guard_enabled: false tears down the unit, the
// ruleset, and the live table; daemon-reload only when a unit file
// actually came off disk.
func TestNLDHostPortsGuardDisabledSweep(t *testing.T) {
	vars := writeVarsDir(t, "host_internal_ports_guard_enabled: false\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/host-internal-ports-guard.service", "[Unit]\n")
	hostWrite(t, r, "/etc/host-internal-ports-guard.nft", "table\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()
	for _, call := range []string{
		"systemctl disable --now host-internal-ports-guard.service",
		"nft delete table ip host_internal_ports_guard",
	} {
		if len(sr.CallsMatching(call)) == 0 {
			t.Fatalf("disable sweep missing %q: %v", call, sr.Calls())
		}
	}
	if hostExists(r, "/etc/systemd/system/host-internal-ports-guard.service") ||
		hostExists(r, "/etc/host-internal-ports-guard.nft") {
		t.Fatal("guard files not removed on the explicit disable")
	}
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload missing after the unit removal")
	}

	// Idempotent second pass: no unit file → no reload this time.
	sr.ClearLog()
	c.groupNLD()
	if len(sr.CallsMatching("systemctl daemon-reload")) != 0 {
		t.Fatal("daemon-reload fired on an already-swept guard")
	}
	if !strings.Contains(strings.Join(sr.Calls(), "\n"), "nft delete table ip host_internal_ports_guard") {
		t.Fatal("live-table delete missing on the idempotent pass (disabling must reopen the ports)")
	}
}
