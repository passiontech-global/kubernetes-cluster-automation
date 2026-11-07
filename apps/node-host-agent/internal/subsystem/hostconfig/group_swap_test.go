// group_swap_test.go — swap sizing converge: controller /
// kine-db targets, active-swap exact-match probe, recreate
// rules, and fail-closed skip on probe failure.
package hostconfig

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// ---------- swap sizing ----------

// swapRunner wraps the shared FakeRunner and materializes the
// swapfile under HostRoot on fallocate/dd — the real nsenter runner
// creates it on the host where hostconfig then sees it through the
// HostRoot mount.
type swapRunner struct {
	*testutil.FakeRunner
	hostRoot string
}

func (s *swapRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := s.FakeRunner.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	if name == "fallocate" && len(args) >= 3 {
		mb, _ := strconv.ParseInt(strings.TrimSuffix(args[1], "M"), 10, 64)
		p := filepath.Join(s.hostRoot, args[2])
		if f, ferr := os.Create(p); ferr == nil {
			_ = f.Truncate(mb * 1048576)
			_ = f.Close()
		}
	}
	if name == "dd" {
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				_ = os.WriteFile(filepath.Join(s.hostRoot, a[3:]), []byte{}, 0o644)
			}
		}
	}
	return out, err
}

func newSwapHost(t *testing.T, vars, node string, sr *testutil.FakeRunner) *Reconciler {
	t.Helper()
	hr := t.TempDir()
	r, err := New(Config{NodeName: node, HostRoot: hr,
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: &swapRunner{FakeRunner: sr, hostRoot: hr}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSwapControllerDefault12G(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if len(sr.CallsMatching("fallocate -l 12288M /swapfile-kine")) == 0 {
		t.Fatalf("12G fallocate missing: %v", sr.CallsMatching("fallocate"))
	}
	if len(sr.CallsMatching("mkswap /swapfile-kine")) == 0 ||
		len(sr.CallsMatching("swapon /swapfile-kine")) == 0 {
		t.Fatal("mkswap/swapon not invoked")
	}
	fstab := hostRead(t, r, "/etc/fstab")
	if !strings.Contains(fstab, "\n/swapfile-kine none swap sw 0 0\n") {
		t.Fatalf("fstab entry missing:\n%s", fstab)
	}
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 60") {
		t.Fatalf("controller swappiness drop-in wrong (ansible: 60):\n%s", sys)
	}
	fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "/swapfile-kine"))
	if fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("swapfile mode wrong: %v", fi)
	}
}

func TestSwapKineDBHost2G(t *testing.T) {
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: db-vm-1
    ip: 10.9.9.9
    kine_db: true
  - name: other-vm
    ip: 10.9.9.10
`)
	sr := newScripted(nil, nil)
	r := newSwapHost(t, vars, "db-vm-1", sr)
	hostWrite(t, r, "/etc/fstab", "")
	c := loadCyc(t, r, vars, "db-vm-1")
	c.groupSwap()
	// ansible db include passed NO swap_path → the task default
	// /swapfile (NOT the controller's /swapfile-kine — that created
	// a second 2G file + orphaned fstab line on the real db-vm).
	if len(sr.CallsMatching("fallocate -l 2048M /swapfile")) == 0 {
		t.Fatalf("2G fallocate missing: %v", sr.CallsMatching("fallocate"))
	}
	if len(sr.CallsMatching("swapfile-kine")) > 0 {
		t.Fatalf("db VM must not touch /swapfile-kine: %v", sr.CallsMatching("swapfile-kine"))
	}
	fstab := hostRead(t, r, "/etc/fstab")
	if !strings.Contains(fstab, "/swapfile none swap sw 0 0") {
		t.Fatalf("db fstab entry missing:\n%s", fstab)
	}
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 10") {
		t.Fatalf("db swappiness drop-in wrong (ansible: 10):\n%s", sys)
	}

	// non-matching host name -> no swap at all
	sr2 := newScripted(nil, nil)
	r2 := newSwapHost(t, vars, "other-vm", sr2)
	c2 := loadCyc(t, r2, vars, "other-vm")
	c2.groupSwap()
	if len(sr2.CallsMatching("fallocate")) > 0 || len(sr2.CallsMatching("swapon ")) > 0 {
		t.Fatalf("swap touched on non-kine_db host: %v", sr2.Calls())
	}
}

func TestSwapSwappinessVarOverride(t *testing.T) {
	vars := writeVarsDir(t, "swap_swappiness: \"30\"\n")
	sr := newScripted(nil, nil)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "")
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 30") {
		t.Fatalf("swap_swappiness override not honoured:\n%s", sys)
	}
}

func TestSwapNoOpOnPlainWorker(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r := newSwapHost(t, vars, "node-b", sr)
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupSwap()
	for _, call := range sr.Calls() {
		if strings.Contains(call, "fallocate") || strings.Contains(call, "swapon") ||
			strings.Contains(call, "mkswap") {
			t.Fatalf("swap touched on plain worker: %s", call)
		}
	}
	if hostExists(r, "/etc/sysctl.d/99-kine-swap.conf") {
		t.Fatal("swappiness drop-in written on non-swap host")
	}
}

func TestSwapSkipsRecreateWhenRightSize(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	// pre-existing 12G sparse file => no recreate path
	sp := filepath.Join(r.cfg.HostRoot, "/swapfile-kine")
	f, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(12288 * 1048576); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()
	if len(sr.CallsMatching("fallocate")) > 0 {
		t.Fatal("right-size swapfile must not be recreated")
	}
	if len(sr.CallsMatching("swapon /swapfile-kine")) == 0 {
		t.Fatal("swapon still expected on inactive file")
	}
}

func TestSwapSwaponProbeFailureSkipsCycle(t *testing.T) {
	vars := writeVarsDir(t, "")
	// Probe failure must fail CLOSED: the wrong-size file may be an
	// ACTIVE swapfile — removing it pulls the kernel's swap target
	// out from under it. The whole cycle must be skipped on a
	// failed probe, not just the remove branch.
	sr := newScripted(nil, map[string]bool{
		"swapon --show=NAME": true,
	})
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	// wrong-size file on disk (2G where 12G is wanted) — the exact
	// shape that would hit the os.Remove path on a bogus "inactive".
	sp := filepath.Join(r.cfg.HostRoot, "/swapfile-kine")
	f, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(2048 * 1048576); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if !hostExists(r, "/swapfile-kine") {
		t.Fatal("wrong-size swapfile removed despite failed active-state probe")
	}
	// the ONLY host command issued is the probe itself — nothing
	// (create/chmod/mkswap/fstab/swapon/sysctl) may proceed.
	if sr.Count() != 1 || !strings.Contains(sr.Nth(0), "swapon --show") {
		t.Fatalf("swap converge proceeded past the failed probe: %v", sr.Calls())
	}
	if hostExists(r, "/etc/sysctl.d/99-kine-swap.conf") {
		t.Fatal("swappiness drop-in written despite skipped cycle")
	}
	if strings.Contains(hostRead(t, r, "/etc/fstab"), "swapfile-kine") {
		t.Fatal("fstab entry added despite skipped cycle")
	}
}

func TestSwapActiveMatchExactLine(t *testing.T) {
	// swapon --show=NAME emits one swap name per line — active-state
	// must be an exact line match. A substring probe marks /swapfile
	// active just because /swapfile-kine is listed, yet the two are
	// independent swap targets.
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: db-vm-1
    ip: 10.9.9.9
    kine_db: true
`)
	seed := func(r *Reconciler, path string, mb int64) {
		t.Helper()
		f, err := os.Create(filepath.Join(r.cfg.HostRoot, path))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(mb * 1048576); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}

	// /swapfile probed while only /swapfile-kine is active: NOT active
	// — the wrong-size file is recreated and swapon is issued.
	sr := newScripted(map[string]string{
		"swapon --show=NAME": "/swapfile-kine\n",
	}, nil)
	r := newSwapHost(t, vars, "db-vm-1", sr)
	hostWrite(t, r, "/etc/fstab", "")
	seed(r, "/swapfile", 1024) // wrong size vs db default 2048
	c := loadCyc(t, r, vars, "db-vm-1")
	c.groupSwap()
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/swapfile"))
	if err != nil || fi.Size() != 2048*1048576 {
		t.Fatalf("/swapfile must be recreated at 2G — substring match marked it active: fi=%v err=%v", fi, err)
	}
	if len(sr.CallsMatching("swapon /swapfile")) == 0 {
		t.Fatalf("swapon /swapfile expected on inactive file: %v", sr.Calls())
	}

	// /swapfile-kine listed exactly: ACTIVE — never removed, never
	// re-swapon'd (controller wants 12G; the live 2G file stays).
	sr2 := newScripted(map[string]string{
		"swapon --show=NAME": "/swapfile\n/swapfile-kine\n",
	}, nil)
	r2 := newSwapHost(t, vars, "node-a", sr2)
	hostWrite(t, r2, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r2, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	seed(r2, "/swapfile-kine", 2048) // wrong size vs controller 12288
	c2 := loadCyc(t, r2, vars, "node-a")
	c2.groupSwap()
	fi, err = os.Stat(filepath.Join(r2.cfg.HostRoot, "/swapfile-kine"))
	if err != nil || fi.Size() != 2048*1048576 {
		t.Fatal("active /swapfile-kine was removed/resized")
	}
	if len(sr2.CallsMatching("swapon /swapfile-kine")) > 0 {
		t.Fatal("swapon issued for already-active /swapfile-kine")
	}
}
