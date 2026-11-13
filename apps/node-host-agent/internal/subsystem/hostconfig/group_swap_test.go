// group_swap_test.go — swap sizing converge: controller /
// kine-db targets, active-swap exact-match probe, recreate
// rules, and fail-closed skip on probe failure.
package hostconfig

import (
	"context"
	"errors"
	"os"
	"os/exec"
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

// ---------- blkid probe fail-closed ----------

// exitStatusErr synthesizes a REAL *exec.ExitError with the wanted
// status: the blkid gate distinguishes the documented exit-2
// no-signature from probe failures BY exit code, so the fixture must
// carry one (FakeRunner's scripted failure is a plain error).
func exitStatusErr(t *testing.T, code int) error {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	runErr := exec.Command(sh, "-c", "exit "+strconv.Itoa(code)).Run()
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) || ee.ExitCode() != code {
		t.Fatalf("cannot synthesize exit-%d error: %v", code, runErr)
	}
	return runErr
}

// seedSwapFile materializes a sparse swapfile at mb under HostRoot.
func seedSwapFile(t *testing.T, r *Reconciler, path string, mb int64) {
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

// TestSwapBlkidFailureSkipsCycle — a blkid probe failure is "cannot
// tell a fresh file from ACTIVE swap": the old `out, _ :=` swallowed
// it and ran mkswap anyway, rewriting the signature of live swap
// whenever the swapon probe missed the active entry. Fail closed:
// counted error, no mkswap, nothing past the probe.
func TestSwapBlkidFailureSkipsCycle(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("blkid", nil)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	seedSwapFile(t, r, "/swapfile-kine", 12288) // right size — no recreate path

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if c.errs == 0 {
		t.Fatal("blkid failure not counted")
	}
	if len(sr.CallsMatching("mkswap")) > 0 {
		t.Fatalf("mkswap ran past a failed blkid probe: %v", sr.CallsMatching("mkswap"))
	}
	// Nothing past the probe: only the swapon probe + blkid ran.
	if n := sr.Count(); n != 2 {
		t.Fatalf("swap converge proceeded past the failed probe (%d calls): %v", n, sr.Calls())
	}
	if strings.Contains(hostRead(t, r, "/etc/fstab"), "swapfile-kine") {
		t.Fatal("fstab entry added despite skipped cycle")
	}
	if hostExists(r, "/etc/sysctl.d/99-kine-swap.conf") {
		t.Fatal("swappiness drop-in written despite skipped cycle")
	}
}

// TestSwapBlkidFailureOnActiveSkips — an ACTIVE swapfile with a failed
// blkid probe must skip too: fail-closed does not soften because the
// file is live — that is exactly the file whose signature mkswap
// would rewrite.
func TestSwapBlkidFailureOnActiveSkips(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"swapon --show=NAME": "/swapfile-kine\n",
	}, nil)
	sr.FailOn("blkid", nil)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	seedSwapFile(t, r, "/swapfile-kine", 12288)

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if c.errs == 0 {
		t.Fatal("blkid failure on an active swapfile not counted")
	}
	if len(sr.CallsMatching("mkswap")) > 0 || len(sr.CallsMatching("swapon /swapfile-kine")) > 0 {
		t.Fatalf("mkswap/swapon ran past a failed blkid probe on an active file: %v", sr.Calls())
	}
	if n := sr.Count(); n != 2 {
		t.Fatalf("swap converge proceeded past the failed probe (%d calls): %v", n, sr.Calls())
	}
}

// TestSwapBlkidExit2UnsignedStillMkswaps — blkid's documented exit-2
// "no signature" is the healthy fresh-file answer; treating EVERY
// probe error as failure would strand fresh swapfiles. The exit-2 arm
// still mkswaps the inactive file, and swapon/fstab follow.
func TestSwapBlkidExit2UnsignedStillMkswaps(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("blkid", exitStatusErr(t, 2))
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if len(sr.CallsMatching("mkswap /swapfile-kine")) == 0 {
		t.Fatalf("exit-2 no-signature must still mkswap the fresh file: %v", sr.Calls())
	}
	if len(sr.CallsMatching("swapon /swapfile-kine")) == 0 {
		t.Fatal("fresh swapfile not activated after exit-2 probe")
	}
	if c.errs != 0 {
		t.Fatalf("exit-2 no-signature counted as probe failure: %v", sr.Calls())
	}
}

// TestSwapRefusesMkswapOnActiveUnsigned — "active but unsigned" means
// the swapon and blkid probes disagree; mkswap is only ever
// legitimate on an INACTIVE file, so the cycle skips rather than
// rewrite the signature of live swap out from under the kernel.
func TestSwapRefusesMkswapOnActiveUnsigned(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"swapon --show=NAME": "/swapfile-kine\n",
	}, nil) // blkid answers unsigned (empty output, success)
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	seedSwapFile(t, r, "/swapfile-kine", 12288)

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if c.errs == 0 {
		t.Fatal("active-but-unsigned contradiction not counted")
	}
	if len(sr.CallsMatching("mkswap")) > 0 || len(sr.CallsMatching("swapon /swapfile-kine")) > 0 {
		t.Fatalf("mkswap/swapon ran on an active unsigned swapfile: %v", sr.Calls())
	}
	if n := sr.Count(); n != 2 {
		t.Fatalf("cycle proceeded past the contradiction (%d calls): %v", n, sr.Calls())
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

// swapFileSized materializes the swapfile at the exact converged
// size — the FakeRunner stubs fallocate/dd without creating bytes,
// so tests that must reach the fstab/swapon/sysctl tail pre-seed a
// sparse file that passes ensureSwapfile's size gate.
func swapFileSized(t *testing.T, r *Reconciler, mb int64) {
	t.Helper()
	p := filepath.Join(r.cfg.HostRoot, "swapfile")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(mb * 1048576); err != nil {
		t.Fatal(err)
	}
}

// swapFixture — fresh reconciler + cyc; runner rules added per test.
func swapFixture(t *testing.T, cluster string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// TestKineDBHostItemTypes — the kine_db flag's accepted shapes:
// bool, truthy/falsey strings, numbers, other values, unset, and
// non-mapping entries.
func TestKineDBHostItemTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"bool_true", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: true\n", true},
		{"bool_false", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: false\n", false},
		{"string_yes", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"yes\"\n", true},
		{"string_one", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"1\"\n", true},
		{"string_no", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: \"no\"\n", false},
		{"int_truthy", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db: 3\n", true},
		{"map_value", "node_exporter_extra_hosts:\n  - name: node-b\n    kine_db:\n      x: 1\n", true},
		{"unset_flag", "node_exporter_extra_hosts:\n  - name: node-b\n", false},
		{"other_node", "node_exporter_extra_hosts:\n  - name: node-a\n    kine_db: true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := writeVarsDir(t, tc.yaml)
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, Runner: sr}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			if got := c.kineDBHost(); got != tc.want {
				t.Fatalf("kineDBHost(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
	// A scalar (non-mapping) list entry must be skipped, not panic.
	vars := writeVarsDir(t, "node_exporter_extra_hosts:\n  - just-a-string\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if c.kineDBHost() {
		t.Fatal("scalar entry matched kineDBHost")
	}
}

// TestGroupSwapClassSelection — only controllers and kine-db hosts
// get a swapfile; everyone else is untouched.
func TestGroupSwapClassSelection(t *testing.T) {
	// Neither controller nor kine-db: no swap work at all.
	r, sr, c := swapFixture(t, "")
	c.groupSwap()
	if len(sr.CallsMatching("swapon")) > 0 || hostExists(r, "/swapfile") {
		t.Fatal("swap converged on a plain node")
	}

	// kine-db host: db class paths + swappiness 10 default.
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: node-b
    kine_db: true
`)
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	swapFileSized(t, r2, 2048) // db class default: 2048 MiB
	sr2.On("blkid -o value -s TYPE /swapfile", "swap")
	sr2.On("swapon /swapfile", "")
	c2.groupSwap()
	fstab := hostRead(t, r2, "/etc/fstab")
	if !strings.Contains(fstab, "/swapfile none swap sw 0 0") {
		t.Fatalf("db swap fstab line missing:\n%s", fstab)
	}
	sw := hostRead(t, r2, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sw, "vm.swappiness = 10") {
		t.Fatalf("db swappiness default missing:\n%s", sw)
	}
}

// TestEnsureSwapfileFailureArms — the fail-closed probes and the
// per-step failure arms of the swapfile lifecycle.
func TestEnsureSwapfileFailureArms(t *testing.T) {
	t.Run("swapon_probe_lost", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.FailOn("swapon --show", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the lost-probe skip counted", c.errs)
		}
	})
	t.Run("blkid_probe_lost", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		sr.On("fallocate", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "")
		sr.FailOn("blkid -o value -s TYPE /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the blkid failure skip counted", c.errs)
		}
	})
	t.Run("blkid_exit2_mkswap_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("fallocate", "")
		// exit 2 = the documented no-signature answer.
		ee := exitErr(2)
		sr.FailOn("blkid -o value -s TYPE /swapfile", ee)
		sr.FailOn("mkswap /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the mkswap failure counted", c.errs)
		}
	})
	t.Run("active_but_unsigned", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show=NAME --noheadings", "/swapfile\n")
		swapFileSized(t, r, 64)
		ee := exitErr(2)
		sr.FailOn("blkid -o value -s TYPE /swapfile", ee)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the active+unsigned disagreement counted", c.errs)
		}
		if len(sr.CallsMatching("mkswap")) > 0 {
			t.Fatal("mkswap ran on an ACTIVE swapfile")
		}
	})
	t.Run("dd_fallback_and_its_failure", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// fallocate fails (no file appears), dd fails too → counted.
		sr.FailOn("fallocate -l 64M /swapfile", nil)
		sr.FailOn("dd if=/dev/zero", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the dd failure counted", c.errs)
		}
		if len(sr.CallsMatching("dd if=/dev/zero")) == 0 {
			t.Fatal("dd fallback not attempted after fallocate failure")
		}
	})
	t.Run("wrong_size_remove_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// A non-empty directory at the swap path: stat size != want
		// and os.Remove of a non-empty dir fails → counted.
		hostWrite(t, r, "/swapfile/junk", "x\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the remove failure counted", c.errs)
		}
	})
	t.Run("fstab_read_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "blocker\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 0 {
			t.Fatalf("errs = %d — fstab read failure is a warning only", c.errs)
		}
	})
	t.Run("swapon_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		sr.FailOn("swapon /swapfile", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the swapon failure counted", c.errs)
		}
	})
	t.Run("swappiness_gate_and_sysctl_fail", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		sr.FailOn("sysctl -w vm.swappiness=10", nil)
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the live sysctl failure counted", c.errs)
		}
		if !strings.Contains(hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf"), "vm.swappiness = 10") {
			t.Fatal("drop-in not converged despite the live-apply failure")
		}
		// A refused swappiness skips only the tail, counts the gate.
		c.errs = 0
		c.ensureSwapfile("/swapfile", 64, "1\n2")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the refused swappiness counted", c.errs)
		}
	})
	t.Run("fstab_line_replaced", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "/swapfile none swap sw,nofail 0 0\nother line\n")
		c.ensureSwapfile("/swapfile", 64, "10")
		fstab := hostRead(t, r, "/etc/fstab")
		if strings.Contains(fstab, "nofail") || !strings.Contains(fstab, "/swapfile none swap sw 0 0\n") {
			t.Fatalf("stale swap line not replaced:\n%s", fstab)
		}
	})
	t.Run("fstab_no_trailing_newline", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64)
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab", "no trailing newline")
		c.ensureSwapfile("/swapfile", 64, "10")
		fstab := hostRead(t, r, "/etc/fstab")
		if !strings.Contains(fstab, "no trailing newline\n/swapfile none swap sw 0 0\n") {
			t.Fatalf("appended fstab line glued onto the prior entry:\n%q", fstab)
		}
	})
}

// TestEnsureSwapfileActiveUntouched — an active swapfile at the WRONG
// size is never removed or recreated out from under the kernel.
func TestEnsureSwapfileActiveUntouched(t *testing.T) {
	r, sr, c := swapFixture(t, "")
	sr.On("swapon --show=NAME --noheadings", "/swapfile\n")
	hostWrite(t, r, "/swapfile", "small\n")
	sr.On("blkid -o value -s TYPE /swapfile", "swap")
	c.ensureSwapfile("/swapfile", 64, "10")
	if got := hostRead(t, r, "/swapfile"); got != "small\n" {
		t.Fatalf("active swapfile rewritten: %q", got)
	}
	if len(sr.CallsMatching("fallocate")) > 0 {
		t.Fatal("recreate ran for an active swapfile")
	}
	if len(sr.CallsMatching("swapon /swapfile")) > 0 {
		t.Fatal("swapon re-issued for an already-active file")
	}
}

// TestEnsureSwapfileChmodAndFstabReadArms — a staged file that the
// fake fallocate never materializes fails the 0600 chmod (counted);
// an unreadable fstab warns before the write path fails.
func TestEnsureSwapfileChmodAndFstabReadArms(t *testing.T) {
	t.Run("chmod_failed", func(t *testing.T) {
		_, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		// fallocate "succeeds" in the runner but no real file exists.
		sr.On("fallocate -l 64M /swapfile", "")
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the chmod-on-missing-file failure", c.errs)
		}
		if len(sr.CallsMatching("blkid")) > 0 {
			t.Fatal("signature probe ran although the swapfile never existed")
		}
	})
	t.Run("fstab_unreadable", func(t *testing.T) {
		r, sr, c := swapFixture(t, "")
		sr.On("swapon --show", "")
		swapFileSized(t, r, 64) // exists at the pinned size — no create
		sr.On("blkid -o value -s TYPE /swapfile", "swap")
		hostWrite(t, r, "/etc/fstab/keep", "blocker\n") // fstab as dir
		c.ensureSwapfile("/swapfile", 64, "10")
		if c.errs != 1 {
			t.Fatalf("errs = %d, want the failed fstab write counted", c.errs)
		}
	})
}

// exitErr — a REAL *exec.ExitError with the given code (local shell,
// no root/network): the only way blkid's exit-2 contract can be
// recognized via errors.As.
func exitErr(code int) error {
	cmd := exec.Command("sh", "-c", "exit "+itoa(code))
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		panic("exitErr: expected ExitError, got " + err.Error())
	}
	return ee
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
