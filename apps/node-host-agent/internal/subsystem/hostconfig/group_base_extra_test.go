// group_base_extra_test.go — groupBase coverage beyond the base
// suite: the inotify sysctl gates, modprobe/sysctl apply failures,
// the controller limits drop-in both ways, the multipath isolation
// drop-in, the logind inhibit-delay derivation table, the
// self-stage binary mode re-tighten + failed install, and the
// conntrack hashsize sizing arms (floor, live bump, refused write).
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// baseFixture — a reconciler + runner + cyc with the stock registry;
// seed extra files per test.
func baseFixture(t *testing.T, cluster string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// TestBaseInotifySysctlGates — a refused (non-printable) value skips
// its pair; a custom value renders verbatim.
func TestBaseInotifySysctlGates(t *testing.T) {
	r, _, c := baseFixture(t, `inotify_max_user_watches: "1\n2"
inotify_max_user_instances: "1024"
`)
	c.groupBase()
	f := hostRead(t, r, "/etc/sysctl.d/99-k8s-inotify.conf")
	if strings.Contains(f, "max_user_watches") {
		t.Fatalf("refused watches value rendered anyway:\n%s", f)
	}
	if !strings.Contains(f, "fs.inotify.max_user_instances = 1024") {
		t.Fatalf("custom instances value missing:\n%s", f)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want exactly the refused value", c.errs)
	}
}

// TestBaseModprobeAndSysctlFailures — BBR/conntrack modprobe failures
// and a failed `sysctl --system` apply each count; the files still
// land for the next boot.
func TestBaseModprobeAndSysctlFailures(t *testing.T) {
	r, sr, c := baseFixture(t, "")
	sr.FailOn("modprobe tcp_bbr", nil)
	sr.FailOn("modprobe nf_conntrack", nil)
	sr.FailOn("sysctl --system", nil)
	c.groupBase()
	if c.errs != 3 {
		t.Fatalf("errs = %d, want 2 modprobe + 1 sysctl counted", c.errs)
	}
	if !hostExists(r, "/etc/modules-load.d/interdc-bbr.conf") {
		t.Fatal("bbr module-load file not converged despite the modprobe failure")
	}
}

// TestBaseAbsentLimitVarsNoError — worker/controller nodes whose vars
// lack k0sworker/k0scontroller_limit_nofile converge clean: an absent
// var is skipped like the sysctl pairs, not refused (refusing the
// empty value would count an error every cycle and fail converge-once
// on healthy nodes).
func TestBaseAbsentLimitVarsNoError(t *testing.T) {
	r, _, c := baseFixture(t, "")
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service", "[Service]\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c.groupBase()
	if c.errs != 0 {
		t.Fatalf("healthy node without limit vars counted %d errors", c.errs)
	}
	if hostExists(r, "/etc/systemd/system/k0sworker.service.d/10-limits.conf") ||
		hostExists(r, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf") {
		t.Fatal("limits drop-in written from an absent var")
	}
}

// TestBaseControllerLimitsDropin — the controller fd-limits drop-in
// converges both ways: rendered on a valid var, refused+skipped on an
// unsafe one, daemon-reload only when it actually landed.
func TestBaseControllerLimitsDropin(t *testing.T) {
	r, sr, c := baseFixture(t, `k0scontroller_limit_nofile: "1048576"
`)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf")
	if !strings.Contains(f, "LimitNOFILE=1048576") || !strings.Contains(f, "LimitNPROC=infinity") {
		t.Fatalf("limits drop-in wrong:\n%s", f)
	}
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("limits drop-in did not daemon-reload")
	}

	// Refused value: the splice-shaped var must leave no drop-in.
	vars := writeVarsDir(t, `k0scontroller_limit_nofile: "1
2"
`)
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r2, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.groupBase()
	if hostExists(r2, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf") {
		t.Fatal("unsafe LimitNOFILE value rendered a drop-in")
	}
	if c2.errs == 0 {
		t.Fatal("refused LimitNOFILE did not count a cycle error")
	}
}

// TestBaseMultipathDropin — the multipathd blacklist only converges
// when multipath is actually present on the host.
func TestBaseMultipathDropin(t *testing.T) {
	r, _, c := baseFixture(t, "")
	c.groupBase()
	if hostExists(r, "/etc/multipath/conf.d/99-k8s-node-ops.conf") {
		t.Fatal("multipath drop-in created on a host without multipath")
	}
	hostWrite(t, r, "/etc/multipath.conf", "# defaults\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/multipath/conf.d/99-k8s-node-ops.conf")
	if !strings.Contains(f, `devnode "^(sd[a-z0-9]+`) {
		t.Fatalf("multipath blacklist missing:\n%s", f)
	}
}

// TestLogindInhibitDelaySecsTable — the kubelet graceful-shutdown
// window + 5s buffer, floored at 65s; unparsable/zero falls back to
// the 60s default (+ buffer).
func TestLogindInhibitDelaySecsTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"garbage", 65},
		{"0", 65},
		{"-5s", 65},
		{"45s", 65},
		{"60s", 65},
		{"70s", 75},
		{"10m", 605},
	} {
		if got := logindInhibitDelaySecs(tc.in); got != tc.want {
			t.Errorf("logindInhibitDelaySecs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestSelfStageBinaryModeRetighten — the host copy already carries
// this build but drifted to 0644: no rewrite, just the chmod back to
// 0755 (the hostPath consumer needs the exec bit).
func TestSelfStageBinaryModeRetighten(t *testing.T) {
	r, _, c := baseFixture(t, "")
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pagecache.Sha256File(src)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/usr/local/bin/node-host-agent", "")
	// Replace the seeded empty file with the REAL test binary content.
	bin, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	c.selfStageBinary()
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %v, want re-tightened 0755", fi.Mode().Perm())
	}
	got, err := pagecache.Sha256File(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"))
	if err != nil || got != sum {
		t.Fatalf("staged binary content churned (sha %v err %v)", got, err)
	}
	if c.errs != 0 {
		t.Fatalf("mode re-tighten counted errors: %d", c.errs)
	}
}

// TestSelfStageBinaryInstallFailure — the host copy drifts to OTHER
// content while the destination path is a directory: the atomic
// replace fails, the failure is counted once, and the node keeps its
// (stale) target.
func TestSelfStageBinaryInstallFailure(t *testing.T) {
	r, _, c := baseFixture(t, "")
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.selfStageBinary()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the failed install counted once", c.errs)
	}
}

// TestConntrackHashsizeArms — want = max(conntrack_max/4, 65536):
// the floor applies under a small pin, the live module parameter is
// bumped when smaller, an unparsable live file is skipped, and a
// refused write counts.
func TestConntrackHashsizeArms(t *testing.T) {
	t.Run("floor_65536", func(t *testing.T) {
		r, _, c := baseFixture(t, "conntrack_max: 100000\n")
		c.groupBase()
		f := hostRead(t, r, "/etc/modprobe.d/nf_conntrack.conf")
		if !strings.Contains(f, "hashsize=65536") {
			t.Fatalf("hashsize floor not applied:\n%s", f)
		}
	})
	t.Run("live_bump", func(t *testing.T) {
		r, _, c := baseFixture(t, "")
		hostWrite(t, r, "/sys/module/nf_conntrack/parameters/hashsize", "1024\n")
		c.groupBase()
		if got := strings.TrimSpace(hostRead(t, r, "/sys/module/nf_conntrack/parameters/hashsize")); got != "65536" {
			t.Fatalf("live hashsize = %q, want grown to 65536", got)
		}
	})
	t.Run("write_refused", func(t *testing.T) {
		r, _, c := baseFixture(t, "")
		p := filepath.Join(r.cfg.HostRoot, "/sys/module/nf_conntrack/parameters/hashsize")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("1024\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		c.groupBase()
		if c.errs == 0 {
			t.Fatal("refused hashsize grow did not count a cycle error")
		}
	})
}

// TestSysctlPtyMaxOverride — pty.max renders (gated on the procfs
// file the sandbox HostRoot seeds) with the vars override winning
// over the 16384 default.
func TestSysctlPtyMaxOverride(t *testing.T) {
	r, _, c := baseFixture(t, "pty_max: 4096\n")
	hostWrite(t, r, "/proc/sys/kernel/pty/max", "16384\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/sysctl.d/99-k8s-network-tuning.conf")
	if !strings.Contains(f, "kernel.pty.max = 4096") {
		t.Fatalf("pty_max override missing:\n%s", f)
	}

	// Default when the var is absent.
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r2, "/proc/sys/kernel/pty/max", "16384\n")
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.groupBase()
	if f := hostRead(t, r2, "/etc/sysctl.d/99-k8s-network-tuning.conf"); !strings.Contains(f, "kernel.pty.max = 16384") {
		t.Fatalf("pty default missing:\n%s", f)
	}
}
