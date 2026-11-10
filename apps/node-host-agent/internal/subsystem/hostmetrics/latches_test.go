package hostmetrics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func TestKernelKeysUsedRatio(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "key-users")
	cfg, _ := fixture(t)
	cfg.KeyUsersFile = f
	c := New(cfg)
	// Missing file → inconclusive, not zero.
	if _, ok := c.kernelKeysUsedRatio(); ok {
		t.Fatal("missing key-users reported as ok")
	}
	testutil.WriteFile(t, f,
		// Real /proc/key-users rows (this host): "uid: usage
		// nkeys/nikeys qnkeys/maxkeys qnbytes/maxbytes".
		"    0:    70 69/69 55/1000000 1326/25000000\n"+
			"  1000:     9 9/9 18/20 79/20000\n"+
			// Edge rows: a UID with zero keys parses to ratio 0, a
			// zero quota row is skipped (no division), malformed
			// lines never kill the parse.
			"  101:     1 0/0 0/200 0/20000\n"+
			"  102:     1 1/1 5/0 9/20000\n"+
			"junk\n")
	got, ok := c.kernelKeysUsedRatio()
	if !ok {
		t.Fatal("key-users not parsed")
	}
	// worst ratio = 18/20 = 0.9 (root row: 55/1000000 ≈ 0.000055)
	if got < 0.89 || got > 0.91 {
		t.Fatalf("ratio=%v want ~0.9", got)
	}
	// 0.9 > 0.80 → latch sets.
	c.Latches().updateKernelKeysLatch(got)
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-kernel-keys-pressure")); err != nil {
		t.Fatal("kernel-keys-pressure latch missing")
	}
}

func TestRefreshLatchesWritesFiles(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	c.Latches().refreshLatches(context.Background())
	// A healthy fixture clears/latches nothing fatal — the point is
	// the loop runs every contract file without panic.
}

// TestRefreshLatchesTouchesHeldLatches: every HELD latch the ticker
// knows — including the kernel-pressure and clocksource evidence
// latches, workerhygiene's MTU drift latch and the apiprober
// per-backend stale family (globbed) — gets its mtime refreshed, so
// the janitor's 24h reap cannot retire a live episode minted by
// another producer.
func TestRefreshLatchesTouchesHeldLatches(t *testing.T) {
	cfg, _ := fixture(t)
	// A FIXED clock — the touch stamps exactly this time, so the
	// assertion is an equality, not a window.
	fixed := time.Unix(1760000000, 0)
	cfg.Clock = timex.NewCell(func() time.Time { return fixed })
	c := New(cfg)
	now := fixed

	old := map[string]string{
		"state-page-alloc-failure":               "",
		"state-clocksource-unstable":             "",
		"state-cilium-mtu-drift":                 "",
		"state-apiserver-backend-stale-10-0-0-1": "",
	}
	for name := range old {
		p := filepath.Join(cfg.WatchdogStateDir, name)
		testutil.WriteFile(t, p, "1700000000\n")
		stamp := now.Add(-48 * time.Hour)
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	c.Latches().refreshLatches(context.Background())

	for name := range old {
		p := filepath.Join(cfg.WatchdogStateDir, name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s vanished during refresh: %v", name, err)
		}
		if !fi.ModTime().Equal(now) {
			t.Fatalf("%s mtime = %v, want the clock %v", name, fi.ModTime(), now)
		}
	}
}

// inodeStatfs returns a statfsFn stub reporting per-mount inode
// counts — used/total pairs drive the inode-pressure hysteresis exactly.
func inodeStatfs(vals map[string][2]uint64) func(string, *unix.Statfs_t) error {
	return func(path string, st *unix.Statfs_t) error {
		v, ok := vals[path]
		if !ok {
			return unix.ENOENT
		}
		st.Files = v[1]
		st.Ffree = v[1] - v[0]
		return nil
	}
}

// latchExists stats state-inode-pressure under the fixture state dir.
func latchExists(t *testing.T, cfg Config) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		latchdefs.LatchFilePrefix+latchdefs.LatchInodePressure))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// TestInodePressureHysteresis drives the inode-pressure latch through one full
// episode via the ticker (refreshLatches): enter at >=95% on any
// mount, HOLD between 90% and 95% (no flap), clear only when every
// mount is <=90%, and never clear on inconclusive evidence.
func TestInodePressureHysteresis(t *testing.T) {
	cfg, _ := fixture(t)
	logFile := filepath.Join(t.TempDir(), "watchdog.log")
	cfg.FilesystemTargets = []string{"/fake/etc", "/fake/k0s"}
	cfg.WatchdogLogFile = logFile
	c := New(cfg)
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/fake/etc": {960, 1000}, "/fake/k0s": {500, 1000},
	})
	l := c.Latches()

	// 96% on /fake/etc → enter, detail names the mount + ratio.
	l.refreshLatches(context.Background())
	if !latchExists(t, cfg) {
		t.Fatal("inode-pressure latch not set at 0.96")
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b),
		"STATE-ENTER: inode-pressure mount=/fake/etc ratio=0.960 >= 0.95") {
		t.Fatalf("STATE-ENTER line missing mount/ratio detail:\n%s", b)
	}

	// 92% (between thresholds) → the latch must HOLD.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/fake/etc": {920, 1000}, "/fake/k0s": {500, 1000},
	})
	l.refreshLatches(context.Background())
	if !latchExists(t, cfg) {
		t.Fatal("inode-pressure latch cleared inside the hysteresis band")
	}

	// Every mount <=90% → clear.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/fake/etc": {900, 1000}, "/fake/k0s": {500, 1000},
	})
	l.refreshLatches(context.Background())
	if latchExists(t, cfg) {
		t.Fatal("inode-pressure latch not cleared at 0.90")
	}

	// A Files==0 mount (no inode table) now counts as parsed healthy
	// — it must not re-enter even though /fake/k0s would parse below
	// the band.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/fake/etc": {0, 0}, "/fake/k0s": {500, 1000},
	})
	l.refreshLatches(context.Background())
	if latchExists(t, cfg) {
		t.Fatal("inode-pressure latch set from inconclusive evidence")
	}
	// A healthy (sub-threshold) full pass still exits cleanly — the
	// no-op exit path must leave the latch absent, not error.
	c.cfg.statfsFn = inodeStatfs(map[string][2]uint64{
		"/fake/etc": {10, 1000}, "/fake/k0s": {500, 1000},
	})
	l.refreshLatches(context.Background())
	if latchExists(t, cfg) {
		t.Fatal("inode-pressure latch appeared on a healthy pass")
	}
}

// TestKernelKeysGaugeEmitAndExit: the scrape-side gauge emits only
// while /proc/key-users parses, and the latch releases once the
// worst per-UID ratio falls back under the threshold.
func TestKernelKeysGaugeEmitAndExit(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.KeyUsersFile = filepath.Join(t.TempDir(), "key-users")
	testutil.WriteFile(t, cfg.KeyUsersFile,
		"  1000: 42 90/90 180/200 1800/20000\n") // qnkeys/maxkeys = 0.9
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_kernel_keys_used_ratio",
		map[string]string{"node": "node-a"}); !ok || v != 0.9 {
		t.Fatalf("kernel keys ratio=%v ok=%v want 0.9", v, ok)
	}

	l := c.Latches()
	latch := filepath.Join(cfg.WatchdogStateDir, "state-kernel-keys-pressure")
	l.updateKernelKeysLatch(0.9)
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("kernel-keys-pressure latch missing above the threshold")
	}
	l.updateKernelKeysLatch(0.1)
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("kernel-keys-pressure latch not released under the threshold")
	}
}

// TestSnapStaleLatchPathsEmptyDir: an empty state dir must not glob
// against the process CWD — the family lookup returns nil.
func TestSnapStaleLatchPathsEmptyDir(t *testing.T) {
	if got := snapStaleLatchPaths(""); got != nil {
		t.Fatalf(`snapStaleLatchPaths("") = %v, want nil`, got)
	}
	// A malformed glob (unclosed "[") errors — nil, never a panic.
	if got := snapStaleLatchPaths(filepath.Join(t.TempDir(), "[")); got != nil {
		t.Fatalf("bad-pattern glob = %v, want nil", got)
	}
}

// refreshLatches' signal-driven updaters — the PSI read, an
// ST_RDONLY statfs flag and a parseable key-users file each drive
// their latch (the earlier tests only exercised the mtime-refresh
// half with inconclusive inputs).
func TestRefreshLatchesSignalPaths(t *testing.T) {
	cfg, _ := fixture(t)
	logFile := filepath.Join(t.TempDir(), "watchdog.log")
	cfg.WatchdogLogFile = logFile

	// PSI over the enter threshold → state-node-overloaded.
	psi := filepath.Join(t.TempDir(), "cpu-pressure")
	testutil.WriteFile(t, psi, "some avg10=1.00 avg60=95.00 avg300=0.00 total=1\n")
	cfg.PSIFile = psi

	// One mount flagged ST_RDONLY (flag bit 1) → state-filesystem-readonly.
	cfg.FilesystemTargets = []string{"/fake/etc", "/fake/k0s"}
	cfg.statfsFn = func(path string, st *unix.Statfs_t) error {
		st.Files = 1000
		st.Ffree = 999
		if path == "/fake/etc" {
			st.Flags = 1 // ST_RDONLY
		}
		return nil
	}

	// key-users at 96% of the key quota → state-kernel-keys-pressure.
	ku := filepath.Join(t.TempDir(), "key-users")
	testutil.WriteFile(t, ku, "  1000: 42 96/96 192/200 1920/20000\n")
	cfg.KeyUsersFile = ku

	c := New(cfg)
	c.Latches().refreshLatches(context.Background())

	for _, name := range []string{
		latchdefs.LatchNodeOverloaded,
		latchdefs.LatchFilesystemReadonly,
		latchdefs.LatchKernelKeysPressure,
	} {
		p := filepath.Join(cfg.WatchdogStateDir,
			latchdefs.LatchFilePrefix+name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("state-%s missing after refresh: %v", name, err)
		}
	}
}
