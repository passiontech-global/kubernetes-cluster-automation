package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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
		"     0: 1234 5678 100 1000000 25000000\n"+
			"  1000: 42 82000 81000 100000 2500000\n")
	got, ok := c.kernelKeysUsedRatio()
	if !ok {
		t.Fatal("key-users not parsed")
	}
	// worst ratio = 81000/100000 = 0.81
	if got < 0.80 || got > 0.82 {
		t.Fatalf("ratio=%v want ~0.81", got)
	}
	// 0.81 > 0.80 → latch sets.
	c.Latches().updateKernelKeysLatch(got)
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-kernel-keys-pressure")); err != nil {
		t.Fatal("kernel-keys-pressure latch missing")
	}
}

func TestRefreshLatchesWritesFiles(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	c.Latches().refreshLatches()
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

	c.Latches().refreshLatches()

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
