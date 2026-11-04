package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"
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
	write(t, f,
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
	c.updateKernelKeysLatch(got)
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-kernel-keys-pressure")); err != nil {
		t.Fatal("kernel-keys-pressure latch missing")
	}
}

func TestRefreshLatchesWritesFiles(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	c.refreshLatches()
	// A healthy fixture clears/latches nothing fatal — the point is
	// the loop runs every contract file without panic.
}
