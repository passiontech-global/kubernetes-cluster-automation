// kmsg_rules_test.go — W13-KR1: isHostOOMComm coverage and the
// page-alloc-failure latch the kmsg drain produces for
// workerhygiene's vm.compact_memory trigger.
package hostmetrics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsHostOOMCommWave13(t *testing.T) {
	for comm, want := range map[string]bool{
		"kubelet":            true,
		"k0s":                true,
		"k0scontroller-shim": true, // k0s prefix
		"containerd":         true,
		"containerd-shim":    true, // substring
		// W13-KR1 additions.
		"nebula":          true,
		"haproxy":         true,
		"coredns":         true,
		"postgres":        true,
		"pgbouncer":       true,
		"cilium-agent":    true,
		"cilium-envoy":    true,
		"cilium-operator": true,
		"node-host-agent": true,
		"etcd":            false,
		"somepod":         false,
		"sshd":            false,
	} {
		if got := isHostOOMComm(comm); got != want {
			t.Fatalf("isHostOOMComm(%q)=%v want %v", comm, got, want)
		}
	}
}

func TestKmsgPageAllocLatch(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	kmsgFixture(t, cfg,
		"python3: page allocation failure: order:4, mode:0x20",
		"order:0 allocation noise is routine — must not latch",
		"page allocation failure: order:2, mode:0x40")
	latch := filepath.Join(cfg.WatchdogStateDir, "state-page-alloc-failure")
	c.Latches().checkKernelDmesg()
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("state-page-alloc-failure latch missing")
	}
}
