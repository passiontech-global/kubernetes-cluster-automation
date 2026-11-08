// kmsg_rules_test.go — kernel-pressure: isHostOOMComm coverage and the
// page-alloc-failure latch the kmsg drain produces for
// workerhygiene's vm.compact_memory trigger.
package kernelfail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsHostOOMCommInfraDaemon(t *testing.T) {
	for comm, want := range map[string]bool{
		"kubelet":            true,
		"k0s":                true,
		"k0scontroller-shim": true, // k0s prefix
		"containerd":         true,
		"containerd-shim":    true, // substring
		// kernel-pressure additions.
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
	f := kfixture(t)
	kmsgFixture(t, f.deps,
		"python3: page allocation failure: order:4, mode:0x20",
		"order:0 allocation noise is routine — must not latch",
		"page allocation failure: order:2, mode:0x40")
	latch := filepath.Join(f.deps.StateDir, "state-page-alloc-failure")
	f.r.checkKernelDmesg()
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("state-page-alloc-failure latch missing")
	}
}

func TestKmsgClocksourceUnstableLatch(t *testing.T) {
	f := kfixture(t)
	kmsgFixture(t, f.deps,
		"kernel: Marking clocksource 'tsc' as unstable because Watchdog caught update",
		"clocksource: timekeeping watchdog on CPU0: Marking clocksource 'tsc' as unstable",
		"clocksource: Switched to clocksource hpet")
	latch := filepath.Join(f.deps.StateDir, "state-clocksource-unstable")
	f.r.checkKernelDmesg()
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("state-clocksource-unstable latch missing")
	}
}
