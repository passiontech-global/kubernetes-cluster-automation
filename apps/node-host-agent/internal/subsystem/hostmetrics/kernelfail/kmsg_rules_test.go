// kmsg_rules_test.go — kernel-pressure: isHostOOMComm coverage and the
// page-alloc-failure latch the kmsg drain produces for
// workerhygiene's vm.compact_memory trigger.
package kernelfail

import (
	"context"
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
	f.r.checkKernelDmesg(context.Background())
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
	f.r.checkKernelDmesg(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("state-clocksource-unstable latch missing")
	}
}

// TestKernelLogABICompat pins the Linux kernel ABI/log-format drift
// the P0-12 audit caught: PCIe AER severity renamed
// "Uncorrected"→"Uncorrectable" in >=5.7, NVMe resets print
// "I/O tag <n> ... reset controller" in >=5.18, and NETDEV WATCHDOG
// moved the iface into a driver/pci prefix in >=6.3. Old AND new
// spellings must classify identically.
func TestKernelLogABICompat(t *testing.T) {
	// AER — both severity spellings arm the acute/fatal regexes.
	for _, msg := range []string{
		"pcieport 0000:00:1c.0: AER: Uncorrected (Fatal) error received: 0000:00:1c.0",
		"pcieport 0000:00:1c.0: AER: Uncorrectable (Fatal) error received: 0000:00:1c.0",
		"pcieport 0000:00:1c.0: PCIe Bus Error: severity=Uncorrected, type=Fatal",
		"pcieport 0000:00:1c.0: PCIe Bus Error: severity=Uncorrectable, type=Fatal",
	} {
		if !pcieAERFatalRe.MatchString(msg) || !pcieNVMeResetRe.MatchString(msg) {
			t.Fatalf("AER regex blind on %q", msg)
		}
	}
	// NVMe — legacy "I/O <n> ... resetting controller" and the
	// >=5.18 "I/O tag <n> ... reset controller" both classify.
	for _, msg := range []string{
		"nvme nvme0: I/O 12 on cpu 3 timeout, resetting controller",
		"nvme nvme0: I/O tag 12 on qid 1 timeout, reset controller",
	} {
		if !nvmeResetRe.MatchString(msg) || !pcieNVMeResetRe.MatchString(msg) {
			t.Fatalf("NVMe regex blind on %q", msg)
		}
	}
	// Corrected-severity noise must stay OUT (classification
	// contract: only fatal/uncorrectable arms the latch).
	for _, msg := range []string{
		"AER: Corrected error received",
		"PCIe Bus Error: severity=Corrected",
	} {
		if pcieAERFatalRe.MatchString(msg) {
			t.Fatalf("corrected severity false-positived: %q", msg)
		}
	}
	// NETDEV WATCHDOG — legacy puts the iface after the colon;
	// >=6.3 puts "CPU: <N>:" there and moves the iface into the
	// driver/pci prefix. netdevTxIface must resolve BOTH.
	for msg, want := range map[string]string{
		"NETDEV WATCHDOG: eth0 (e1000e): transmit queue 0 timed out":                     "eth0",
		"eth0: NETDEV WATCHDOG: transmit queue 0 timed out":                              "eth0",
		"igb 0000:02:00.0 eno1: NETDEV WATCHDOG: CPU: 5: transmit queue 0 timed out":     "eno1",
		"ixgbe 0000:04:00.1 ens3f1: NETDEV WATCHDOG: CPU: 2: transmit queue 3 timed out": "ens3f1",
	} {
		if got := netdevTxIface(msg); got != want {
			t.Fatalf("netdevTxIface(%q)=%q want %q", msg, got, want)
		}
		if !netdevTxTimeoutRe.MatchString(msg) {
			t.Fatalf("tx-timeout regex blind on %q", msg)
		}
	}
}
