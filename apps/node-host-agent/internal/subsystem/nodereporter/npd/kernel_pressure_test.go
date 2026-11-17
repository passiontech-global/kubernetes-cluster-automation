// kernel_pressure_test.go — kernel-pressure temp rules:
// PageAllocFailure, NeighborTableOverflow, NetdevTxTimeout,
// TCPMemoryPressure as counter+Event rules.
package npd

import (
	"context"
	"testing"
)

func TestKernelPressureTempRules(t *testing.T) {
	e := fixture(t)
	for reason, msg := range map[string]string{
		"PageAllocFailure":      "python3: page allocation failure: order:4, mode:0x20",
		"NeighborTableOverflow": "neighbour: arp_cache: neighbor table overflow!",
		"NetdevTxTimeout":       "NETDEV WATCHDOG: ens3 (virtio_net): transmit queue 0 timed out",
		"TCPMemoryPressure":     "TCP: out of memory -- consider tuning tcp_mem",
	} {
		e.m.processKernelLine(context.Background(), e.sink, msg)
		if got := e.sink.counter(reason); got != 1 {
			t.Fatalf("problem_counter{%s}=%v want 1", reason, got)
		}
	}
	// Negative matches — routine lines must not trip the new rules.
	for _, msg := range []string{
		"page allocation failure: order:0, mode:0x20",
		"neighbour: table is fine",
		"TCP: reno recovery",
	} {
		e.m.processKernelLine(context.Background(), e.sink, msg)
	}
	for _, reason := range []string{"PageAllocFailure", "NeighborTableOverflow",
		"NetdevTxTimeout", "TCPMemoryPressure"} {
		if got := e.sink.counter(reason); got != 1 {
			t.Fatalf("problem_counter{%s}=%v want still 1 (no false positive)", reason, got)
		}
	}
}

// TestPCIeBusErrorKernelABICompat pins the >=5.7/5.18 kmsg
// spellings on the NPD temporary rule — same drift as kernelfail's
// pcieNVMeResetRe, kept in parity so NPD Events don't go blind on
// newer kernels.
func TestPCIeBusErrorKernelABICompat(t *testing.T) {
	e := fixture(t)
	for _, msg := range []string{
		"pcieport 0000:00:1c.0: AER: Uncorrectable (Fatal) error received: 0000:00:1c.0",
		"pcieport 0000:00:1c.0: PCIe Bus Error: severity=Uncorrectable, type=Fatal",
		"nvme nvme0: I/O tag 12 on qid 1 timeout, reset controller",
	} {
		e.m.processKernelLine(context.Background(), e.sink, msg)
	}
	if got := e.sink.counter("PCIeBusError"); got != 3 {
		t.Fatalf("problem_counter{PCIeBusError}=%v want 3", got)
	}
}
