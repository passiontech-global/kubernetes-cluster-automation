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
