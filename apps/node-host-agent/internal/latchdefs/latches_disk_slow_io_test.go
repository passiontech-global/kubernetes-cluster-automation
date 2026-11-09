// latches_disk_slow_io_test.go — disk-slow-io latch registry coverage: the
// disk-slow-io latch is a known workerhygiene latch so the
// janitor's known/unknown reap never classifies it as foreign.
package latchdefs

import "testing"

// TestDiskSlowIOLatchRegistered: LatchDiskSlowIO must round-trip
// through the registry — an unregistered name would be reaped as
// "unknown" by the janitor while the condition is live.
func TestDiskSlowIOLatchRegistered(t *testing.T) {
	if LatchDiskSlowIO != "disk-slow-io" {
		t.Fatalf("LatchDiskSlowIO=%q want \"disk-slow-io\"", LatchDiskSlowIO)
	}
	if !KnownLatchName(LatchDiskSlowIO) {
		t.Fatal("disk-slow-io not in the known-latch registry")
	}
	found := false
	for _, d := range LatchDefs {
		if d.Name == LatchDiskSlowIO {
			found = true
			if d.Owner != "workerhygiene" {
				t.Fatalf("disk-slow-io owner=%q want workerhygiene", d.Owner)
			}
			if d.Prefix {
				t.Fatal("disk-slow-io marked as a parameterized family")
			}
		}
	}
	if !found {
		t.Fatal("disk-slow-io missing from LatchDefs")
	}
}
