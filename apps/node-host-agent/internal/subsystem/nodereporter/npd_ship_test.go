// npd_ship_test.go — the npd.Monitor → syncConditions shipping
// seam: monitor-computed condition state lands on the node ONE
// cycle after the monitor computes it (syncConditions runs first
// inside Cycle — the 2026-11-07 wedge fix — so the monitors ship
// the previous cycle's state). Monitor internals are covered by the
// npd package's own suite.
package nodereporter

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// TestMonitorConditionsShip: a kmsg hung-task record latches the
// permanent KernelDeadlock and an ro mount row latches
// ReadonlyFilesystem — both ship to the node status on the cycle
// after the monitors ran.
func TestMonitorConditionsShip(t *testing.T) {
	e := fixture(t)
	// An ro watched mount, plus a hung-task kmsg record inside the
	// 5m lookback window (the uptime fixture is 3600s).
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 ro,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(e.kmsg, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(
		"6,1,3599000000,-;INFO: task jbd2/vda1-8:439 blocked for more than 120 seconds.\n")
	_ = f.Close()

	e.cycle() // monitors compute AFTER this cycle's syncConditions…
	e.cycle() // …so the state ships here.

	if c := e.cond(t, "KernelDeadlock"); c.Status != corev1.ConditionTrue ||
		c.Reason != "KernelDeadlock" {
		t.Fatalf("KernelDeadlock = {%s %s}, want True/KernelDeadlock", c.Status, c.Reason)
	}
	if got := e.gauge("KernelDeadlock", "KernelDeadlock"); got != 1 {
		t.Fatalf("problem_gauge = %v, want 1", got)
	}
	if c := e.cond(t, "ReadonlyFilesystem"); c.Status != corev1.ConditionTrue ||
		c.Reason != "FilesystemIsReadOnly" {
		t.Fatalf("ReadonlyFilesystem = {%s %s}, want True/FilesystemIsReadOnly",
			c.Status, c.Reason)
	}
}
