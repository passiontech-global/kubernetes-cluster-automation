// disk_slow_io_condition_test.go — disk-slow-io latch→condition wiring:
// state-disk-slow-io must flip the DiskSlowIO permanent
// NodeCondition, False without the latch.
package nodereporter

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// TestDiskSlowIOCondition: baseline False, True while
// state-disk-slow-io exists, back to False once the latch clears —
// the condition is the signal node-hang-precordon /
// descheduler-storm-gate consume (never a reboot trigger).
func TestDiskSlowIOCondition(t *testing.T) {
	e := fixture(t)
	if got := condEvalFor(t, e.r, "DiskSlowIO"); got.status != corev1.ConditionFalse {
		t.Fatalf("DiskSlowIO baseline=%v want False", got.status)
	}
	latch := filepath.Join(e.dir, "state-disk-slow-io")
	if err := os.WriteFile(latch, []byte("1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := condEvalFor(t, e.r, "DiskSlowIO")
	if got.status != corev1.ConditionTrue ||
		got.reason != "DiskSlowIODetected" {
		t.Fatalf("DiskSlowIO=%v/%s want True/DiskSlowIODetected",
			got.status, got.reason)
	}
	if want := "watchdog state disk-slow-io active since 1700000000"; got.message != want {
		t.Fatalf("message=%q want %q", got.message, want)
	}
	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	if got := condEvalFor(t, e.r, "DiskSlowIO"); got.status != corev1.ConditionFalse {
		t.Fatal("DiskSlowIO stuck True after latch removal")
	}
}
