package pods_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestKonnUnitFileUnreadableAbortsPreservesLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.MkProc(t, 7101, "S", fmt.Sprintf(proxyCmdline, "10.9.9.9"), "NODE_IP=10.9.9.9\x00")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
		t.Fatal("setup: LatchKonnectivityIPMismatch not armed")
	}
	chk := wdepstest.Check[*pods.KonnCheck](e.H, wdeps.CheckKonn)
	if chk.Fails != 1 {
		t.Fatalf("setup Fails=%d want 1", chk.Fails)
	}

	unitFile := e.H.Cfg.K0sWorkerUnitFile
	if err := os.Chmod(unitFile, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unitFile, 0o644) })

	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
		t.Fatal("LatchKonnectivityIPMismatch falsely exited when K0sWorkerUnitFile returned EACCES")
	}
	if chk.Fails != 1 {
		t.Fatalf("Fails=%d want preserved 1", chk.Fails)
	}

	// Restore unit file with matching IP -> exits latch cleanly.
	if err := os.Chmod(unitFile, 0o644); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 7101, "S", fmt.Sprintf(proxyCmdline, "10.1.2.3"), "NODE_IP=10.1.2.3\x00")
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
		t.Fatal("LatchKonnectivityIPMismatch did not exit after recovery")
	}
}
