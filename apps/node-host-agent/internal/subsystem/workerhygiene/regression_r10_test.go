package workerhygiene

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10CtrMetaJournalOnceErrorInHygieneCyclePreservesLatch(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1, "S", "init", "")

	journalOut := "Nov 10 01:00:00 node containerd: failed to loadmeta: invalid freelist page"
	var journalErr error
	e.H.Cfg.Seams.Host.JournalFn = func(context.Context) (string, error) {
		return journalOut, journalErr
	}

	// Cycles 1-2: corruption signature in shared k0sworker journal snapshot arms LatchContainerdCorrupt.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("setup: LatchContainerdCorrupt not armed via Hygiene.Cycle")
	}
	chk := wdepstest.Check[*ctr.CtrMetaCheck](e.H, wdeps.CheckCtrMeta)

	// Cycle 3: JournalFn fails (ClassFailed) in production Hygiene.Cycle (MetaJournalFn == nil).
	// Must abort and preserve LatchContainerdCorrupt and fails streak.
	journalOut = ""
	journalErr = errors.New("journalctl exited 1: EACCES")
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt falsely exited in Hygiene.Cycle on JournalFn error")
	}
	if chk.Name() != wdeps.CheckCtrMeta {
		t.Fatalf("unexpected check name %q", chk.Name())
	}

	// Cycle 4: journalctl reports no journal files (ClassFilesGone) -> still aborts and preserves latch.
	journalOut = "No journal files were found."
	journalErr = nil
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrMeta, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2 on ClassFilesGone", got)
	}
	if !e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt falsely exited in Hygiene.Cycle on ClassFilesGone")
	}

	// Cycle 5: quiet healthy unit (ClassEmpty: "", nil) keeps JournalOK()==true and exits cleanly.
	journalOut = ""
	journalErr = nil
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt did not exit on clean quiet journal (ClassEmpty)")
	}
}
