package guards_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10DstateCheckAllStatsUnreadableAbortsPreservesLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.MkStatProc(t, 1001, "runc", "D", "")
	e.MkStatProc(t, 1002, "containerd", "D", "")

	// Cycles 1-2 via Hygiene.Cycle (uses StatsOnce) arm LatchDStateStorm.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("setup: LatchDStateStorm not armed")
	}

	// chmod 0o000 all /proc/<pid>/stat files -> must abort and preserve LatchDStateStorm.
	for _, pid := range []string{"1001", "1002"} {
		p := filepath.Join(e.ProcDir, pid, "stat")
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	}
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDState, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("LatchDStateStorm falsely exited when all /proc/<pid>/stat returned EACCES")
	}

	// Restore readable healthy S-state -> exits LatchDStateStorm cleanly.
	for _, pid := range []string{"1001", "1002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.MkStatProc(t, 1001, "runc", "S", "")
	e.MkStatProc(t, 1002, "containerd", "S", "")
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("LatchDStateStorm did not exit after recovery")
	}

	// ENOENT-only exited PIDs still exit cleanly when latch is armed.
	e.MkStatProc(t, 1001, "runc", "D", "")
	e.MkStatProc(t, 1002, "containerd", "D", "")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("re-arm failed")
	}
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "1001"))
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "1002"))
	e.H.Check(wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{1001, 1002} },
		PidsOK:       func() bool { return true },
	})
	if e.H.State.Exists(latchdefs.LatchDStateStorm) {
		t.Fatal("expected ENOENT-only exited PIDs to clear LatchDStateStorm")
	}
}

func TestR10ZombieStormAllStatsUnreadableAbortsPreservesLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.Pressure.ZombieStormThreshold = 1
	// Parent 2000 + two zombie children 2001, 2002.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2000", "stat"),
		"2000 (parent) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 111 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2001", "stat"),
		"2001 (z1) Z 2000 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 112 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2002", "stat"),
		"2002 (z2) Z 2000 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 113 0 0\n")

	// Cycles 1-2 arm LatchZombieStorm.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("setup: LatchZombieStorm not armed")
	}

	// chmod 0o000 all /proc/<pid>/stat files -> must abort without clearing LatchZombieStorm or streaks.
	for _, pid := range []string{"2000", "2001", "2002"} {
		p := filepath.Join(e.ProcDir, pid, "stat")
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	}
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckZombieStorm, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm falsely exited when all /proc/<pid>/stat returned EACCES")
	}

	// Restore readable stats while zombies persist (with ConsecNeeded=3 check or streak preservation):
	// First verify with ConsecNeeded=2 that restoring readable stats keeps LatchZombieStorm armed,
	// and clearing zombies exits cleanly.
	for _, pid := range []string{"2000", "2001", "2002"} {
		if err := os.Chmod(filepath.Join(e.ProcDir, pid, "stat"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// While zombies still exist, no second ACTION line should be emitted (streak > ConsecNeeded, not reset to 0->2!).
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm exited while zombies persisted after stat recovery")
	}
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "2001"))
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "2002"))
	e.H.Cycle(context.Background())
	if e.H.State.Exists(latchdefs.LatchZombieStorm) {
		t.Fatal("LatchZombieStorm did not exit after recovery")
	}
}

func TestR10PipeWriteCheckAPIOKFalseDefersEventUntilRecovery(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ghost-pod",
			Namespace: "default",
			UID:       types.UID(wdepstest.UIDA),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "700", "stat"),
		"700 (myapp) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "700", "wchan"), "pipe_write\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "700", "cgroup"),
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+
			strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-abc.scope\n")

	chk := e.H.Check(wdeps.CheckPipeWrite)
	pidsFn := func() []int { return []int{700} }
	pidsOK := func() bool { return true }

	// Cycles 1-2 with APIOK=false (pod list unavailable): must NOT mark evented[uid]=true.
	downEnv := &wdeps.CycleEnv{WorkerActive: true, APIOK: false, PidsOnce: pidsFn, PidsOK: pidsOK}
	chk.Run(context.Background(), downEnv)
	chk.Run(context.Background(), downEnv)

	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 0 {
		t.Fatalf("unexpected events while APIOK=false: %+v", evs.Items)
	}

	// Cycle 3: API recovers with pod present -> ContainerPipeWriteBlocked Warning Event MUST be emitted!
	upEnv := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*pod},
		PidsOnce:     pidsFn,
		PidsOK:       pidsOK,
	}
	chk.Run(context.Background(), upEnv)
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerPipeWriteBlocked" {
		t.Fatalf("events=%+v want 1 ContainerPipeWriteBlocked after API recovery", evs.Items)
	}

	// Cycle 4: still frozen -> event remains deduped (count stays 1).
	chk.Run(context.Background(), upEnv)
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 {
		t.Fatalf("events=%d want 1 (deduped)", len(evs.Items))
	}
}
