// guards_pipe_write_test.go — pipe-write-freeze (A1) coverage: the
// state-S pipe_write persist window, the per-pod Warning Event
// dedupe + re-arm, the state-D exclusion (DstateCheck's class) and
// the host-process exclusion.
package guards_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// mkPipeWriteProc lays a fake process with the given state + wchan
// and its own cgroup file — inside a kubepods pod cgroup when uid
// is set (the podUIDForPID attribution the check shares with
// zombie/psi), in a host system.slice cgroup when uid is "".
func mkPipeWriteProc(t *testing.T, e *env, pid int, comm, state, wchan, uid string) {
	t.Helper()
	e.MkStatProc(t, pid, comm, state, wchan)
	cg := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
		strings.ReplaceAll(uid, "-", "_") + ".slice/cri-containerd-x.scope\n"
	if uid == "" {
		cg = "0::/system.slice/hostdaemon.service\n"
	}
	if err := os.WriteFile(filepath.Join(e.ProcDir, strconv.Itoa(pid), "cgroup"),
		[]byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
}

// pipeWriteEnv builds the hand-run CycleEnv for the fake proc tree.
func pipeWriteEnv(pod *corev1.Pod, pids ...int) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{
		WorkerActive: true,
		Pods:         []corev1.Pod{*pod},
		PidsOnce:     func() []int { return pids },
	}
}

// TestPipeWriteFreezePersistsTwoCyclesAndEvents — the roadmap A1
// contract: state-S + wchan=pipe_write counts only after the
// 2-cycle persist window, then lands ONE ContainerPipeWriteBlocked
// Warning on the owning pod (deduped for the rest of the freeze).
func TestPipeWriteFreezePersistsTwoCyclesAndEvents(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "frozen", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	mkPipeWriteProc(t, e, 700, "myapp", "S", "pipe_write", wdepstest.UIDA)
	run := func() {
		wdepstest.Check[*guards.PipeWriteCheck](h, wdeps.CheckPipeWrite).
			Run(ctx, pipeWriteEnv(pod, 700))
	}

	run() // streak 1 of 2 — inside the persist window, nothing yet
	if h.PipeBlockedProcs != 0 {
		t.Fatalf("blocked=%d on the first cycle (persist window not met)",
			h.PipeBlockedProcs)
	}
	if got := e.LogLines(t); strings.Contains(got, "pipe-write-freeze") {
		t.Fatalf("suspect line inside the persist window:\n%s", got)
	}
	run() // streak 2 — frozen, suspect line + event
	if h.PipeBlockedProcs != 1 {
		t.Fatalf("blocked=%d after two stuck cycles, want 1", h.PipeBlockedProcs)
	}
	if got := e.LogLines(t); !strings.Contains(got,
		"stuck in state-S pipe_write 2 cycles") {
		t.Fatalf("suspect line missing the persist evidence:\n%s", got)
	}
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerPipeWriteBlocked" {
		t.Fatalf("events=%+v want one ContainerPipeWriteBlocked", evs.Items)
	}
	if evs.Items[0].Regarding.Name != "frozen" {
		t.Fatalf("event regarding=%q want pod frozen", evs.Items[0].Regarding.Name)
	}
	run() // dedupe: the freeze persists, no second event
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("dedupe failed: %d events in one freeze", len(evs.Items))
	}
	if h.PipeBlockedProcs != 1 {
		t.Fatalf("blocked=%d while the freeze persists, want 1", h.PipeBlockedProcs)
	}

	// Recovery: the wchan drains — streak cleared, marker re-armed,
	// gauge drops without a fake 0 (it just reports this cycle).
	mkPipeWriteProc(t, e, 700, "myapp", "S", "0", wdepstest.UIDA)
	run()
	if h.PipeBlockedProcs != 0 {
		t.Fatalf("blocked=%d after recovery, want 0", h.PipeBlockedProcs)
	}

	// Re-freeze on the SAME pid: the re-armed marker must allow a
	// fresh event after the window rebuilds (a pod recovered and
	// froze again re-pages). Advance the fixture clock so the new
	// EventTime/name differs (the frozen clock would mint an
	// identical event name).
	e.Fixture.Now = e.Fixture.Now.Add(time.Minute)
	mkPipeWriteProc(t, e, 700, "myapp", "S", "pipe_write", wdepstest.UIDA)
	run()
	run()
	evs, _ = e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("re-freeze events=%d, want a fresh event", len(evs.Items))
	}
}

// TestPipeWriteFreezeIgnoresDStateAndHostProcs — a "D" state
// pipe_write is the d-state-storm detector's class, not this one;
// a process outside pod cgroups (host daemon, shim) is never a
// candidate.
func TestPipeWriteFreezeIgnoresDStateAndHostProcs(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "frozen", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	// pid 701: pod process, but state D — DstateCheck's domain.
	mkPipeWriteProc(t, e, 701, "myapp", "D", "pipe_write", wdepstest.UIDA)
	// pid 702: state S + pipe_write but a host system.slice cgroup —
	// excluded by attribution, not by its own state.
	mkPipeWriteProc(t, e, 702, "hostdaemon", "S", "pipe_write", "")
	run := func() {
		wdepstest.Check[*guards.PipeWriteCheck](h, wdeps.CheckPipeWrite).
			Run(ctx, pipeWriteEnv(pod, 701, 702))
	}
	run()
	run()
	if h.PipeBlockedProcs != 0 {
		t.Fatalf("blocked=%d, want 0 (D-state and host procs excluded)",
			h.PipeBlockedProcs)
	}
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 0 {
		t.Fatalf("events=%d, want 0", len(evs.Items))
	}
}
