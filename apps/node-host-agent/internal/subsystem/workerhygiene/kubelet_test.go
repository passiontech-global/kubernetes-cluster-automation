// kubelet_test.go — check 4 kubelet-runtime-stall (05) and check 5
// kubelet-watch-wedge (06) restart remedies.
package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

// --- check 4: kubelet-stall (05) ---

func TestKubeletStall10250DownRestarts(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("connection refused")
	latch := filepath.Join(e.state, "state-kubelet-runtime-stall")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing after %d cycles: %v", 2, err)
	}
	if !e.sdRan("systemctl restart k0sworker.service") {
		t.Fatalf("k0sworker restart not issued, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
	if e.h.stallFails != 0 {
		t.Fatalf("stallFails=%d want 0 after action", e.h.stallFails)
	}
	if !strings.Contains(logLines(t, e), "ACTION: restarting k0sworker - kubelet-10250-down") {
		t.Fatalf("missing ACTION log:\n%s", logLines(t, e))
	}
}

// TestKubeletStall10250AuthResponseIsUp: kubelet denying anonymous
// /healthz with 401/403 is an ALIVE listener answering an auth
// refusal — the anonymous probe read it as down and spent k0sworker
// restarts on a healthy kubelet (prod false positive). Any HTTP code
// must count as up; only transport errors count as down.
func TestKubeletStall10250AuthResponseIsUp(t *testing.T) {
	for _, code := range []int{401, 403} {
		t.Run(fmt.Sprintf("code-%d", code), func(t *testing.T) {
			e := fixture(t)
			e.status[defaultKubeletHealthzURL] = code
			latch := filepath.Join(e.state, "state-kubelet-runtime-stall")
			for i := 0; i < 3; i++ {
				e.h.Cycle(context.Background())
			}
			if _, err := os.Stat(latch); !os.IsNotExist(err) {
				t.Fatalf("stall latch on %d (listener answered — alive)", code)
			}
			if e.sdRan("restart k0sworker.service") {
				t.Fatalf("restart on %d auth response", code)
			}
			if e.h.stallFails != 0 {
				t.Fatalf("stallFails=%d want 0 — %d counts as alive",
					e.h.stallFails, code)
			}
		})
	}
}

// TestKubeletStall10250AuthClearsStaleEvidence: a listener that went
// from unreachable to answering 401 has RECOVERED — the fail streak
// and any stale runtime-stall latch must clear, not stay latched for
// the NHC→SNR escalation path.
func TestKubeletStall10250AuthClearsStaleEvidence(t *testing.T) {
	e := fixture(t)
	latch := filepath.Join(e.state, "state-kubelet-runtime-stall")
	e.h.state.Enter("kubelet-runtime-stall", "test")
	e.h.stallFails = 1
	e.status[defaultKubeletHealthzURL] = 401
	e.h.Cycle(context.Background())
	if e.h.stallFails != 0 {
		t.Fatalf("stallFails=%d want 0 after 401 answer", e.h.stallFails)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("runtime-stall latch kept after the listener answered 401")
	}
}

// TestKubeletStall10250ProbeSendsBearerToken: kubelet :10250 denies
// anonymous /healthz — the SA token from KubeletTokenPath must ride
// the probe (syncloop parity) so auth-requiring clusters return the
// real verdict.
func TestKubeletStall10250ProbeSendsBearerToken(t *testing.T) {
	e := fixture(t)
	tok := filepath.Join(e.state, "sa-token")
	writeFile(t, tok, "tok-abc-123\n")
	e.h.cfg.Kubelet.TokenPath = tok
	e.h.Cycle(context.Background())
	if got := e.bearer[defaultKubeletHealthzURL]; got != "tok-abc-123" {
		t.Fatalf("10250 probe bearer = %q, want the SA token", got)
	}
}

func TestKubeletStallPhantomPods(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Zero live tasks (task root exists but is empty) → phantom-pods.
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); err != nil {
		t.Fatalf("stall latch missing: %v", err)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for phantom pods")
	}
	if !strings.Contains(logLines(t, e), "phantom-pods poddirs=5 tasks=0") {
		t.Fatalf("missing phantom-pods log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallLiveTasksNoRestart(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A live task means containerd is fine — kubelet healthz answers.
	e.mkProc(t, 9001, "S", "", "")
	e.mkTask(t, uidA, "app", 9001)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch with live tasks")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart with live tasks")
	}
}

func TestKubeletStallOverloadedSuppresses(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("refused")
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"), "1\n")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch written under overload (amplifier)")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart under overload")
	}
	if !strings.Contains(logLines(t, e), "suppressed-overloaded") {
		t.Fatalf("missing suppression log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallCooldownAndSettle(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("refused")
	// Freshly spent budget → cooldown blocks the restart.
	writeFile(t, filepath.Join(e.state, "last-restart"),
		fmt.Sprintf("%d\n", e.now.Unix()))
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart inside 30m cooldown")
	}
	// Now the budget is old enough but k0sworker just restarted —
	// the settle gate takes over (uptimeµs - 60s → age 60s < 180s).
	e.now = e.now.Add(time.Hour)
	e.sdReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart while k0sworker not settled (<180s active)")
	}
	if !strings.Contains(logLines(t, e), "not settled") {
		t.Fatalf("missing settle log:\n%s", logLines(t, e))
	}
}

// --- check 5: kubelet-watch-wedge (06) ---

// assignedPod is an old non-terminating pod on node-a with no kubelet
// pod dir — watch-wedge evidence.
func assignedPod(e *env, name, uid string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(uid),
			CreationTimestamp: metav1.NewTime(e.now.Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestKubeletWatchWedgeRestarts(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen-pod", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.state, "state-kubelet-watch-wedge")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("wedge latch missing: %v", err)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for watch wedge")
	}
	if !strings.Contains(logLines(t, e), "kubelet-watch-wedge unseen-pods=1") {
		t.Fatalf("missing wedge log:\n%s", logLines(t, e))
	}
}

func TestKubeletWatchWedgeYoungAndDirsSkipped(t *testing.T) {
	e := fixture(t)
	// Too young (below KubeletWatchMinAge).
	young := assignedPod(e, "young", uidA, 2*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), young, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Old but the pod dir EXISTS (kubelet admitted it).
	old := assignedPod(e, "admitted", uidB, 30*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.kubepods, uidB), 0o755); err != nil {
		t.Fatal(err)
	}
	// Terminating / Succeeded / Failed are skipped entirely.
	term := assignedPod(e, "term", uidC, 30*time.Minute)
	ts := metav1.NewTime(e.now.Add(-time.Minute))
	term.DeletionTimestamp = &ts
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), term, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	done := assignedPod(e, "done", uidD, 30*time.Minute)
	done.Status.Phase = corev1.PodSucceeded
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), done, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on ineligible pods")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart on ineligible pods")
	}
}

func TestKubeletWatchWedgeUpstreamGate(t *testing.T) {
	e := fixture(t)
	e.h.cfg.APIBackends = []string{"10.0.0.1:6443", "10.0.0.2:6443"}
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.state, "state-kubelet-watch-wedge")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing: %v", err)
	}
	// Only ONE backend stale → not an upstream wedge → restart.
	writeFile(t, filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-1"), "1\n")
	e.h.watch.fails = 2
	e.h.Cycle(context.Background())
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("restart blocked by partial staleness")
	}
	// ALL backends stale → upstream gate blocks the restart.
	e.sdcmds = nil
	writeFile(t, filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-2"), "1\n")
	e.h.watch.fails = 2
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart fired despite all backends stale")
	}
	if !strings.Contains(logLines(t, e), "api backend stale") {
		t.Fatalf("missing upstream-gate log:\n%s", logLines(t, e))
	}
}

func TestKubeletWatchWedgeAPIFailKeepsLatch(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-kubelet-watch-wedge"), "1\n")
	e.cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); err != nil {
		t.Fatal("latch cleared on inconclusive (API-failed) cycle")
	}
}

// TestKubeletWatchWedgePodsDirGoneInconclusive: with the pods ROOT
// itself gone/unreadable every per-pod stat fails and ALL pods would
// count "missing" — the sweep must abort instead of latching a false
// wedge and spending a k0sworker restart on a filesystem blip.
func TestKubeletWatchWedgePodsDirGoneInconclusive(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.kubepods); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on unstatable pods dir")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart spent on unstatable pods dir")
	}
}

// TestKubeletWatchWedgePodsDirIsFileInconclusive: a REGULAR FILE at
// the pods-root path stats cleanly but every per-pod join then fails
// ENOTDIR — ALL assigned pods would count "missing" → the same false
// wedge + wasted k0sworker restart as the dir-gone case. The IsDir
// guard takes the same inconclusive path.
func TestKubeletWatchWedgePodsDirIsFileInconclusive(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.kubepods); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.kubepods, "not a dir\n")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on file-as-pods-dir")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart spent on file-as-pods-dir")
	}
	if !strings.Contains(logLines(t, e), "not a directory") {
		t.Fatalf("missing inconclusive log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallStoppedTaskRecordsNotPhantom(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Drained/evicted node shape: pod dirs remain, task dirs exist
	// but every init pid is DEAD (STOPPED records still count, like
	// `ctr tasks ls | wc -l` — not phantom).
	e.mkTask(t, uidA, "app", 0)
	e.mkTask(t, "uid-b-dead-pod-01234", "app", 9999) // dead pid (not in e.live)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("phantom-pods restart with stopped task records")
	}
}
