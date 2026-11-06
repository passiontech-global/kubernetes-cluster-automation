// kubelet_test.go — check 4 kubelet-runtime-stall (05) and check 5
// kubelet-watch-wedge (06) restart remedies.
package kubelet_test

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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- check 4: kubelet-stall (05) ---

func TestKubeletStall10250DownRestarts(t *testing.T) {
	e := fixture(t)
	e.Probes[wdeps.DefaultKubeletHealthzURL] = errors.New("connection refused")
	latch := filepath.Join(e.StateDir, "state-kubelet-runtime-stall")

	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing after %d cycles: %v", 2, err)
	}
	if !e.SDRan("systemctl restart k0sworker.service") {
		t.Fatalf("k0sworker restart not issued, cmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
	if wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails != 0 {
		t.Fatalf("stallFails=%d want 0 after action", wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails)
	}
	if !strings.Contains(e.LogLines(t), "ACTION: restarting k0sworker - kubelet-10250-down") {
		t.Fatalf("missing ACTION log:\n%s", e.LogLines(t))
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
			e.Status[wdeps.DefaultKubeletHealthzURL] = code
			latch := filepath.Join(e.StateDir, "state-kubelet-runtime-stall")
			for i := 0; i < 3; i++ {
				e.H.Cycle(context.Background())
			}
			if _, err := os.Stat(latch); !os.IsNotExist(err) {
				t.Fatalf("stall latch on %d (listener answered — alive)", code)
			}
			if e.SDRan("restart k0sworker.service") {
				t.Fatalf("restart on %d auth response", code)
			}
			if wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails != 0 {
				t.Fatalf("stallFails=%d want 0 — %d counts as alive",
					wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails, code)
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
	latch := filepath.Join(e.StateDir, "state-kubelet-runtime-stall")
	e.H.State.Enter("kubelet-runtime-stall", "test")
	wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails = 1
	e.Status[wdeps.DefaultKubeletHealthzURL] = 401
	e.H.Cycle(context.Background())
	if wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails != 0 {
		t.Fatalf("stallFails=%d want 0 after 401 answer", wdepstest.Check[*kubelet.StallCheck](e.H, wdeps.CheckStall).Fails)
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
	tok := filepath.Join(e.StateDir, "sa-token")
	wdepstest.WriteFile(t, tok, "tok-abc-123\n")
	e.H.Cfg.Kubelet.TokenPath = tok
	e.H.Cycle(context.Background())
	if got := e.Bearer[wdeps.DefaultKubeletHealthzURL]; got != "tok-abc-123" {
		t.Fatalf("10250 probe bearer = %q, want the SA token", got)
	}
}

func TestKubeletStallPhantomPods(t *testing.T) {
	e := fixture(t)
	for i := 0; i < kubelet.PoddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.KubepodsDir, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Zero live tasks (task root exists but is empty) → phantom-pods.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-runtime-stall")); err != nil {
		t.Fatalf("stall latch missing: %v", err)
	}
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for phantom pods")
	}
	if !strings.Contains(e.LogLines(t), "phantom-pods poddirs=5 tasks=0") {
		t.Fatalf("missing phantom-pods log:\n%s", e.LogLines(t))
	}
}

func TestKubeletStallLiveTasksNoRestart(t *testing.T) {
	e := fixture(t)
	for i := 0; i < kubelet.PoddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.KubepodsDir, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A live task means containerd is fine — kubelet healthz answers.
	e.MkProc(t, 9001, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "app", 9001)
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch with live tasks")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart with live tasks")
	}
}

func TestKubeletStallOverloadedSuppresses(t *testing.T) {
	e := fixture(t)
	e.Probes[wdeps.DefaultKubeletHealthzURL] = errors.New("refused")
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-node-overloaded"), "1\n")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch written under overload (amplifier)")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart under overload")
	}
	if !strings.Contains(e.LogLines(t), "suppressed-overloaded") {
		t.Fatalf("missing suppression log:\n%s", e.LogLines(t))
	}
}

func TestKubeletStallCooldownAndSettle(t *testing.T) {
	e := fixture(t)
	e.Probes[wdeps.DefaultKubeletHealthzURL] = errors.New("refused")
	// Freshly spent budget → cooldown blocks the restart.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "last-restart"),
		fmt.Sprintf("%d\n", e.Now.Unix()))
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart inside 30m cooldown")
	}
	// Now the budget is old enough but k0sworker just restarted —
	// the settle gate takes over (uptimeµs - 60s → age 60s < 180s).
	e.Now = e.Now.Add(time.Hour)
	e.SDReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart while k0sworker not settled (<180s active)")
	}
	if !strings.Contains(e.LogLines(t), "not settled") {
		t.Fatalf("missing settle log:\n%s", e.LogLines(t))
	}
}

// --- check 5: kubelet-watch-wedge (06) ---

// assignedPod is an old non-terminating pod on node-a with no kubelet
// pod dir — watch-wedge evidence.
func assignedPod(e *env, name, uid string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(uid),
			CreationTimestamp: metav1.NewTime(e.Now.Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestKubeletWatchWedgeRestarts(t *testing.T) {
	e := fixture(t)
	p := e.AssignedPod("unseen-pod", wdepstest.UIDA, 20*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.StateDir, "state-kubelet-watch-wedge")

	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("wedge latch missing: %v", err)
	}
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for watch wedge")
	}
	if !strings.Contains(e.LogLines(t), "kubelet-watch-wedge unseen-pods=1") {
		t.Fatalf("missing wedge log:\n%s", e.LogLines(t))
	}
}

func TestKubeletWatchWedgeYoungAndDirsSkipped(t *testing.T) {
	e := fixture(t)
	// Too young (below KubeletWatchMinAge).
	young := e.AssignedPod("young", wdepstest.UIDA, 2*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), young, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Old but the pod dir EXISTS (kubelet admitted it).
	old := e.AssignedPod("admitted", wdepstest.UIDB, 30*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.KubepodsDir, wdepstest.UIDB), 0o755); err != nil {
		t.Fatal(err)
	}
	// Terminating / Succeeded / Failed are skipped entirely.
	term := e.AssignedPod("term", wdepstest.UIDC, 30*time.Minute)
	ts := metav1.NewTime(e.Now.Add(-time.Minute))
	term.DeletionTimestamp = &ts
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), term, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	done := e.AssignedPod("done", wdepstest.UIDD, 30*time.Minute)
	done.Status.Phase = corev1.PodSucceeded
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), done, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on ineligible pods")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart on ineligible pods")
	}
}

func TestKubeletWatchWedgeUpstreamGate(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.APIBackends = []string{"10.0.0.1:6443", "10.0.0.2:6443"}
	p := e.AssignedPod("unseen", wdepstest.UIDA, 20*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.StateDir, "state-kubelet-watch-wedge")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing: %v", err)
	}
	// Only ONE backend stale → not an upstream wedge → restart.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-apiserver-backend-stale-10-0-0-1"), "1\n")
	wdepstest.Check[*kubelet.WatchWedgeCheck](e.H, wdeps.CheckWatch).Fails = 2
	e.H.Cycle(context.Background())
	if !e.SDRan("restart k0sworker.service") {
		t.Fatal("restart blocked by partial staleness")
	}
	// ALL backends stale → upstream gate blocks the restart.
	e.SDCmds = nil
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-apiserver-backend-stale-10-0-0-2"), "1\n")
	wdepstest.Check[*kubelet.WatchWedgeCheck](e.H, wdeps.CheckWatch).Fails = 2
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart fired despite all backends stale")
	}
	if !strings.Contains(e.LogLines(t), "api backend stale") {
		t.Fatalf("missing upstream-gate log:\n%s", e.LogLines(t))
	}
}

func TestKubeletWatchWedgeAPIFailKeepsLatch(t *testing.T) {
	e := fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-kubelet-watch-wedge"), "1\n")
	e.CS.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-watch-wedge")); err != nil {
		t.Fatal("latch cleared on inconclusive (API-failed) cycle")
	}
}

// TestKubeletWatchWedgePodsDirGoneInconclusive: with the pods ROOT
// itself gone/unreadable every per-pod stat fails and ALL pods would
// count "missing" — the sweep must abort instead of latching a false
// wedge and spending a k0sworker restart on a filesystem blip.
func TestKubeletWatchWedgePodsDirGoneInconclusive(t *testing.T) {
	e := fixture(t)
	p := e.AssignedPod("unseen", wdepstest.UIDA, 20*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.KubepodsDir); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on unstatable pods dir")
	}
	if e.SDRan("restart k0sworker.service") {
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
	p := e.AssignedPod("unseen", wdepstest.UIDA, 20*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.KubepodsDir); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, e.KubepodsDir, "not a dir\n")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on file-as-pods-dir")
	}
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("restart spent on file-as-pods-dir")
	}
	if !strings.Contains(e.LogLines(t), "not a directory") {
		t.Fatalf("missing inconclusive log:\n%s", e.LogLines(t))
	}
}

func TestKubeletStallStoppedTaskRecordsNotPhantom(t *testing.T) {
	e := fixture(t)
	for i := 0; i < kubelet.PoddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.KubepodsDir, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Drained/evicted node shape: pod dirs remain, task dirs exist
	// but every init pid is DEAD (STOPPED records still count, like
	// `ctr tasks ls | wc -l` — not phantom).
	e.MkTask(t, wdepstest.UIDA, "app", 0)
	e.MkTask(t, "uid-b-dead-pod-01234", "app", 9999) // dead pid (not in e.Live)
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("phantom-pods restart with stopped task records")
	}
}
