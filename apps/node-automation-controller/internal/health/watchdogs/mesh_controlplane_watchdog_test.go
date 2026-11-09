// mesh_controlplane_watchdog_test.go — coverage for the
// mesh-controlplane-watchdog check (issuer-serial-watch/mesh-net-guards): wedged linkerd
// control-plane pod heal and the healNamedPod maintenance gate.
package watchdogs

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// mesh-net-guards — a wedged linkerd pod (started, never Ready, >5m) is
// deleted to force a re-roll, matching Deployment-suffixed pod names.
func TestCheckMeshLinkerdWedgedHeals(t *testing.T) {
	started := true
	podName := kube.LinkerdDestinationName + "-7f8b9c6d4-abcde"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.LinkerdNS, Name: podName,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("u-dest"),
			Labels: map[string]string{
				"linkerd.io/control-plane-component": "destination",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "destination", Started: &started, Ready: false}},
		},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("wedged linkerd pod passed")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, podName, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged linkerd pod not deleted")
	}
}

// ---------------------------------------------------------------------------
// healNamedPod — maintenance gate (node-hang-precordon)
// ---------------------------------------------------------------------------

// A wedged control-plane pod is NOT deleted while maintenance is in
// flight — the direct healNamedPod path (linkerd re-roll) respects
// the same mutex as healComponentPod.
func TestHealNamedPodDefersDuringMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         kube.LinkerdNS,
			Name:              kube.LinkerdDestinationName + "-aaa-111",
			UID:               types.UID("u-dest"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	// kured holding its node-lock = a reboot drain in flight.
	kured := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "kube-system",
		Name:        "kured",
		Annotations: map[string]string{kube.KuredLockAnno: "w1"},
	}}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), kured, pod)
	p := testProberDyn(cs, probetest.OpDyn())
	probetest.MustCheck[*meshControlPlaneCheck](t, p).healNamedPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance — heal must defer")
	}
}

// Without a maintenance signal the same call deletes the pod.
func TestHealNamedPodDeletesWithoutMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         kube.LinkerdNS,
			Name:              kube.LinkerdDestinationName + "-bbb-222",
			UID:               types.UID("u-dest2"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	probetest.MustCheck[*meshControlPlaneCheck](t, p).healNamedPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("pod not deleted outside maintenance")
	}
}

// ---------------------------------------------------------------------------
// mesh-net-guards — linkerd wedge scan list failure (fail-closed parity)
// ---------------------------------------------------------------------------

// The linkerd pod list is the mesh-net-guards wedge scan's only input: a list
// failure must be COUNTED like every swallowed infra error in the
// heal path — without it an apiserver flap reads as a clean sweep
// while the scan silently no-ops. The skipped scan must not
// fabricate a finding though: nothing was evaluated.
func TestCheckMeshLinkerdPodListInfraCounted(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	runErrors := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := runErrors()
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("a skipped wedge scan must not fabricate a finding: %+v", res)
	}
	if got := runErrors() - before; got != 1 {
		t.Fatalf("hook_run_errors delta = %v, want 1 — the skipped scan must count its list error", got)
	}
}

// ---------------------------------------------------------------------------
// mesh-controlplane — one HealAllowed evaluation per heal attempt
// ---------------------------------------------------------------------------

// healComponentPod no longer pre-gates: the cooldown/maintenance
// gate lives solely in healNamedPod, so one heal attempt (here the
// cilium-operator IPAM shape) evaluates the gate exactly ONCE and
// still deletes the wedged pod.
func TestMeshHealComponentPodSingleGateEval(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: ciliumOperatorPrefix + "6f9d8-abcde",
			UID:    types.UID("u-cilium-op"),
			Labels: map[string]string{"io.cilium/app": "operator"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	chk.healComponentPod(ctx, logr.Discard(), "cilium-operator",
		ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, time.Now())
	if chk.gateEvals != 1 {
		t.Fatalf("gate evaluations = %d, want exactly 1 per heal attempt", chk.gateEvals)
	}
	if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged cilium-operator pod not deleted")
	}
}

// The cooldown is honored on the healComponentPod path too — the
// single gate in healNamedPod refuses inside the cooldown window and
// the target survives.
func TestMeshHealComponentPodRespectsCooldown(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: ciliumOperatorPrefix + "6f9d8-abcde",
			UID:    types.UID("u-cilium-op"),
			Labels: map[string]string{"io.cilium/app": "operator"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	now := time.Now()
	chk.Heals.Stamp("cilium-operator", now.Add(-time.Minute)) // inside the 1h cooldown
	chk.healComponentPod(ctx, logr.Discard(), "cilium-operator",
		ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, now)
	if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the heal cooldown — gate refused too late")
	}
}
