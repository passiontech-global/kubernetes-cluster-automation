// mesh_controlplane_watchdog_test.go — coverage for the
// mesh-controlplane-watchdog check (issuer-serial-watch/mesh-net-guards): wedged linkerd
// control-plane pod heal and the healNamedPod maintenance gate.
package watchdogs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
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
// The fixture carries a controller ownerRef and one Ready sibling: the
// delete must fire only when the component has a replica that can
// absorb traffic during the re-roll.
func TestCheckMeshLinkerdWedgedHeals(t *testing.T) {
	started := true
	podName := kube.LinkerdDestinationName + "-7f8b9c6d4-abcde"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.LinkerdNS, Name: podName,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("u-dest"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: "linkerd-destination-7f8b9c6d4", UID: types.UID("rs-dest"),
				Controller: &ctrue,
			}},
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
	sibling := readyLinkerdPod("linkerd-destination-7f8b9c6d4-ffff",
		"u-dest-ready", "rs-dest")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod, sibling)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("wedged linkerd pod passed")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, podName, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged linkerd pod not deleted")
	}
}

var ctrue = true

// wedgedLinkerdPod builds a started-never-Ready Running pod >5m old —
// the all-started-none-Ready wedge signature.
func wedgedLinkerdPod(name, uid, ownerUID string) *corev1.Pod {
	started := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.LinkerdNS, Name: name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: name + "-rs", UID: types.UID(ownerUID),
				Controller: &ctrue,
			}},
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
}

// readyLinkerdPod builds the Running+Ready sibling the sibling gate
// counts (Running phase, Ready=True condition, same controller UID).
func readyLinkerdPod(name, uid, ownerUID string) *corev1.Pod {
	started := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.LinkerdNS, Name: name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: name + "-rs", UID: types.UID(ownerUID),
				Controller: &ctrue,
			}},
			Labels: map[string]string{
				"linkerd.io/control-plane-component": "destination",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "destination", Started: &started, Ready: true}},
		},
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

// Without a maintenance signal the same call deletes the pod (owned:
// the ownerRef gate in healNamedPod only rejects unowned pods).
func TestHealNamedPodDeletesWithoutMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         kube.LinkerdNS,
			Name:              kube.LinkerdDestinationName + "-bbb-222",
			UID:               types.UID("u-dest2"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: "linkerd-destination-bbb", UID: types.UID("rs-dest2"),
				Controller: &ctrue,
			}},
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
			UID: types.UID("u-cilium-op"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "cilium-operator", UID: types.UID("dep-cilium-op"),
				Controller: &ctrue,
			}},
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
			UID: types.UID("u-cilium-op"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "cilium-operator", UID: types.UID("dep-cilium-op"),
				Controller: &ctrue,
			}},
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

// ---------------------------------------------------------------------------
// issuer-serial-watch — CiliumIPAMExhausted heartbeat freshness (issuer-serial-watch)
// ---------------------------------------------------------------------------

// ciliumOpPod builds a Running cilium-operator replica with a
// Deployment ownerRef — the re-rollable shape healNamedPod requires.
func ciliumOpPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: name,
			UID:               types.UID("u-" + name),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "cilium-operator", UID: types.UID("dep-cilium-op"),
				Controller: &ctrue,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// ipamNode builds a Ready node carrying CiliumIPAMExhausted=True
// transitioned `age` ago; heartbeat is fresh by default (the
// ReadyWorkerNode stamp), staleHeartbeat freezes it past the
// 10m freshness window.
func ipamNode(name string, age time.Duration, staleHeartbeat bool) *corev1.Node {
	n := probetest.ReadyWorkerNode(name, "CiliumIPAMExhausted", age, false)
	if staleHeartbeat {
		for i := range n.Status.Conditions {
			if n.Status.Conditions[i].Type == "CiliumIPAMExhausted" {
				n.Status.Conditions[i].LastHeartbeatTime =
					metav1.NewTime(time.Now().Add(-ciliumIPAMCondHeartbeatMax - time.Minute))
			}
		}
	}
	return n
}

// A CiliumIPAMExhausted=True whose heartbeat froze is a zombie — the
// owning reporter is dead (the node-condition-sweeper owns clearing
// it). The watchdog must not heal on stale evidence: no finding, no
// pod delete.
func TestMeshIPAMExhaustedStaleHeartbeatSkipped(t *testing.T) {
	pod := ciliumOpPod(ciliumOperatorPrefix + "6f9d8-abcde")
	cs := fake.NewSimpleClientset(
		ipamNode("w1", 20*time.Minute, true), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("stale-heartbeat zombie must not produce a finding: %+v", res)
	}
	if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("stale-heartbeat evidence must not delete the operator pod")
	}
}

// A fresh CiliumIPAMExhausted=True deletes the pod the leader Lease
// names — holderIdentity "<pod>_<uuid>" resolves the elected leader,
// so the standby listed first survives.
func TestMeshIPAMExhaustedHealsLeaseHolder(t *testing.T) {
	standby := ciliumOpPod(ciliumOperatorPrefix + "standby-111")
	leader := ciliumOpPod(ciliumOperatorPrefix + "leader-222")
	holder := leader.Name + "_9f8e7d6c"
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: ciliumOperatorLease},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
	cs := fake.NewSimpleClientset(
		ipamNode("w1", 20*time.Minute, false), standby, leader, lease)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("fresh CiliumIPAMExhausted must FAIL the check")
	}
	if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
		Get(ctx, leader.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("lease-holder leader pod not deleted")
	}
	if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
		Get(ctx, standby.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("standby pod deleted — the heal must target the lease holder only")
	}
}

// With no leader Lease at all, the heal falls back to the first
// Running cilium-operator-* pod — still a re-rollable target.
func TestMeshIPAMExhaustedNoLeaseFallsBack(t *testing.T) {
	first := ciliumOpPod(ciliumOperatorPrefix + "first-111")
	second := ciliumOpPod(ciliumOperatorPrefix + "second-222")
	cs := fake.NewSimpleClientset(
		ipamNode("w1", 20*time.Minute, false), first, second)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("fresh CiliumIPAMExhausted must FAIL the check")
	}
	deleted := 0
	for _, name := range []string{first.Name, second.Name} {
		if _, err := cs.CoreV1().Pods(ciliumOperatorNS).
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			deleted++
		}
	}
	if deleted != 1 {
		t.Fatalf("no-lease fallback deleted %d pods, want exactly 1", deleted)
	}
}

// ---------------------------------------------------------------------------
// mesh-net-guards — sibling / ownerRef gates on the wedged-linkerd heal
// ---------------------------------------------------------------------------

// Sole-replica wedge (started, never Ready, >5m, no Ready sibling):
// the sweep must still emit the finding (the wedge gauge stays live)
// but NOT delete — re-rolling a lone not-Ready replica every cooldown
// only churns pods while the component stays degraded.
func TestCheckMeshLinkerdSoleReplicaWedgedNotDeleted(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-7f8b9c6d4-abcde",
		"u-dest", "rs-dest")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx)
	if res.Pass || !strings.Contains(res.Why, "destination:wedged") {
		t.Fatalf("sole-replica wedge must stay detect-only with the finding emitted, got pass=%v why=%q", res.Pass, res.Why)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("sole-replica wedged pod deleted — no Ready sibling must stand the heal down")
	}
}

// With a second replica genuinely Ready, the not-Ready pod may be
// re-rolled — the sibling can absorb mesh traffic during the bounce.
func TestCheckMeshLinkerdWedgedWithReadySiblingDeletes(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-7f8b9c6d4-abcde",
		"u-dest", "rs-dest")
	sibling := readyLinkerdPod(kube.LinkerdDestinationName+"-7f8b9c6d4-ffff",
		"u-dest-ready", "rs-dest")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod, sibling)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("wedged linkerd pod passed")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged pod with a Ready sibling not deleted")
	}
}

// A pod with no controller ownerRef must never be deleted: nothing
// would re-roll it, so the delete turns a stuck component into a
// missing one. The rejection happens before the gate — no
// HealAllowed evaluation is spent on an undeletable target.
func TestHealNamedPodSkipsUnownedPod(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-ccc-333", "u-dest3", "rs-dest3")
	pod.OwnerReferences = nil
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	chk.healNamedPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if chk.gateEvals != 0 {
		t.Fatalf("gate evaluations = %d, want 0 — unowned pod must be rejected before the gate", chk.gateEvals)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("unowned pod deleted — nothing would re-roll it")
	}
}

// ---------------------------------------------------------------------------
// linkerdPodWedged — wedge signature truth table
// ---------------------------------------------------------------------------

// The wedged signature is exactly two shapes: a CrashLoopBackOff
// container past 2 restarts, or every container started and none
// ever went Ready (the ranch-style wedge). Everything adjacent —
// pending pods, terminating pods, too-young pods, missing statuses,
// a Ready container, an unstarted container, a crashloop still under
// the restart bar — must read false so the re-roll only fires on the
// ported signatures.
func TestLinkerdPodWedgedSignatures(t *testing.T) {
	started := true
	notStarted := false
	old := time.Now().Add(-time.Hour)
	young := time.Now().Add(-time.Minute)
	deleting := metav1.NewTime(time.Now())

	mk := func(mut func(*corev1.Pod)) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "linkerd-destination-x",
				CreationTimestamp: metav1.NewTime(old),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		mut(p)
		return p
	}
	crashloop := func(restarts int32, ready bool) []corev1.ContainerStatus {
		return []corev1.ContainerStatus{{
			Name: "c", Started: &started, Ready: ready,
			RestartCount: restarts,
			State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		}}
	}

	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"pending pod is not a wedge", mk(func(p *corev1.Pod) {
			p.Status.Phase = corev1.PodPending
		}), false},
		{"deleting pod is not a wedge", mk(func(p *corev1.Pod) {
			p.DeletionTimestamp = &deleting
		}), false},
		{"too young to judge", mk(func(p *corev1.Pod) {
			p.CreationTimestamp = metav1.NewTime(young)
			p.Status.ContainerStatuses = crashloop(5, false)
		}), false},
		{"no container statuses yet", mk(func(*corev1.Pod) {}), false},
		{"crashloop past the restart bar", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = crashloop(3, false)
		}), true},
		{"crashloop under the restart bar on a Ready container", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = crashloop(2, true)
		}), false},
		{"all started, none ever Ready — the ranch wedge", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = []corev1.ContainerStatus{
				{Name: "a", Started: &started, Ready: false},
				{Name: "b", Started: &started, Ready: false},
			}
		}), true},
		{"one Ready container clears the wedge", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = []corev1.ContainerStatus{
				{Name: "a", Started: &started, Ready: false},
				{Name: "b", Started: &started, Ready: true},
			}
		}), false},
		{"an unstarted container is not the all-started wedge", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = []corev1.ContainerStatus{
				{Name: "a", Started: &started, Ready: false},
				{Name: "b", Started: &notStarted, Ready: false},
			}
		}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := linkerdPodWedged(tc.pod, time.Now()); got != tc.want {
				t.Fatalf("linkerdPodWedged = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// healComponentPod — generic prefix target resolution
// ---------------------------------------------------------------------------

// A non-cilium prefix takes the generic first-match loop: the first
// live pod under the prefix is handed to healNamedPod — the
// ciliumOperatorPrefix lease-resolution branch is skipped entirely.
func TestMeshHealComponentPodGenericPrefix(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-abc-123",
		"u-gen", "rs-gen")
	// A same-prefix pod already deleting must not be picked over the
	// live one — the loop skips DeletionTimestamp targets.
	marked := wedgedLinkerdPod(kube.LinkerdDestinationName+"-abc-000",
		"u-marked", "rs-marked")
	ts := metav1.NewTime(time.Now())
	marked.DeletionTimestamp = &ts
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod, marked)
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	chk.healComponentPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		kube.LinkerdNS, kube.LinkerdDestinationName, linkerdHealCooldown, time.Now())
	if chk.gateEvals != 1 {
		t.Fatalf("gate evaluations = %d, want exactly 1 — the live prefix match must reach the gate", chk.gateEvals)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("generic-prefix target pod not deleted")
	}
}

// No live pod under the prefix resolves to a nil target — the heal
// stops before the gate, spending no HealAllowed evaluation.
func TestMeshHealComponentPodNoTarget(t *testing.T) {
	pod := wedgedLinkerdPod("linkerd-identity-abc-123", "u-id", "rs-id")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	chk.healComponentPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		kube.LinkerdNS, kube.LinkerdDestinationName, linkerdHealCooldown, time.Now())
	if chk.gateEvals != 0 {
		t.Fatalf("gate evaluations = %d, want 0 — no target must not reach the gate", chk.gateEvals)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted although no pod matched the prefix")
	}
}

// A pod-list failure defers the whole heal AND counts it — an
// apiserver flap must not read as a silent clean pass while the
// target resolution no-ops.
func TestMeshHealComponentPodListErrorCounted(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	runErrors := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := runErrors()
	chk.healComponentPod(ctx, logr.Discard(), "cilium-operator",
		ciliumOperatorNS, ciliumOperatorPrefix, ciliumOpHealCooldown, time.Now())
	if got := runErrors() - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — the list failure must be counted", got)
	}
	if chk.gateEvals != 0 {
		t.Fatalf("gate evaluations = %d, want 0 — the list error must stop before the gate", chk.gateEvals)
	}
}

// ---------------------------------------------------------------------------
// ciliumOperatorLeaderPod — leader-election Lease resolution
// ---------------------------------------------------------------------------

// ciliumOpRunning builds a Running cilium-operator replica — the only
// shape the leader resolution will touch (fallback never picks a
// non-Running or deleting pod).
func ciliumOpRunning(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: name,
			UID: types.UID("u-" + name),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func ciliumOpLease(holder string) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ciliumOperatorNS, Name: ciliumOperatorLease,
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
}

// The Lease's holderIdentity names the elected replica — the heal
// must bounce the leader, not a standby, or the wedged IPAM
// bookkeeping survives the re-roll. client-go leader election
// appends "_<uuid>" to the pod name, so the suffix-stripped
// candidate is tried before the verbatim identity.
func TestCiliumOperatorLeaderPodPrefersLeaseHolder(t *testing.T) {
	standby := ciliumOpRunning("cilium-operator-aaa")
	leader := ciliumOpRunning("cilium-operator-bbb")
	holder := "cilium-operator-bbb_9f2e1c"
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		standby, leader, ciliumOpLease(holder))
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	pods := []*corev1.Pod{standby, leader}
	if got := chk.ciliumOperatorLeaderPod(ctx, logr.Discard(), pods); got != leader {
		t.Fatalf("leader pod = %v, want the Lease holder cilium-operator-bbb", got)
	}
}

// A holderIdentity naming a pod that no longer exists (or is no
// longer Running) degrades to the first Running cilium-operator pod
// — still the right re-roll target over an arbitrary pick.
func TestCiliumOperatorLeaderPodHolderGoneFallsBack(t *testing.T) {
	standby := ciliumOpRunning("cilium-operator-aaa")
	holder := "cilium-operator-gone_deadbeef"
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		standby, ciliumOpLease(holder))
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	if got := chk.ciliumOperatorLeaderPod(ctx, logr.Discard(),
		[]*corev1.Pod{standby}); got != standby {
		t.Fatalf("holder-gone pick = %v, want the first Running fallback", got)
	}
}

// A Lease read failure is counted and degrades to the fallback —
// "can't prove the leader" must still surface as an error, not a
// silent arbitrary pick.
func TestCiliumOperatorLeaderPodLeaseErrorCounted(t *testing.T) {
	standby := ciliumOpRunning("cilium-operator-aaa")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), standby)
	cs.PrependReactor("list", "leases",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	runErrors := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := runErrors()
	if got := chk.ciliumOperatorLeaderPod(ctx, logr.Discard(),
		[]*corev1.Pod{standby}); got != standby {
		t.Fatalf("lease-error pick = %v, want the fallback", got)
	}
	if got := runErrors() - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — the lease read failure must be counted", got)
	}
}

// ---------------------------------------------------------------------------
// healNamedPod — gate error paths
// ---------------------------------------------------------------------------

// An unverifiable maintenance check fails the heal CLOSED: the pod
// stays, the miss is counted, and the one gate evaluation is still
// spent (the verdict was attempted).
func TestHealNamedPodUnverifiableFailsClosed(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-ddd-444", "u-dest4", "rs-dest4")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	runErrors := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := runErrors()
	chk.healNamedPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while the maintenance check was unverifiable")
	}
	if got := runErrors() - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — unverifiable is fail-closed, not silent", got)
	}
}

// A delivered-gate delete that the apiserver rejects is counted and
// logged — the pod stays and the cooldown is NOT stamped (the ledger
// stamps only on a delivered delete, so the next sweep retries).
func TestHealNamedPodDeleteErrorCounted(t *testing.T) {
	pod := wedgedLinkerdPod(kube.LinkerdDestinationName+"-eee-555", "u-dest5", "rs-dest5")
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*meshControlPlaneCheck](t, p)
	runErrors := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := runErrors()
	chk.healNamedPod(ctx, logr.Discard(), kube.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted although the apiserver rejected the delete")
	}
	if got := runErrors() - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — the failed delete must be counted", got)
	}
}
