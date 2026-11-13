package heal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

var ctx = context.Background()

// planAwareDyn is a dynamic fake that knows the PlanList kind (and
// every other CRD the sweep lists) via the platform/testhelp table.
func planAwareDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testhelp.NewDynamicClient(objs...)
}

// cordonedNow builds a node inside the active-cordon window —
// maintenance mutex signal (a).
func cordonedNow(name string) *corev1.Node {
	t := metav1.NewTime(time.Now())
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{
				{Key: kube.UnschedulableTaintKey, TimeAdded: &t}},
		},
	}
}

func pod(ns, name string, uid types.UID, phase corev1.PodPhase,
	created time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: uid,
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

// AllowedV's cooldown check runs BEFORE the mutex: a cooled-down key
// defers (false, false) even when every maintenance read would fail
// — proven here by a clientset whose lists all error.
func TestAllowedCooledDownShortCircuits(t *testing.T) {
	var heals state.CooldownSet
	now := time.Now()
	heals.Stamp("k", now.Add(-time.Minute))

	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "*",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs, nil,
		&heals, "k", 5*time.Minute, now)
	if proceed || unverifiable {
		t.Fatalf("cooled-down AllowedV = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

// A held mutex defers without the unverifiable flag — normal
// operation, no IncError owed by the caller.
func TestAllowedMaintenanceHeld(t *testing.T) {
	cs := fake.NewSimpleClientset(cordonedNow("w1"))
	proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs, nil,
		&state.CooldownSet{}, "k", time.Minute, time.Now())
	if proceed || unverifiable {
		t.Fatalf("held AllowedV = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

// An unverifiable mutex (nil dyn is a wiring bug, not "no signal")
// fails closed AND flags it — the caller IncErrors on this path.
func TestAllowedUnverifiableFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs, nil,
		&state.CooldownSet{}, "k", time.Minute, time.Now())
	if proceed || !unverifiable {
		t.Fatalf("unverifiable AllowedV = (%v,%v), want (false,true)",
			proceed, unverifiable)
	}
}

// Clear maintenance + no cooldown = proceed.
func TestAllowedProceeds(t *testing.T) {
	cs := fake.NewSimpleClientset()
	proceed, unverifiable := AllowedV(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), &state.CooldownSet{}, "k", time.Minute, time.Now())
	if !proceed || unverifiable {
		t.Fatalf("clear AllowedV = (%v,%v), want (true,false)",
			proceed, unverifiable)
	}
}

// A nil heals pointer skips the cooldown check: a key that WOULD be
// cooled proceeds when the mutex is clear.
func TestAllowedNilHealsSkipsCooldown(t *testing.T) {
	cs := fake.NewSimpleClientset()
	proceed, _ := AllowedV(ctx, logr.Discard(), nil, cs, planAwareDyn(),
		nil, "k", time.Hour, time.Now())
	if !proceed {
		t.Fatal("nil heals blocked the heal")
	}
}

// A shared Verdict memoizes the mutex across preamble calls: two
// AllowedV calls against a cordoned-then-cleared view still see the
// FIRST evaluation — one node list total, not one per call.
func TestAllowedVSharedVerdictMemoizes(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var lists int
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			lists++
			return false, nil, nil // tracker serves the (empty) list
		})
	var v maintenance.Verdict
	now := time.Now()
	for i := 0; i < 2; i++ {
		proceed, unverifiable := AllowedV(ctx, logr.Discard(), &v, cs,
			planAwareDyn(), &state.CooldownSet{}, "k", time.Minute, now)
		if !proceed || unverifiable {
			t.Fatalf("call %d = (%v,%v), want (true,false)", i, proceed, unverifiable)
		}
	}
	if lists != 1 {
		t.Fatalf("node lists = %d, want 1 (memoized verdict)", lists)
	}
}

// A delivered delete stamps the ledger — the pod is gone and the
// key reads cooled.
func TestDeletePodStampsOnDelivery(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	var heals state.CooldownSet
	now := time.Now()

	deleted, err := DeletePod(ctx, cs, &heals, "k", p, now)
	if err != nil || !deleted {
		t.Fatalf("DeletePod = (%v,%v)", deleted, err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(ctx, "op-abc-1",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod still present: %v", err)
	}
	if !heals.CooledDown("k", time.Hour, now) {
		t.Fatal("delivered delete did not stamp the ledger")
	}
}

// The delete carries the UID precondition and no propagation policy
// — "delete the pod I vetted, not a same-named recreate", with the
// apiserver's default propagation like every reference site.
func TestDeletePodUIDPrecondition(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-42", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	var got metav1.DeleteOptions
	cs.PrependReactor("delete", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			got = a.(ktesting.DeleteAction).GetDeleteOptions()
			return false, nil, nil // unhandled — the tracker deletes
		})
	if _, err := DeletePod(ctx, cs, nil, "k", p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got.Preconditions == nil || got.Preconditions.UID == nil ||
		*got.Preconditions.UID != "uid-42" {
		t.Fatalf("DeleteOptions = %+v, want UID precondition uid-42", got)
	}
	if got.PropagationPolicy != nil {
		t.Fatalf("PropagationPolicy = %v, want unset (apiserver default)",
			*got.PropagationPolicy)
	}
}

// A failed delete surfaces the error and does NOT stamp — the next
// sweep must retry, not sit out the whole cooldown.
func TestDeletePodFailureLeavesLedgerUnstamped(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	var heals state.CooldownSet
	now := time.Now()

	deleted, err := DeletePod(ctx, cs, &heals, "k", p, now)
	if deleted || err == nil {
		t.Fatalf("DeletePod = (%v,%v), want (false, err)", deleted, err)
	}
	if heals.CooledDown("k", time.Hour, now) {
		t.Fatal("failed delete stamped the ledger")
	}
}

// A nil heals pointer skips the stamp — same contract as Allowed.
func TestDeletePodNilHeals(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	if deleted, err := DeletePod(ctx, cs, nil, "k", p, time.Now()); err != nil || !deleted {
		t.Fatalf("DeletePod nil heals = (%v,%v)", deleted, err)
	}
}

// A delivered eviction stamps the ledger and removes the pod — the
// same delivered-only contract DeletePod pins.
func TestEvictPodStampsOnDelivery(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	testhelp.EmulateEviction(cs)
	var heals state.CooldownSet
	now := time.Now()

	evicted, refused, err := EvictPod(ctx, cs, &heals, "k", p, now)
	if err != nil || refused || !evicted {
		t.Fatalf("EvictPod = (%v,%v,%v), want (true,false,nil)", evicted, refused, err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(ctx, "op-abc-1",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("delivered eviction left the pod behind: %v", err)
	}
	if !heals.CooledDown("k", time.Hour, now) {
		t.Fatal("delivered eviction did not stamp the ledger")
	}
}

// The eviction carries the UID precondition on its DeleteOptions —
// "kill the pod I vetted, not a same-named recreate" — with no
// propagation policy, matching DeletePod's wire shape.
func TestEvictPodUIDPrecondition(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-42", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	var got metav1.DeleteOptions
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			got = *ca.GetObject().(*policyv1.Eviction).DeleteOptions
			return true, nil, nil
		})
	if _, _, err := EvictPod(ctx, cs, nil, "k", p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got.Preconditions == nil || got.Preconditions.UID == nil ||
		*got.Preconditions.UID != types.UID("uid-42") {
		t.Fatalf("Eviction DeleteOptions = %+v, want UID precondition uid-42", got)
	}
	if got.PropagationPolicy != nil {
		t.Fatalf("PropagationPolicy = %v, want unset (apiserver default)",
			*got.PropagationPolicy)
	}
}

// A PDB with disruptionsAllowed==0 refuses the eviction with HTTP
// 429 — a DEFERRAL, not a failure: (false, true, nil) so the caller
// keeps the pod, counts no error and stamps no ledger.
func TestEvictPodPDBRefusalDefers(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	var heals state.CooldownSet
	now := time.Now()

	evicted, refused, err := EvictPod(ctx, cs, &heals, "k", p, now)
	if evicted || !refused || err != nil {
		t.Fatalf("EvictPod 429 = (%v,%v,%v), want (false,true,nil)", evicted, refused, err)
	}
	if heals.CooledDown("k", time.Hour, now) {
		t.Fatal("PDB refusal stamped the ledger")
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(ctx, "op-abc-1",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("PDB-refused pod must stay, get err = %v", err)
	}
}

// Any other API failure is (false, false, err) and does NOT stamp —
// the caller meters it and the next sweep retries.
func TestEvictPodFailurePassthrough(t *testing.T) {
	p := pod("ns1", "op-abc-1", "uid-1", corev1.PodRunning, time.Now())
	cs := fake.NewSimpleClientset(p)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, errors.New("api down")
		})
	var heals state.CooldownSet
	now := time.Now()

	evicted, refused, err := EvictPod(ctx, cs, &heals, "k", p, now)
	if evicted || refused || err == nil {
		t.Fatalf("EvictPod failure = (%v,%v,%v), want (false,false,err)", evicted, refused, err)
	}
	if heals.CooledDown("k", time.Hour, now) {
		t.Fatal("failed eviction stamped the ledger")
	}
}

func TestOldestRunningPod(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	recent := time.Now()
	terminating := pod("ns1", "op-abc-3", "u3", corev1.PodRunning, old.Add(-time.Hour))
	terminating.DeletionTimestamp = &metav1.Time{Time: recent}

	for _, tc := range []struct {
		name     string
		pods     []corev1.Pod
		prefixes []string
		want     string // "" expects nil
	}{
		{"empty", nil, []string{"op"}, ""},
		{"no prefixes", []corev1.Pod{
			*pod("ns1", "op-abc-1", "u1", corev1.PodRunning, old)},
			nil, ""},
		{"oldest running wins", []corev1.Pod{
			*pod("ns1", "op-abc-2", "u2", corev1.PodRunning, recent),
			*pod("ns1", "op-abc-1", "u1", corev1.PodRunning, old)},
			[]string{"op"}, "op-abc-1"},
		{"non-running skipped", []corev1.Pod{
			*pod("ns1", "op-abc-1", "u1", corev1.PodPending, old),
			*pod("ns1", "op-abc-2", "u2", corev1.PodRunning, recent)},
			[]string{"op"}, "op-abc-2"},
		{"terminating skipped", []corev1.Pod{
			*terminating,
			*pod("ns1", "op-abc-4", "u4", corev1.PodRunning, recent)},
			[]string{"op"}, "op-abc-4"},
		// The dash is required: a bare "op2-" name and the exact
		// deployment name itself are not "op-" pods.
		{"prefix needs the dash", []corev1.Pod{
			*pod("ns1", "op", "u1", corev1.PodRunning, old),
			*pod("ns1", "op2-abc-1", "u2", corev1.PodRunning, old),
			*pod("ns1", "op-abc-1", "u3", corev1.PodRunning, recent)},
			[]string{"op"}, "op-abc-1"},
		{"any prefix matches", []corev1.Pod{
			*pod("ns1", "other-abc-1", "u1", corev1.PodRunning, old)},
			[]string{"op", "other"}, "other-abc-1"},
		{"no match", []corev1.Pod{
			*pod("ns1", "unrelated-1", "u1", corev1.PodRunning, old)},
			[]string{"op"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := OldestRunningPod(tc.pods, tc.prefixes...)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("OldestRunningPod = %s, want nil", got.Name)
				}
				return
			}
			if got == nil || got.Name != tc.want {
				t.Fatalf("OldestRunningPod = %v, want %s", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Gate — the nil-heals/zero-cooldown AllowedV shape every
// maintenance-gated module repeats. The pair contract is AllowedV's:
// proceed=false on a held mutex or a spent budget, unverifiable=true
// (fail closed) when the maintenance read itself fails.
// ---------------------------------------------------------------------------

func TestGateProceedsWhenClear(t *testing.T) {
	resetBudget(t)
	cs := fake.NewSimpleClientset()
	proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), "k", time.Now())
	if !proceed || unverifiable {
		t.Fatalf("clear Gate = (%v,%v), want (true,false)",
			proceed, unverifiable)
	}
}

func TestGateHeldMutexDefers(t *testing.T) {
	resetBudget(t)
	cs := fake.NewSimpleClientset(cordonedNow("w1"))
	proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), "k", time.Now())
	if proceed || unverifiable {
		t.Fatalf("held Gate = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

func TestGateUnverifiableFailsClosed(t *testing.T) {
	resetBudget(t)
	cs := fake.NewSimpleClientset()
	proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs,
		nil, "k", time.Now()) // nil dyn = wiring bug -> unverifiable
	if proceed || !unverifiable {
		t.Fatalf("unverifiable Gate = (%v,%v), want (false,true)",
			proceed, unverifiable)
	}
}

// Gate has no heals ledger — a target stamped hot still proceeds
// (the cooldown lives in the caller's own stamp checks), and a spent
// aggregate budget defers exactly like a held mutex.
func TestGateBudgetExhaustedDefers(t *testing.T) {
	resetBudget(t)
	ConfigureBudget(1, time.Hour)
	cs := fake.NewSimpleClientset()
	now := time.Now()
	if proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), "k1", now); !proceed || unverifiable {
		t.Fatalf("first Gate = (%v,%v), want (true,false)",
			proceed, unverifiable)
	}
	proceed, unverifiable := Gate(ctx, logr.Discard(), nil, cs,
		planAwareDyn(), "k2", now)
	if proceed || unverifiable {
		t.Fatalf("budget-spent Gate = (%v,%v), want (false,false)",
			proceed, unverifiable)
	}
}

// The sweep overlay's quorum reservation: two pods of the same
// controller inside one sweep share ONE disruption slot — the
// second DeletePod defers (false, nil) with no API call and no
// ledger stamp, so two parallel checks cannot each delete a pod of
// the same 2-replica workload and take it to zero.
func TestDeletePodQuorumReservation(t *testing.T) {
	ctrl := true
	owner := metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "web-6d9f", Controller: &ctrl,
	}
	p1 := pod("ns1", "web-0", "u1", corev1.PodRunning, time.Now())
	p1.OwnerReferences = []metav1.OwnerReference{owner}
	p2 := pod("ns1", "web-1", "u2", corev1.PodRunning, time.Now())
	p2.OwnerReferences = []metav1.OwnerReference{owner}
	cs := fake.NewSimpleClientset(p1, p2)
	var heals state.CooldownSet
	sctx := kube.WithSweepOverlay(ctx)
	now := time.Now()

	deleted, err := DeletePod(sctx, cs, &heals, "k1", p1, now)
	if err != nil || !deleted {
		t.Fatalf("first DeletePod = (%v,%v), want (true,nil)", deleted, err)
	}
	deleted, err = DeletePod(sctx, cs, &heals, "k2", p2, now)
	if err != nil || deleted {
		t.Fatalf("second same-owner DeletePod = (%v,%v), want (false,nil) deferral",
			deleted, err)
	}
	if _, gerr := cs.CoreV1().Pods("ns1").Get(ctx, "web-1",
		metav1.GetOptions{}); gerr != nil {
		t.Fatal("denied pod must survive — no API delete was issued")
	}
	if heals.CooledDown("k2", time.Hour, now) {
		t.Fatal("denied delete must not stamp the ledger")
	}
}

// EvictPod reports the same reservation denial as refused=true —
// the existing "PDB said no, deferral" contract every caller
// already handles (EvictPodV refunds the grant on refused).
func TestEvictPodQuorumReservation(t *testing.T) {
	ctrl := true
	owner := metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "web-6d9f", Controller: &ctrl,
	}
	p1 := pod("ns1", "web-0", "u1", corev1.PodRunning, time.Now())
	p1.OwnerReferences = []metav1.OwnerReference{owner}
	p2 := pod("ns1", "web-1", "u2", corev1.PodRunning, time.Now())
	p2.OwnerReferences = []metav1.OwnerReference{owner}
	cs := fake.NewSimpleClientset(p1, p2)
	sctx := kube.WithSweepOverlay(ctx)
	now := time.Now()

	evicted, refused, err := EvictPod(sctx, cs, nil, "k1", p1, now)
	if err != nil || !evicted || refused {
		t.Fatalf("first EvictPod = (%v,%v,%v), want (true,false,nil)",
			evicted, refused, err)
	}
	evicted, refused, err = EvictPod(sctx, cs, nil, "k2", p2, now)
	if err != nil || evicted || !refused {
		t.Fatalf("second same-owner EvictPod = (%v,%v,%v), want (false,true,nil)",
			evicted, refused, err)
	}
	if _, gerr := cs.CoreV1().Pods("ns1").Get(ctx, "web-1",
		metav1.GetOptions{}); gerr != nil {
		t.Fatal("denied pod must survive — no eviction was issued")
	}
}
