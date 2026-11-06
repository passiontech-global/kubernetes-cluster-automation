package heal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
	var v kube.Verdict
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
