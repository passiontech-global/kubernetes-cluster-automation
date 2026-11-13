// heal_ops_test.go — the two new heal shapes: SafePodDelete's
// fail-closed sibling guard (each skip path keeps the pod, a proven
// sibling population lets DeletePodHeal run), and BounceOperatorPod's
// gate→list→pick→delete skeleton (cooldown and unverifiable defer,
// delivered deletes stamp the shared key and count).
package probefw

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func ownedPod(ns, name string, uid types.UID, ready bool, deleting bool) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: uid,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet",
			Name: "web-rs", UID: "ctrl-1", Controller: &[]bool{true}[0],
		}},
	}}
	p.Status.Phase = corev1.PodRunning
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	if deleting {
		now := metav1.NewTime(time.Now())
		p.DeletionTimestamp = &now
	}
	return p
}

func safePodDeleteDeps(cs *fake.Clientset) *Deps {
	// The maintenance mutex evaluates clear: no cordoned nodes, no
	// kured lock, empty autopilot Plan list.
	return &Deps{Name: "test-queue", CS: cs, Dyn: testhelp.NewDynamicClient()}
}

func TestSafePodDeleteGuardPaths(t *testing.T) {
	ctx := t.Context()
	now := time.Now()

	t.Run("unowned pod never deleted", func(t *testing.T) {
		loner := ownedPod("apps", "web-1", "u1", true, false)
		loner.ObjectMeta.OwnerReferences = nil
		cs := fake.NewSimpleClientset(&loner)
		d := safePodDeleteDeps(cs)

		d.SafePodDelete(ctx, logr.Discard(), "check", &loner,
			ReadyByOwner([]corev1.Pod{loner}), 1, time.Hour, now)

		if _, err := cs.CoreV1().Pods("apps").
			Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatal("unowned pod deleted — no sibling proof possible")
		}
	})

	t.Run("no ready sibling never deleted", func(t *testing.T) {
		loner := ownedPod("apps", "web-1", "u1", true, false)
		cs := fake.NewSimpleClientset(&loner)
		d := safePodDeleteDeps(cs)

		// The census counts the pod itself; ReadySiblings discounts
		// it — 1 Ready pod reads 0 siblings, min 1 defers.
		d.SafePodDelete(ctx, logr.Discard(), "check", &loner,
			ReadyByOwner([]corev1.Pod{loner}), 1, time.Hour, now)

		if _, err := cs.CoreV1().Pods("apps").
			Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatal("lone replica deleted — delete would blackhole the workload")
		}
	})

	t.Run("terminating pod never deleted", func(t *testing.T) {
		going := ownedPod("apps", "web-1", "u1", true, true)
		cs := fake.NewSimpleClientset(&going)
		d := safePodDeleteDeps(cs)

		d.SafePodDelete(ctx, logr.Discard(), "check", &going,
			map[types.UID]int{"ctrl-1": 2}, 1, time.Hour, now)

		if _, err := cs.CoreV1().Pods("apps").
			Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatal("terminating pod double-deleted")
		}
	})

	t.Run("unverifiable mutex defers", func(t *testing.T) {
		pod := ownedPod("apps", "web-1", "u1", true, false)
		sibling := ownedPod("apps", "web-2", "u2", true, false)
		cs := fake.NewSimpleClientset(&pod)
		// Dyn=nil makes the autopilot-Plan mutex signal unverifiable —
		// the delete must defer rather than run blind.
		d := &Deps{Name: "test-queue", CS: cs}

		d.SafePodDelete(ctx, logr.Discard(), "check", &pod,
			ReadyByOwner([]corev1.Pod{pod, sibling}), 1, time.Hour, now)

		if _, err := cs.CoreV1().Pods("apps").
			Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatal("pod deleted while mutex unverifiable")
		}
	})
}

func TestSafePodDeleteHealsWithSiblingProof(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	pod := ownedPod("apps", "web-1", "u1", true, false)
	sibling := ownedPod("apps", "web-2", "u2", true, false)
	cs := fake.NewSimpleClientset(&pod)
	d := safePodDeleteDeps(cs)

	d.SafePodDelete(ctx, logr.Discard(), "guard-check", &pod,
		ReadyByOwner([]corev1.Pod{pod, sibling}), 1, time.Hour, now)

	if _, err := cs.CoreV1().Pods("apps").
		Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("proven-sibling pod not deleted (get err = %v)", err)
	}
	// The ledger key is the SelfHealKey over the CONTROLLER key —
	// the key the h2/outlier/cloudflared call sites stamp today.
	if _, ok := d.Heals.Last(SelfHealKey("guard-check", "apps/web-rs")); !ok {
		t.Fatal("heal ledger not stamped under the controller key")
	}
}

func TestSafePodDeleteTwoSiblingPosture(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	// min=2 is the safe-evict posture (linkerd identity): the census
	// must hold the stalled pod itself — one OTHER Ready sibling
	// alone (census 1) still defers at min 2.
	pod := ownedPod("apps", "web-1", "u1", true, false)
	sibling := ownedPod("apps", "web-2", "u2", true, false)
	cs := fake.NewSimpleClientset(&pod)
	d := safePodDeleteDeps(cs)

	d.SafePodDelete(ctx, logr.Discard(), "guard-check", &pod,
		ReadyByOwner([]corev1.Pod{pod, sibling}), 2, time.Hour, now)
	if _, err := cs.CoreV1().Pods("apps").
		Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatal("min=2 deleted off a census of 1 Ready pod")
	}

	third := ownedPod("apps", "web-3", "u3", true, false)
	cs = fake.NewSimpleClientset(&pod)
	d = safePodDeleteDeps(cs)
	d.SafePodDelete(ctx, logr.Discard(), "guard-check", &pod,
		ReadyByOwner([]corev1.Pod{pod, sibling, third}), 2, time.Hour, now)
	if _, err := cs.CoreV1().Pods("apps").
		Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("min=2 with census 2 did not delete (get err = %v)", err)
	}
}

func bouncePod(ns, name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: types.UID("uid-" + name)}}
}

func TestBounceOperatorPodGateDefers(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	pod := bouncePod("olm", "olm-operator-abc")
	cs := fake.NewSimpleClientset(pod)

	t.Run("cooldown defers without listing", func(t *testing.T) {
		d := safePodDeleteDeps(cs)
		d.Heals.Stamp("olm-operator", now.Add(-time.Minute))

		if n := d.BounceOperatorPod(ctx, logr.Discard(), "olm-health",
			"olm", nil, &d.Heals, "olm-operator", time.Hour, now); n != 0 {
			t.Fatalf("bounce inside cooldown = %d deletes, want 0", n)
		}
		if _, err := cs.CoreV1().Pods("olm").
			Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
			t.Fatal("pod deleted inside cooldown")
		}
	})

	t.Run("unverifiable mutex defers", func(t *testing.T) {
		d := &Deps{Name: "test-queue", CS: cs} // Dyn=nil → unverifiable
		if n := d.BounceOperatorPod(ctx, logr.Discard(), "olm-health",
			"olm", nil, &d.Heals, "olm-operator", time.Hour, now); n != 0 {
			t.Fatalf("bounce with unverifiable mutex = %d deletes, want 0", n)
		}
		if _, err := cs.CoreV1().Pods("olm").
			Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
			t.Fatal("pod deleted while mutex unverifiable")
		}
	})
}

func TestBounceOperatorPodListErrorDefers(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("list boom")
		})
	d := safePodDeleteDeps(cs)

	if n := d.BounceOperatorPod(ctx, logr.Discard(), "olm-health",
		"olm", nil, &d.Heals, "olm-operator", time.Hour, now); n != 0 {
		t.Fatalf("bounce past a failed list = %d deletes, want 0", n)
	}
}

func TestBounceOperatorPodDeletesAndStamps(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	target := bouncePod("olm", "olm-operator-abc")
	other := bouncePod("olm", "catalog-operator-def")
	cs := fake.NewSimpleClientset(target, other)
	d := safePodDeleteDeps(cs)

	n := d.BounceOperatorPod(ctx, logr.Discard(), "olm-health",
		"olm", func(pods []corev1.Pod) []*corev1.Pod {
			// The call site's per-ns prefix pick — only
			// olm-operator-* pods are the target.
			var out []*corev1.Pod
			for i := range pods {
				if strings.HasPrefix(pods[i].Name, "olm-operator-") {
					out = append(out, &pods[i])
				}
			}
			return out
		}, &d.Heals, "olm-operator", time.Hour, now)

	if n != 1 {
		t.Fatalf("bounce deleted %d pods, want 1", n)
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, target.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("picked pod not deleted (get err = %v)", err)
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, other.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-matching pod deleted — pick was ignored")
	}
	// ONE key stamps the gate AND every delivered delete.
	if _, ok := d.Heals.Last("olm-operator"); !ok {
		t.Fatal("bounce ledger not stamped under the shared key")
	}
	// The stamp the delivered delete left must defer the next bounce
	// for the window — the gate reads the same ledger.
	if n := d.BounceOperatorPod(ctx, logr.Discard(), "olm-health",
		"olm", nil, &d.Heals, "olm-operator", time.Hour, now); n != 0 {
		t.Fatalf("second bounce inside cooldown = %d deletes, want 0", n)
	}
}

func TestBounceOperatorPodNilPickTakesAll(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	a := bouncePod("opns", "op-1")
	b := bouncePod("opns", "op-2")
	cs := fake.NewSimpleClientset(a, b)
	d := safePodDeleteDeps(cs)

	if n := d.BounceOperatorPod(ctx, logr.Discard(), "prov-health",
		"opns", nil, &d.Heals, "provisioner", time.Hour, now); n != 2 {
		t.Fatalf("nil pick deleted %d pods, want all 2", n)
	}
}

// ---------------------------------------------------------------------------
// Budget-grant refunds — the exactly-once contract at the probefw gate
// owners. heal.ConfigureBudget is process-global; each test restores
// the inert gate on cleanup.
// ---------------------------------------------------------------------------

// A DeletePodHeal whose delete is cleanly deferred by the sweep
// overlay's quorum reservation must hand the gate's budget grant
// back exactly once — proven by window accounting: budget=2, the
// first heal spends one grant for real, the second heal's grant is
// refunded on deferral, and a third gate still proceeds.
func TestDeletePodHealRefundsOnQuorumDenial(t *testing.T) {
	heal.ConfigureBudget(2, time.Hour)
	defer heal.ConfigureBudget(0, 0)

	// Two pods of the SAME controller — the second delete inside one
	// sweep defers at the quorum guard.
	p1 := ownedPod("apps", "web-1", "u1", true, false)
	p2 := ownedPod("apps", "web-2", "u2", true, false)
	cs := fake.NewSimpleClientset(&p1, &p2)
	d := safePodDeleteDeps(cs)
	sctx := WithSweepSnapshot(t.Context())
	now := time.Now()

	if !d.DeletePodHeal(sctx, logr.Discard(), "check-a", "t1", &p1,
		time.Hour, now) {
		t.Fatal("first heal should deliver")
	}
	if d.DeletePodHeal(sctx, logr.Discard(), "check-b", "t2", &p2,
		time.Hour, now) {
		t.Fatal("second same-owner heal must defer at the quorum guard")
	}
	// The deferred heal's grant went back: with budget=2 and one
	// grant genuinely spent, a third gate still proceeds. Without
	// the refund the window would read 2/2 and deny.
	proceed, unverifiable := d.HealAllowed(sctx, logr.Discard(),
		nil, "selfheal/check-c/t3", 0, now)
	if !proceed || unverifiable {
		t.Fatalf("post-deferral gate = (%v,%v), want (true,false) — "+
			"the deferred heal's grant was not refunded", proceed, unverifiable)
	}
}

// BounceOperatorPod refunds its ONE gate grant only when the whole
// pass delivers and attempts nothing — every target cleanly
// deferred. Here the workload's disruption slot is pre-reserved so
// both targets defer; budget=1 means the refund is the difference
// between proceed and deny on the next gate.
func TestBounceOperatorPodRefundsOnceOnAllDeferred(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	defer heal.ConfigureBudget(0, 0)

	p1 := ownedPod("ops", "op-1", "u1", true, false)
	p2 := ownedPod("ops", "op-2", "u2", true, false)
	cs := fake.NewSimpleClientset(&p1, &p2)
	d := safePodDeleteDeps(cs)
	sctx := WithSweepSnapshot(t.Context())
	now := time.Now()

	// Spend the shared workload slot up front — both bounce targets
	// then defer at the quorum guard with no mutation attempted.
	if !kube.TryReserveWorkloadDisruption(sctx, &p1) {
		t.Fatal("pre-reserve failed")
	}
	deleted := d.BounceOperatorPod(sctx, logr.Discard(),
		"bounce-check", "ops", nil, nil, "bounce-key", time.Hour, now)
	if deleted != 0 {
		t.Fatalf("deleted = %d, want 0 — every target deferred", deleted)
	}
	// The gate's grant was refunded exactly once: the next gate
	// proceeds (without the refund the single grant stays spent).
	proceed, unverifiable := d.HealAllowed(sctx, logr.Discard(),
		nil, "selfheal/other/t", 0, now)
	if !proceed || unverifiable {
		t.Fatalf("post-bounce gate = (%v,%v), want (true,false) — "+
			"the all-deferred bounce did not refund its grant",
			proceed, unverifiable)
	}
}

// A bounce that DELIVERS keeps its grant — the refund path must not
// fire when even one mutation executed.
func TestBounceOperatorPodDeliveredKeepsGrant(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	defer heal.ConfigureBudget(0, 0)

	p1 := ownedPod("ops", "op-1", "u1", true, false)
	p2 := ownedPod("ops", "op-2", "u2", true, false)
	cs := fake.NewSimpleClientset(&p1, &p2)
	d := safePodDeleteDeps(cs)
	sctx := WithSweepSnapshot(t.Context())
	now := time.Now()

	// Only p1 is picked — its delete delivers (the first reservation
	// for the workload wins the slot).
	deleted := d.BounceOperatorPod(sctx, logr.Discard(),
		"bounce-check", "ops",
		func(pods []corev1.Pod) []*corev1.Pod {
			var out []*corev1.Pod
			for i := range pods {
				if pods[i].Name == "op-1" {
					out = append(out, &pods[i])
				}
			}
			return out
		}, nil, "bounce-key", time.Hour, now)
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	proceed, unverifiable := d.HealAllowed(sctx, logr.Discard(),
		nil, "selfheal/other/t", 0, now)
	if proceed || unverifiable {
		t.Fatalf("post-delivery gate = (%v,%v), want (false,false) — "+
			"a delivered heal refunded its grant", proceed, unverifiable)
	}
}
