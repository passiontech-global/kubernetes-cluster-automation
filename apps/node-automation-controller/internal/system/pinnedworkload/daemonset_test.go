// daemonset_test.go — the DaemonSetSpec reconcile skeleton: get →
// NotFound skip → Drifted → missing-container guard → Settled
// rollout gate → strategic-merge Patch → 15m requeue. Same shape as
// DeploymentSpec minus the replica pin, plus the Settled gate —
// patching mid-rollout would stack a second rolling restart. The
// module hooks (Drifted, Settled) are plain closures here.
package pinnedworkload

import (
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// pinnedDS is a kube-system/agent DaemonSet carrying the "agent"
// container the spec's patch merges by name.
func pinnedDS() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "agent", Image: "agent:v1"}},
				},
			},
		},
	}
}

// baseDSSpec is a fully-drifted DaemonSetSpec with a static
// priorityClassName patch and a nil Settled gate (patch whenever
// drifted) — tests override Drifted/Settled for the branch under test.
func baseDSSpec(cs kubernetes.Interface) DaemonSetSpec {
	return DaemonSetSpec{
		CS:         cs,
		Namespace:  "kube-system",
		Name:       "agent",
		Container:  "agent",
		NoDriftLog: "already pinned",
		PatchLog:   "drifted — restoring pinned spec",
		Drifted:    func(*appsv1.DaemonSet) bool { return true },
		Patch: []byte(`{"spec":{"template":{"spec":` +
			`{"priorityClassName":"system-node-critical"}}}}`),
	}
}

func getDS(t *testing.T, cs *fake.Clientset) *appsv1.DaemonSet {
	t.Helper()
	ds, err := cs.AppsV1().DaemonSets("kube-system").
		Get(t.Context(), "agent", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	return ds
}

// forbidDSPatch records any patch attempt on daemonsets — the probe
// for "reconcile must not patch" (the DaemonSet twin of
// testutil.ForbidDeployPatch).
func forbidDSPatch(cs *fake.Clientset, patched *bool) {
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			*patched = true
			return true, nil, nil
		})
}

// A missing DaemonSet is the "cluster without this addon" no-op —
// nil error on the 15m requeue.
func TestDaemonSetSpecNotFound(t *testing.T) {
	res, err := baseDSSpec(fake.NewSimpleClientset()).
		Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A get failure other than NotFound is a real error — only NotFound
// is the skip path.
func TestDaemonSetSpecGetError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	_, err := baseDSSpec(cs).Reconcile(t.Context())
	if err == nil {
		t.Fatal("expected error when the daemonset get fails")
	}
	if !strings.Contains(err.Error(), "get daemonset kube-system/agent") {
		t.Fatalf("error missing the wrapped ref: %v", err)
	}
}

// Drift-free means no patch — the 15m requeue is the only output.
func TestDaemonSetSpecNoDrift(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	var patched bool
	forbidDSPatch(cs, &patched)

	s := baseDSSpec(cs)
	s.Drifted = func(*appsv1.DaemonSet) bool { return false }
	res, err := s.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a drift-free DaemonSet")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A missing container reads as drift, but the patch merges containers
// by name and would append an entry with NO image — the apiserver
// rejects it forever. The skeleton must skip with a warn, never
// attempt the patch.
func TestDaemonSetSpecMissingContainerSkips(t *testing.T) {
	ds := pinnedDS()
	ds.Spec.Template.Spec.Containers = nil
	cs := fake.NewSimpleClientset(ds)
	var patched bool
	forbidDSPatch(cs, &patched)

	res, err := baseDSSpec(cs).Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched a DaemonSet whose pinned container is absent — " +
			"the name-only merge entry has no image and is rejected forever")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A drifted DaemonSet mid-rollout must not be patched — that would
// stack a second rolling restart (the double flap the bash hook
// avoided). The Settled gate holds the patch for the next pass.
func TestDaemonSetSpecUnsettledSkips(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	var patched bool
	forbidDSPatch(cs, &patched)

	s := baseDSSpec(cs)
	s.Settled = func(*appsv1.DaemonSet) bool { return false }
	res, err := s.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patched {
		t.Fatal("patched during an unsettled rollout — should have skipped")
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A drifted, settled DaemonSet gets the static patch — the fake
// tracker applies the strategic merge for real.
func TestDaemonSetSpecAppliesPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	s := baseDSSpec(cs)
	s.Settled = func(*appsv1.DaemonSet) bool { return true }
	res, err := s.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := getDS(t, cs).Spec.Template.Spec.PriorityClassName; got !=
		"system-node-critical" {
		t.Fatalf("priorityClassName = %q, want system-node-critical", got)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
}

// A nil Settled gate means "patch whenever drifted" — the DS specs
// that carry no rollout concern never wire one.
func TestDaemonSetSpecNilSettledPatches(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	s := baseDSSpec(cs) // Settled stays nil
	if _, err := s.Reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := getDS(t, cs).Spec.Template.Spec.PriorityClassName; got !=
		"system-node-critical" {
		t.Fatalf("priorityClassName = %q, want system-node-critical", got)
	}
}

// A failed drift patch errors the reconcile — the metric must
// surface a persistent failure to re-pin.
func TestDaemonSetSpecPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(pinnedDS())
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	_, err := baseDSSpec(cs).Reconcile(t.Context())
	if err == nil {
		t.Fatal("expected error when the drift patch fails")
	}
	if !strings.Contains(err.Error(), "patch daemonset kube-system/agent") {
		t.Fatalf("error missing the wrapped ref: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Informer-cache read + direct-CS drift confirm (Reader seam)
// ---------------------------------------------------------------------------

// A drifted cache read with a settled LIVE object must not patch —
// the destructive path confirms on the direct clientset. Drifted
// keys on the priorityClassName: the cache copy carries it (drifted),
// the live copy does not.
func TestDaemonSetSpecCachedReadConfirmSkipsSettled(t *testing.T) {
	live := pinnedDS()
	stale := pinnedDS()
	stale.Spec.Template.Spec.PriorityClassName = "system-node-critical" // drifted per the hook
	cs := fake.NewSimpleClientset(live)
	var patched bool
	forbidDSPatch(cs, &patched)

	s := baseDSSpec(cs)
	s.Reader = &fakeCacheReader{objs: []client.Object{stale}}
	s.Drifted = func(ds *appsv1.DaemonSet) bool {
		return ds.Spec.Template.Spec.PriorityClassName == "system-node-critical"
	}
	res, err := s.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 15*time.Minute {
		t.Fatalf("expected 15m requeue, got %s", res.RequeueAfter)
	}
	if patched {
		t.Fatal("patched off a stale cache read — the direct-CS confirm must veto")
	}
}

// A drifted cache read with a drifted LIVE object still patches.
func TestDaemonSetSpecCachedReadConfirmPatchesDrift(t *testing.T) {
	live := pinnedDS()
	live.Spec.Template.Spec.PriorityClassName = "system-node-critical"
	stale := pinnedDS()
	stale.Spec.Template.Spec.PriorityClassName = "system-node-critical"
	cs := fake.NewSimpleClientset(live)
	var patches int
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})

	s := baseDSSpec(cs)
	s.Reader = &fakeCacheReader{objs: []client.Object{stale}}
	s.Drifted = func(ds *appsv1.DaemonSet) bool {
		return ds.Spec.Template.Spec.PriorityClassName == "system-node-critical"
	}
	if _, err := s.Reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if patches != 1 {
		t.Fatalf("confirmed drift patch attempts = %d, want 1", patches)
	}
}
