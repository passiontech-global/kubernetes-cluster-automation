package deschedulerstormgate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// stormEvidence.storming — the verdict's fold over the signal slices.
// ---------------------------------------------------------------------------

// Any one non-empty signal slice is storm evidence; all empty is a
// clear verdict.
func TestStormEvidenceStorming(t *testing.T) {
	cases := []struct {
		name string
		ev   *stormEvidence
		want bool
	}{
		{"all empty is clear", &stormEvidence{}, false},
		{"notReady alone storms", &stormEvidence{notReady: []string{"n1"}}, true},
		{"bad alone storms", &stormEvidence{bad: []string{"n1"}}, true},
		{"tainted alone storms", &stormEvidence{tainted: []string{"n1"}}, true},
		{"cordoned alone storms", &stormEvidence{cordoned: []string{"n1"}}, true},
		{"maintenance alone storms", &stormEvidence{maintenance: []string{"kured"}}, true},
		{"preempted alone storms", &stormEvidence{preempted: []string{"pod"}}, true},
		{"imagePull alone storms", &stormEvidence{imagePull: []string{"pod"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.storming(); got != tc.want {
				t.Fatalf("storming() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hold-TOCTOU guard — the scale patch's resourceVersion precondition.
// ---------------------------------------------------------------------------

// The hold-annotation TOCTOU: three cluster-wide scans run between
// the deployment Get and the scale patch, so an operator setting
// storm-gate-hold=true mid-sweep used to be defeated — the patch
// carried no precondition and silently scaled anyway. The patch now
// pins the Get's metadata.resourceVersion; the apiserver rejects with
// 409 and the reconcile DEFERS: no scale, no decision annotation, no
// error, the regular cadence re-reads everything next sweep.
func TestStormGateMidSweepHoldConflictDefers(t *testing.T) {
	deploy := deschedulerDeploy(2, nil) // clear verdict -> want 1 -> scale patch fires
	deploy.ResourceVersion = "42"
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deploy)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	deployGVR := appsv1.SchemeGroupVersion.WithResource("deployments")
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			pa := a.(ktesting.PatchAction)
			var body struct {
				Metadata struct {
					ResourceVersion string `json:"resourceVersion"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(pa.GetPatch(), &body); err != nil {
				t.Fatalf("unmarshal patch body: %v", err)
			}
			// The operator sets the hold annotation mid-sweep — a
			// concurrent write the fake tracker does not replay for
			// us, so the reactor performs it by hand the way the
			// apiserver would (RV bumped 42 -> 43). All tracker
			// access here goes through cs.Tracker() directly: the
			// reactor already runs under Fake.Invokes' exclusive
			// lock, and a nested clientset call would re-enter it
			// and deadlock.
			tracked, err := cs.Tracker().Get(
				deployGVR, "kube-system", "descheduler", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get deployment inside reactor: %v", err)
			}
			live := tracked.(*appsv1.Deployment)
			if live.Annotations == nil {
				live.Annotations = map[string]string{}
			}
			live.Annotations[stormGateHoldAnno] = "true"
			live.ResourceVersion = "43"
			cs.Tracker().Update(deployGVR, live, "kube-system")
			// The apiserver contract this test stands in for: a merge
			// patch whose metadata.resourceVersion no longer matches
			// the live object is rejected with 409 Conflict.
			if body.Metadata.ResourceVersion != "43" {
				return true, nil, apierrors.NewConflict(
					deployGVR.GroupResource(), "descheduler",
					errors.New("the object has been modified; please apply your changes to the latest version and try again"))
			}
			return false, nil, nil
		})
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatalf("a lost race must defer, not error the reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Minute {
		t.Fatalf("deferred sweep lost the regular 5m requeue: %+v", res)
	}
	if got := getDeschedulerReplicas(t, cs); got != 2 {
		t.Fatalf("scaled despite the mid-sweep hold — replicas=%d", got)
	}
	d := getDescheduler(t, cs)
	if d.Annotations[stormGateHoldAnno] != "true" {
		t.Fatalf("mid-sweep hold annotation lost: %v", d.Annotations)
	}
	if got := d.Annotations[stormGateDecisionAnno]; got != "" {
		t.Fatalf("decision annotation written on a conflicted sweep: %q", got)
	}
}

// A deployment with spec.replicas unset reads as the API default of
// 1: a clear verdict scales nothing (the old cur=-1 sentinel forced
// a redundant scale patch on EVERY clear reconcile against such a
// deployment) and the decision annotation carries cur=1 evidence,
// not an empty cur=.
func TestStormGateNilReplicasDefaultsToOne(t *testing.T) {
	deploy := deschedulerDeploy(1, nil)
	deploy.Spec.Replicas = nil
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil), // clear -> want 1
		deploy)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	var patches [][]byte
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			patches = append(patches, a.(ktesting.PatchAction).GetPatch())
			return false, nil, nil
		})
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range patches {
		if strings.Contains(string(p), "replicas") {
			t.Fatalf("nil replicas scaled although the API default is already 1: %s", p)
		}
	}
	decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]
	if !strings.Contains(decision, "want=1") || !strings.Contains(decision, "cur=1") {
		t.Fatalf("decision annotation missing the cur=1 API default: %q", decision)
	}
}
