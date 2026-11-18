// workspace_pvc_reorder_test.go — owner liveness is checked BEFORE the
// per-namespace pod LIST: a still-live run rejects the claim in the
// collect loop, so no pod scan is paid at collect OR at Confirm.
package failedjobsjanitor

import (
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// A live run's claim is filtered before claimedPVCNames runs, so the
// namespace's pod LIST is never issued. The old order re-listed pods
// for every candidate before discovering the owner was still alive.
func TestOrphanWorkspacePVCLiveRefSkipsPodListEntirely(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-live-owner", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-live")}, nil)
	cs := fake.NewSimpleClientset(pvc)
	var podLists int32
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&podLists, 1)
			return false, nil, nil // fall through to the tracker
		})
	// No terminal condition → the PipelineRun is still running.
	live := fjjRun(kube.GVRTektonPipelineRun, "PipelineRun",
		"cicd", "pr-live", "", 0)
	dyn := fjjDynFake(live)
	j := &failedJobsJanitor{
		cs: cs, dyn: dyn, now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}

	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-live-owner") {
		t.Fatal("claim with a live owner must be kept")
	}
	if got := atomic.LoadInt32(&podLists); got != 0 {
		t.Fatalf("pod scans = %d, want 0 (live owner filtered before the LIST)", got)
	}

	// Confirm a live pod would have been seen by claimedPVCNames if it
	// had run: dropping such a pod in must not affect the verdict.
	if err := cs.Tracker().Add(fjjPodClaiming("cicd", "runner", "pvc-live-owner", corev1.PodRunning)); err != nil {
		t.Fatal(err)
	}
	if !fjjPVCExists(t, cs, "cicd", "pvc-live-owner") {
		t.Fatal("claim with a live owner must still be kept")
	}
}

// When every owner ref is gone/terminal the pod LIST is still paid at
// collect (and again at Confirm) — the reorder must not suppress the
// fail-closed mount check for genuine orphan candidates.
func TestOrphanWorkspacePVCDoneRefsStillPayPodList(t *testing.T) {
	pvc := fjjWorkspacePVC("cicd", "pvc-done-owner", 8*time.Hour,
		[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
	cs := fake.NewSimpleClientset(pvc)
	var podLists int32
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			atomic.AddInt32(&podLists, 1)
			return false, nil, nil // fall through to the tracker
		})
	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}

	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if fjjPVCExists(t, cs, "cicd", "pvc-done-owner") {
		t.Fatal("orphan claim with no pods was not reaped")
	}
	if got := atomic.LoadInt32(&podLists); got < 2 {
		t.Fatalf("pod scans = %d, want >= 2 (collect + fresh Confirm)", got)
	}
}
