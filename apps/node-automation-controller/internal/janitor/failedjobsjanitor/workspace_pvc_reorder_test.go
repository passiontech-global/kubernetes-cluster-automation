// workspace_pvc_reorder_test.go — owner liveness is checked BEFORE the
// per-namespace pod LIST: a still-live run rejects the claim in the
// collect loop, so no pod scan is paid at collect OR at Confirm.
package failedjobsjanitor

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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

// claimedPVCNames pushes terminal-pod filtering server-side via FieldSelector
// while keeping quorum ListEach (no ResourceVersion="0").
func TestClaimedPVCNamesFieldSelector(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var gotFields string
	cs.PrependReactor("list", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			gotFields = a.(ktesting.ListAction).GetListRestrictions().Fields.String()
			return false, nil, nil
		})
	j := &failedJobsJanitor{cs: cs}
	if _, err := j.claimedPVCNames(ctx, "cicd"); err != nil {
		t.Fatal(err)
	}
	if want := "status.phase!=Failed,status.phase!=Succeeded"; gotFields != want {
		t.Fatalf("claimedPVCNames field selector = %q, want %q", gotFields, want)
	}
}

// Multiple orphan PVCs in the same namespace share ONE fresh Confirm pod LIST
// (total 2 pod LISTs: 1 collect + 1 Confirm), and every delete carries its UID
// precondition.
func TestOrphanWorkspacePVCConfirmBatchedPerNamespace(t *testing.T) {
	objs := make([]runtime.Object, 0, 5)
	for i := range 5 {
		pvc := fjjWorkspacePVC("cicd", fmt.Sprintf("pvc-orphan-%d", i), 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil)
		pvc.UID = types.UID(fmt.Sprintf("uid-%d", i))
		objs = append(objs, pvc)
	}
	cs := fake.NewSimpleClientset(objs...)
	var podLists atomic.Int32
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			podLists.Add(1)
			return false, nil, nil
		})
	deletedUIDs := map[string]types.UID{}
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			da := a.(ktesting.DeleteAction)
			if opts := da.GetDeleteOptions(); opts.Preconditions != nil && opts.Preconditions.UID != nil {
				deletedUIDs[da.GetName()] = *opts.Preconditions.UID
			}
			return false, nil, nil
		})

	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now,
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := podLists.Load(); got != 2 {
		t.Fatalf("pod scans = %d, want exactly 2 (1 collect + 1 batched Confirm)", got)
	}
	for i := range 5 {
		name := fmt.Sprintf("pvc-orphan-%d", i)
		if fjjPVCExists(t, cs, "cicd", name) {
			t.Fatalf("orphan pvc %s was not deleted", name)
		}
		if deletedUIDs[name] != types.UID(fmt.Sprintf("uid-%d", i)) {
			t.Fatalf("pvc %s delete UID = %q, want uid-%d", name, deletedUIDs[name], i)
		}
	}
}

// When Confirm's namespace-batched pod LIST fails, all target PVCs in that
// namespace stay protected (fail closed), no re-list is attempted for sibling
// PVCs, and queue error metering increments by exactly 1.
func TestOrphanWorkspacePVCConfirmPodListErrorFailsClosedOnce(t *testing.T) {
	objs := make([]runtime.Object, 0, 3)
	for i := range 3 {
		objs = append(objs, fjjWorkspacePVC("cicd", fmt.Sprintf("pvc-err-%d", i), 8*time.Hour,
			[]metav1.OwnerReference{fjjPVCOwner("tekton.dev/v1", "PipelineRun", "pr-gone")}, nil))
	}
	cs := fake.NewSimpleClientset(objs...)
	var podLists atomic.Int32
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			if podLists.Add(1) == 2 {
				return true, nil, errors.New("confirm pod list failed")
			}
			return false, nil, nil
		})

	j := &failedJobsJanitor{
		cs: cs, dyn: fjjDynFake(), now: time.Now, queue: "failed-jobs-janitor",
		stuckEmitted: state.GaugeLedger[stuckTerminatingKey]{},
	}
	before := testutil.QueueErrorCount(t, "failed-jobs-janitor")
	if err := j.sweepOrphanWorkspacePVCs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := podLists.Load(); got != 2 {
		t.Fatalf("pod scans = %d, want 2 (1 collect + 1 Confirm)", got)
	}
	if got := testutil.QueueErrorCount(t, "failed-jobs-janitor") - before; got != 1 {
		t.Fatalf("queue error delta = %v, want 1 (single IncError for batched confirm)", got)
	}
	for i := range 3 {
		name := fmt.Sprintf("pvc-err-%d", i)
		if !fjjPVCExists(t, cs, "cicd", name) {
			t.Fatalf("pvc %s deleted despite failed confirm pod list", name)
		}
	}
}
