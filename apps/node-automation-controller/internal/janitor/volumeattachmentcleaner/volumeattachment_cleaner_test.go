package volumeattachmentcleaner

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// vaTrackedCount reports how many keys a FirstSeenLedger holds —
// the ledger exposes no Len, so a keep-all Prune does the counting.
func vaTrackedCount(l *state.FirstSeenLedger) int {
	n := 0
	l.Prune(func(string) bool { n++; return true })
	return n
}

// ---------------------------------------------------------------------------
// Builders (vac-prefixed)
// ---------------------------------------------------------------------------

func vacNode(name string, ready corev1.ConditionStatus, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: ready}}},
	}
}

func vacAttachment(name, node string, created time.Time) *storagev1.VolumeAttachment {
	return &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(created)},
		Spec: storagev1.VolumeAttachmentSpec{
			Attacher: "test.csi.example",
			NodeName: node,
			Source:   storagev1.VolumeAttachmentSource{PersistentVolumeName: ptr.To("pv-" + name)},
		},
	}
}

func vacPod(ns, name, node string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: phase},
	}
}

func newVACleaner(cs *fake.Clientset, now shared.Clock) *volumeAttachmentCleaner {
	return &volumeAttachmentCleaner{
		cs:    cs,
		queue: "volumeattachment-cleaner",
		now:   now,
	}
}

func vaExists(t *testing.T, cs *fake.Clientset, name string) bool {
	t.Helper()
	_, err := cs.StorageV1().VolumeAttachments().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get va %s: %v", name, err)
	return false
}

// outOfService is the fencing taint dead-node-sweeper applies.
var outOfService = corev1.Taint{
	Key:    vaOutOfServiceTaint,
	Value:  "nodeshutdown",
	Effect: corev1.TaintEffectNoExecute,
}

// ---------------------------------------------------------------------------
// missing_node
// ---------------------------------------------------------------------------

// A VA pointing at a deleted node is recorded on the first sighting
// and only reaped on the second — a one-off node List gap must never
// detach a volume.
func TestVACleanerMissingNodeTwoSightings(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-orphan", "gone-node", now.Add(-10*time.Minute)),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	before := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("missing_node"))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted on first orphan sighting")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-orphan", time.Now()); !ok {
		t.Fatal("first sighting not recorded in orphanFirstSeen")
	}

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-orphan") {
		t.Fatal("VA not deleted on second consecutive sighting")
	}
	if got := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("missing_node")) - before; got != 1 {
		t.Fatalf("missing_node counter delta = %v, want 1", got)
	}
	if _, ok := c.orphanFirstSeen.Seen("va-orphan", time.Now()); ok {
		t.Fatal("deleted VA still tracked in orphanFirstSeen")
	}
}

// The 5m age gate holds even on a second sighting — a fresh VA may
// still be racing its node create.
func TestVACleanerMissingNodeTooYoung(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-young", "gone-node", now.Add(-2*time.Minute)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	for i := 0; i < 2; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !vaExists(t, cs, "va-young") {
		t.Fatal("VA younger than 5m deleted despite second sighting")
	}
	// Past the age gate the next sighting reaps it.
	now = now.Add(4 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-young") {
		t.Fatal("VA kept after both age gate and sightings passed")
	}
}

// A node that reappears resets the two-sighting window — the VA must
// be seen orphaned twice again before it is eligible.
func TestVACleanerNodeReappearsResetsGrace(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-flap", "flap-node", now.Add(-30*time.Minute)),
		vacNode("alive", corev1.ConditionTrue),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting
	if _, err := cs.CoreV1().Nodes().Create(ctx,
		vacNode("flap-node", corev1.ConditionTrue), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.orphanFirstSeen.Seen("va-flap", time.Now()); ok {
		t.Fatal("orphan tracking not pruned when the node reappeared")
	}
	if err := cs.CoreV1().Nodes().Delete(ctx, "flap-node", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted on first sighting after node re-flapped away")
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-flap") {
		t.Fatal("VA not deleted on second consecutive sighting")
	}
}

// A VA already in Terminating is never touched — a second delete
// cannot unstick its finalizer anyway.
func TestVACleanerSkipsTerminatingVA(t *testing.T) {
	now := time.Now()
	ts := metav1.NewTime(now.Add(-time.Hour))
	va := vacAttachment("va-terminating", "gone-node", now.Add(-30*time.Minute))
	va.DeletionTimestamp = &ts
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue), va)
	c := newVACleaner(cs, func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !vaExists(t, cs, "va-terminating") {
		t.Fatal("terminating VA touched")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-terminating", time.Now()); ok {
		t.Fatal("terminating VA tracked as orphan")
	}
}

// ---------------------------------------------------------------------------
// out_of_service_node
// ---------------------------------------------------------------------------

// A fenced node (out-of-service taint) that stays not-Ready past the
// window and hosts no non-terminal pods gets its VAs reaped. A
// terminal pod on the node does not block.
func TestVACleanerOutOfService(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacPod("data", "old-job", "dead", corev1.PodSucceeded),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	before := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("out_of_service_node"))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted before the 15m not-Ready window elapsed")
	}
	now = now.Add(16 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-fenced") {
		t.Fatal("VA kept on fenced node past the window with 0 live pods")
	}
	if got := promtest.ToFloat64(metrics.VolumeAttachmentsCleanedTotal.
		WithLabelValues("out_of_service_node")) - before; got != 1 {
		t.Fatalf("out_of_service_node counter delta = %v, want 1", got)
	}
}

// A single non-terminal pod on the fenced node keeps the VA — the
// mount may still be real.
func TestVACleanerOutOfServicePodsBlock(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacPod("data", "still-running", "dead", corev1.PodRunning),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted while a non-terminal pod still sits on the node")
	}
}

// The 15m not-Ready window re-arms when the node flips Ready — a
// flap cannot smuggle a detach in under the wire.
func TestVACleanerNotReadyWindowRearms(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("flap", corev1.ConditionFalse, outOfService),
		vacAttachment("va-flap", "flap", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted inside the not-Ready window")
	}
	// Node recovers → the death clock must reset.
	if _, err := cs.CoreV1().Nodes().Update(ctx,
		vacNode("flap", corev1.ConditionTrue, outOfService), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.nodeNotReadySince.Seen("flap", time.Now()); ok {
		t.Fatal("not-Ready ledger not pruned on recovery")
	}
	// Node dies again — a fresh window starts now, so even after the
	// original 15m mark the VA must survive the first new cycle.
	if _, err := cs.CoreV1().Nodes().Update(ctx,
		vacNode("flap", corev1.ConditionFalse, outOfService), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted on a re-armed not-Ready window")
	}
}

// NotReady without the fencing taint is never enough — the taint is
// the declaration that a fencer already judged the node dead.
func TestVACleanerKeepsUntaintedNotReadyNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("sick", corev1.ConditionFalse), // no taint
		vacAttachment("va-sick", "sick", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-healthy", "alive", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"va-sick", "va-healthy"} {
		if !vaExists(t, cs, name) {
			t.Fatalf("VA %s deleted without fencing evidence", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Hard bounds & error paths
// ---------------------------------------------------------------------------

// The cap bounds detach churn at vaDeleteCap per cycle even when more
// VAs are eligible.
func TestVACleanerCap(t *testing.T) {
	now := time.Now()
	objs := []runtime.Object{vacNode("alive", corev1.ConditionTrue)}
	for i := 0; i < vaDeleteCap+2; i++ {
		objs = append(objs, vacAttachment(
			fmt.Sprintf("va-%02d", i), "gone-node", now.Add(-time.Hour)))
	}
	cs := fake.NewSimpleClientset(objs...)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting for all
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining, err := cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 2 {
		t.Fatalf("expected exactly 2 survivors after cap=%d, got %d",
			vaDeleteCap, len(remaining.Items))
	}
}

// Zero nodes means the apiserver/RBAC broke — every VA would look
// orphaned, so nothing is evaluated or recorded. The refusal is
// deliberately non-fatal (nil return) but MUST be metered — a
// persistently-empty node list is broken RBAC, invisible otherwise.
func TestVACleanerEmptyNodeListAborts(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)))
	c := newVACleaner(cs, func() time.Time { return now })

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatalf("empty node list must abort cleanly, got %v", err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted with an empty node list")
	}
	if vaTrackedCount(&c.orphanFirstSeen) != 0 {
		t.Fatal("orphan sightings recorded on an aborted run")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("empty node list not metered: error delta = %v, want 1", got)
	}
}

// A node list failure is a real error — the periodic wrapper meters it.
func TestVACleanerNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, time.Now)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A VA list failure is likewise a real error.
func TestVACleanerVAListError(t *testing.T) {
	cs := fake.NewSimpleClientset(vacNode("alive", corev1.ConditionTrue))
	cs.PrependReactor("list", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, time.Now)
	if err := c.run(ctx); err == nil {
		t.Fatal("expected error when the volumeattachment list fails")
	}
}

// A pod list failure on the out-of-service path fails closed: the VA
// is kept and the run itself does not error.
func TestVACleanerPodListErrorFailsClosed(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatalf("pod list failure must not error the run: %v", err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted when the pod count could not be confirmed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("queue error delta = %v, want 1", got)
	}
}

// The delete carries a UID precondition — VA names are deterministic
// csi-hash names, so a re-attachment between list and delete recreates
// the SAME name and only the vetted object may be removed.
func TestVACleanerDeleteUIDPrecondition(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour))
	va.UID = "uid-va-orphan"
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue), va)
	var gotUID *types.UID
	cs.PrependReactor("delete", "volumeattachments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	c := newVACleaner(cs, func() time.Time { return now })

	for i := 0; i < 2; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if gotUID == nil || *gotUID != va.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if vaExists(t, cs, "va-orphan") {
		t.Fatal("orphan VA not deleted")
	}
}

// A failed VA delete is tolerated (logged + metered) — the run still
// nils out and the VA survives for the next sweep.
func TestVACleanerDeleteErrorTolerated(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)))
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	} // first sighting
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("delete rejected")
		})
	if err := c.run(ctx); err != nil {
		t.Fatalf("VA delete failures must not error the run: %v", err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted despite the failing delete call")
	}
}

// va-stuck-terminating — a VolumeAttachment Terminating >15m whose node is gone has its
// finalizers stripped (the attacher-side detach can never drain).
func TestVACleanerStuckTerminatingFinalizerStrip(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck", "node-gone", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w-live", corev1.ConditionTrue)) // va's node-gone absent from the live list
	c := newVACleaner(cs, func() time.Time { return now })
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("stuck VA finalizers not stripped: %v", got.Finalizers)
	}
}

// Same shape but inside the 15m grace window — left for the
// stuck-terminating audit, not stripped.
func TestVACleanerStuckTerminatingTooYoung(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-fresh", "node-gone", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-5 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w-live", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-fresh", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped inside the grace window")
	}
}

// ---------------------------------------------------------------------------
// Ready-node unused-volume branch (fast-reboot dangling VA)
// ---------------------------------------------------------------------------

// vacPV builds a CSI PersistentVolume — its kubelet unique name is
// "kubernetes.io/csi/<driver>^<handle>".
func vacPV(name, driver, handle string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver: driver, VolumeHandle: handle}}}}
}

// vacClaim builds a PVC bound to volume.
func vacClaim(ns, name, volume string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: volume}}
}

// vacPVCUser builds a Running pod on node that mounts claim.
func vacPVCUser(ns, name, node, claim string) *corev1.Pod {
	p := vacPod(ns, name, node, corev1.PodRunning)
	p.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: claim}}}}
	return p
}

// A VA stuck Terminating >=15m on a node that rebooted back to Ready
// (no out-of-service taint) gets its finalizers stripped — but only
// when the unused-volume proof held in TWO consecutive cycles: no
// non-terminal pod mounts the PV and the volume is absent from
// VolumesInUse/VolumesAttached.
func TestVolumeAttachmentCleanerStuckReadyNodeUnused(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck-ready", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	node := vacNode("w1", corev1.ConditionTrue)
	// The kubelet no longer reports the volume anywhere.
	cs := fake.NewSimpleClientset(va, node, vacPV("pv-data", "csi.test", "vol-1"),
		vacPod("infra", "agent", "w1", corev1.PodRunning))
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck-ready", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped on the first sighting — needs 2 cycles")
	}
	if _, ok := c.stuckReadyFirstSeen.Seen("va-stuck-ready", time.Now()); !ok {
		t.Fatal("ready-node sighting not recorded")
	}

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck-ready", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("stuck finalizers not stripped on second sighting: %v", got.Finalizers)
	}
}

// A non-terminal pod still mounting the PV (through its PVC) blocks
// the strip — the mount may still be real.
func TestVolumeAttachmentCleanerStuckReadyPodBlocks(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-blocked", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	cs := fake.NewSimpleClientset(va, vacNode("w1", corev1.ConditionTrue),
		vacPV("pv-data", "csi.test", "vol-1"),
		vacClaim("data", "claim-a", "pv-data"),
		vacPVCUser("data", "writer", "w1", "claim-a"))
	c := newVACleaner(cs, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while a pod still mounts the PV")
	}
}

// A volume still present in node.Status.VolumesInUse blocks the
// strip — the kubelet's own ledger says the mount may still exist.
func TestVolumeAttachmentCleanerStuckReadyVolumeInUseBlocks(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-inuse", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	va.Spec.Source.PersistentVolumeName = ptr.To("pv-data")
	node := vacNode("w1", corev1.ConditionTrue)
	node.Status.VolumesInUse = []corev1.UniqueVolumeName{
		"kubernetes.io/csi/csi.test^vol-1"}
	node.Status.VolumesAttached = []corev1.AttachedVolume{{
		Name: "kubernetes.io/csi/csi.test^vol-1", DevicePath: "/var/x"}}
	cs := fake.NewSimpleClientset(va, node,
		vacPV("pv-data", "csi.test", "vol-1"))
	c := newVACleaner(cs, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if err := c.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-inuse", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while the volume is still in-use on the node")
	}
}

// ---------------------------------------------------------------------------
// Live confirm on the direct clientset (stale-informer guard)
// ---------------------------------------------------------------------------

// staleNodes is a CachedNodeReader stub playing the informer cache:
// it returns exactly the nodes handed to it, independent of the
// fake clientset that plays the live apiserver — a census/live
// split the direct confirm must resolve.
type staleNodes struct{ items []corev1.Node }

func (s *staleNodes) List(_ context.Context, list client.ObjectList,
	_ ...client.ListOption) error {
	nl := list.(*corev1.NodeList)
	nl.Items = append(nl.Items, s.items...)
	return nil
}

// The informer census has dropped the node but the live Get still
// finds it: the LIVE answer wins — the VA survives, the stale
// orphan sighting re-arms, and nothing is metered.
func TestVACleanerLiveConfirmOverridesStaleMissingNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-stale", "live-node", now.Add(-time.Hour)),
		vacNode("live-node", corev1.ConditionTrue),
		vacNode("other", corev1.ConditionTrue), // keeps the census non-empty
	)
	c := newVACleaner(cs, func() time.Time { return now })
	// The cache plays stale: live-node is missing from it.
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("other", corev1.ConditionTrue)}}
	// The orphan sighting predates this cycle, so the census verdict
	// is destructive and the direct confirm actually runs.
	c.orphanFirstSeen.Seed("va-stale", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-stale") {
		t.Fatal("VA deleted while the live apiserver still has the node")
	}
	if _, ok := c.orphanFirstSeen.Seen("va-stale", now); ok {
		t.Fatal("stale orphan sighting not re-armed after the live confirm")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("stale-snapshot save not metered as an error: delta = %v, want 0", got)
	}
}

// Same split on the out-of-service branch: the census still shows
// the node fenced and past the not-Ready window, but the live node
// is Ready again — the gate re-runs on the LIVE node and keeps the
// VA.
func TestVACleanerLiveConfirmOverridesStaleFencedNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-flap", "flap", now.Add(-time.Hour)),
		vacNode("flap", corev1.ConditionTrue, outOfService), // live: recovered
		vacNode("other", corev1.ConditionTrue),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("flap", corev1.ConditionFalse, outOfService)}} // census: dead
	c.nodeNotReadySince.Seed("flap", now.Add(-20*time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted while the live node is Ready again")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("stale-snapshot save not metered as an error: delta = %v, want 0", got)
	}
}

// A live node Get that fails keeps the VA (fail closed) and meters
// once — an unverifiable confirm must never detach a volume.
func TestVACleanerLiveConfirmErrorFailsClosed(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-orphan", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-orphan", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-orphan") {
		t.Fatal("VA deleted when the live confirm itself failed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("failed confirm not metered: error delta = %v, want 1", got)
	}
}

// The strip branch live-wins too: the census dropped the node, but
// the live apiserver has it Ready with no prior unused-volume
// sighting — the finalizers stay.
func TestVACleanerLiveConfirmOverridesStaleStrip(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-stuck", "w1", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va,
		vacNode("w1", corev1.ConditionTrue),
		vacNode("other", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })
	c.nodeReader = &staleNodes{items: []corev1.Node{
		*vacNode("other", corev1.ConditionTrue)}} // census: w1 gone

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-stuck", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers stripped while the live apiserver still has the node")
	}
}

// ---------------------------------------------------------------------------
// OnError race classification (NotFound / Conflict are not failures)
// ---------------------------------------------------------------------------

// A delete answered NotFound raced an external cleanup — logged as a
// skip, not metered as an error.
func TestVACleanerDeleteNotFoundNotMetered(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-raced", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				storagev1.Resource("volumeattachments"), "va-raced")
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-raced", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("NotFound race metered as an error: delta = %v, want 0", got)
	}
	if !vaExists(t, cs, "va-raced") {
		t.Fatal("VA vanished despite the rejected delete")
	}
}

// A Conflict answer is the UID precondition firing on a recreated
// same-name VA — equally a race, equally not an error.
func TestVACleanerDeleteConflictNotMetered(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacAttachment("va-raced", "gone-node", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
	)
	cs.PrependReactor("delete", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(
				storagev1.Resource("volumeattachments"), "va-raced",
				errors.New("uid mismatch"))
		})
	c := newVACleaner(cs, func() time.Time { return now })
	c.orphanFirstSeen.Seed("va-raced", now.Add(-time.Minute))

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 0 {
		t.Fatalf("Conflict race metered as an error: delta = %v, want 0", got)
	}
	if !vaExists(t, cs, "va-raced") {
		t.Fatal("VA vanished despite the rejected delete")
	}
}

// ---------------------------------------------------------------------------
// uniqueVolumeName / volumeOnNode — kubelet ledger shapes
// ---------------------------------------------------------------------------

// uniqueVolumeName resolves CSI and Local PVs to the kubelet unique
// volume name; any other PV shape (HostPath, NFS, ...) is
// unresolvable — the caller must fail closed, not guess.
func TestUniqueVolumeNameShapes(t *testing.T) {
	csi := vacPV("pv-csi", "csi.test", "vol-1")
	local := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-local"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				Local: &corev1.LocalVolumeSource{Path: "/mnt/disks/x"}}}}
	hostPath := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-host"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}}}
	nfs := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				NFS: &corev1.NFSVolumeSource{Server: "srv", Path: "/exp"}}}}

	tt := []struct {
		name   string
		pv     *corev1.PersistentVolume
		want   string
		wantOK bool
	}{
		{"csi", csi, "kubernetes.io/csi/csi.test^vol-1", true},
		{"local", local, "kubernetes.io/local-volume/pv-local", true},
		{"hostpath", hostPath, "", false},
		{"nfs", nfs, "", false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := uniqueVolumeName(tc.pv)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("uniqueVolumeName = (%q, %v), want (%q, %v)",
					got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// A Local PV resolves to "kubernetes.io/local-volume/<pv.Name>" and
// is matched against the node's VolumesInUse/Attached ledger — present
// blocks the strip; absent proves it unused. An unresolvable shape
// (HostPath) is never verifiable: the gate must fail closed.
func TestVolumeOnNodeResolvesLocalPV(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-local"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					Local: &corev1.LocalVolumeSource{Path: "/mnt/disks/x"}}}},
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-host"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}}},
	)
	c := newVACleaner(cs, time.Now)
	log := logf.FromContext(ctx)
	node := vacNode("w1", corev1.ConditionTrue)
	node.Status.VolumesInUse = []corev1.UniqueVolumeName{
		"kubernetes.io/local-volume/pv-local"}
	cache := map[string]pvProbe{}

	inUse, verifiable := c.volumeOnNode(ctx, cache, node, "pv-local", log)
	if !inUse || !verifiable {
		t.Fatalf("local PV in VolumesInUse = (%v, %v), want (true, true)", inUse, verifiable)
	}
	node.Status.VolumesInUse = nil
	cache = map[string]pvProbe{} // fresh cycle cache
	inUse, verifiable = c.volumeOnNode(ctx, cache, node, "pv-local", log)
	if inUse || !verifiable {
		t.Fatalf("local PV absent from ledger = (%v, %v), want (false, true)", inUse, verifiable)
	}
	cache = map[string]pvProbe{}
	inUse, verifiable = c.volumeOnNode(ctx, cache, node, "pv-host", log)
	if inUse || verifiable {
		t.Fatalf("hostpath PV = (%v, %v), want (false, false) — fail closed", inUse, verifiable)
	}
}

// ---------------------------------------------------------------------------
// pvcBoundVolume — fail-closed memoized claim lookup
// ---------------------------------------------------------------------------

// A PVC bound to a different PV resolves to that PV name; a NotFound
// claim reads as "" with no error; a non-NotFound Get failure fails
// closed, is metered exactly ONCE (the memoized probe carries the
// reported flag), and keeps returning the error on re-reads.
func TestPVCBoundVolumeVerdicts(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("alive", corev1.ConditionTrue),
		vacClaim("data", "claim-bound", "pv-other"))
	c := newVACleaner(cs, func() time.Time { return now })
	log := logf.FromContext(ctx)

	vol, err := c.pvcBoundVolume(ctx, map[string]pvcProbe{}, "data", "claim-bound", log)
	if err != nil || vol != "pv-other" {
		t.Fatalf("bound claim = (%q, %v), want (pv-other, nil)", vol, err)
	}
	vol, err = c.pvcBoundVolume(ctx, map[string]pvcProbe{}, "data", "claim-gone", log)
	if err != nil || vol != "" {
		t.Fatalf("missing claim = (%q, %v), want (\"\", nil)", vol, err)
	}

	cs.PrependReactor("get", "persistentvolumeclaims",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.(ktesting.GetAction).GetName() == "claim-broken" {
				return true, nil, errors.New("api down")
			}
			return false, nil, nil // fall through to the tracker
		})
	cache := map[string]pvcProbe{}
	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	vol, err = c.pvcBoundVolume(ctx, cache, "data", "claim-broken", log)
	if err == nil || vol != "" {
		t.Fatalf("broken claim = (%q, %v), want (\"\", error)", vol, err)
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("pvc lookup failure not metered exactly once: delta = %v, want 1", got)
	}
	// Memoized: the second read returns the cached error without a
	// second metering.
	if _, err = c.pvcBoundVolume(ctx, cache, "data", "claim-broken", log); err == nil {
		t.Fatal("memoized error lost on re-read")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("memoized pvc error re-metered: delta = %v, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// confirmLiveNode — the three-way destructive verdict
// ---------------------------------------------------------------------------

// NotFound stands (gone=true), a live node wins (gone=false with the
// node handed back), and a failed confirm reports the error with
// gone=false so callers keep the VA fail-closed.
func TestConfirmLiveNodeVerdicts(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(vacNode("present", corev1.ConditionTrue))
	c := newVACleaner(cs, func() time.Time { return now })

	node, gone, err := c.confirmLiveNode(ctx, "present")
	if err != nil || gone || node == nil || node.Name != "present" {
		t.Fatalf("live node = (%v, %v, %v), want (node, false, nil)", node, gone, err)
	}
	node, gone, err = c.confirmLiveNode(ctx, "absent")
	if err != nil || !gone || node != nil {
		t.Fatalf("absent node = (%v, %v, %v), want (nil, true, nil)", node, gone, err)
	}
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	node, gone, err = c.confirmLiveNode(ctx, "present")
	if err == nil || gone || node != nil {
		t.Fatalf("failed confirm = (%v, %v, %v), want (nil, false, error)", node, gone, err)
	}
}

// ---------------------------------------------------------------------------
// stripFinalizers — patch verdict metering
// ---------------------------------------------------------------------------

// A successful strip clears the finalizers and increments
// VolumeAttachmentFinalizersRemovedTotal for the VA's node.
func TestStripFinalizersSuccess(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-strip", "n-strip", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va)
	c := newVACleaner(cs, func() time.Time { return now })
	testutil.CleanupMetric(t, metrics.VolumeAttachmentFinalizersRemovedTotal, "n-strip")

	before := promtest.ToFloat64(
		metrics.VolumeAttachmentFinalizersRemovedTotal.WithLabelValues("n-strip"))
	if err := c.stripFinalizers(ctx, va); err != nil {
		t.Fatalf("stripFinalizers: %v", err)
	}
	if got := promtest.ToFloat64(
		metrics.VolumeAttachmentFinalizersRemovedTotal.WithLabelValues("n-strip")) - before; got != 1 {
		t.Fatalf("finalizer-removed counter delta = %v, want 1", got)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-strip", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 {
		t.Fatalf("finalizers not cleared by the patch: %v", got.Finalizers)
	}
}

// A failed patch is metered (IncError) and reported — the finalizers
// must survive for the next sweep's retry.
func TestStripFinalizersPatchError(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-strip", "n-strip", now.Add(-time.Hour))
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	va.DeletionTimestamp = &termAt
	va.Finalizers = []string{"external-attacher/csi-test"}
	cs := fake.NewSimpleClientset(va)
	c := newVACleaner(cs, func() time.Time { return now })
	cs.PrependReactor("patch", "volumeattachments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})

	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	if err := c.stripFinalizers(ctx, va); err == nil {
		t.Fatal("expected the patch failure to be reported")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("patch failure not metered: error delta = %v, want 1", got)
	}
	got, err := cs.StorageV1().VolumeAttachments().Get(ctx, "va-strip", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizers lost despite the failed patch")
	}
}

// The strip counter's series is bounded by the node census:
// stripFinalizers records the tuple it Inc'd, each sweep's
// carry-forward re-arms the tuples whose node this census still
// lists, and the end-of-sweep Prune retires the series once the node
// is gone — node-pool rotation must not grow the vec for the process
// lifetime (the deadnodesweeper's fencedWithoutSNREmitted shape).
func TestRunPrunesRemovedFinalizerSeriesWhenNodeGone(t *testing.T) {
	now := time.Now()
	termAt := metav1.NewTime(now.Add(-30 * time.Minute))
	mkStrip := func(name, node string) *storagev1.VolumeAttachment {
		va := vacAttachment(name, node, now.Add(-time.Hour))
		va.DeletionTimestamp = &termAt
		va.Finalizers = []string{"external-attacher/csi-test"}
		return va
	}
	va := mkStrip("va-strip", "n-gone")
	cs := fake.NewSimpleClientset(vacNode("alive", corev1.ConditionTrue), va)
	c := newVACleaner(cs, func() time.Time { return now })
	testutil.CleanupMetric(t, metrics.VolumeAttachmentFinalizersRemovedTotal, "n-gone")
	testutil.CleanupMetric(t, metrics.VolumeAttachmentFinalizersRemovedTotal, "alive")

	// A strip already counted for a node the NEXT census may not list
	// ("alive" stays listed; this is the pre-seeded live series the
	// carry-forward must keep).
	c.finalizersRemovedEmitted.Emit("alive", "alive")
	metrics.VolumeAttachmentFinalizersRemovedTotal.WithLabelValues("alive").Inc()
	c.finalizersRemovedEmitted.Prune(func(...string) bool { return false })

	// Sweep 1: the stuck-Terminating VA on the gone node is stripped
	// (nodeByName misses → confirmLiveNode NotFound → strip) and its
	// tuple recorded; "alive" is carried forward.
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := promtest.ToFloat64(
		metrics.VolumeAttachmentFinalizersRemovedTotal.WithLabelValues("n-gone")); got != 1 {
		t.Fatalf("strip counter delta = %v, want 1", got)
	}
	if _, ok := c.finalizersRemovedEmitted.Last()["alive"]; !ok {
		t.Fatal("carry-forward dropped the tuple of a node the census still lists")
	}

	// Sweep 2: the VA is gone and "n-gone" is still absent from the
	// census — its series must be retired, "alive"'s kept.
	if err := cs.StorageV1().VolumeAttachments().Delete(ctx, "va-strip",
		metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.VolumeAttachmentFinalizersRemovedTotal.DeleteLabelValues("n-gone") {
		t.Fatal("series of a census-gone node survived the end-of-sweep prune")
	}
	if _, ok := c.finalizersRemovedEmitted.Last()["alive"]; !ok {
		t.Fatal("prune dropped the tuple of a node the census still lists")
	}
	if _, ok := c.finalizersRemovedEmitted.Last()["n-gone"]; ok {
		t.Fatal("ledger kept the tuple of a census-gone node")
	}
}
