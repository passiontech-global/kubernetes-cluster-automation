package volumeattachmentcleaner

import (
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

// W4 — a VolumeAttachment Terminating >15m whose node is gone has its
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
