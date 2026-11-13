// va_verdicts_test.go — the unit-level verdict branches the
// sweep-level fixtures cannot reach individually: kubelet ledger
// shapes, memoized claim/PV probes, the live-confirm three-way
// verdict, strip metering, the stuckTerminating verdict matrix and
// the mounted-claim census.
package volumeattachmentcleaner

import (
	"context"
	"errors"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

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

// ---------------------------------------------------------------------------
// stuckTerminatingNodeDead — the wedged-detach verdict branches the
// sweep-level fixtures cannot reach individually
// ---------------------------------------------------------------------------

// The gate's verdict matrix: node gone strips; a Ready node needs
// the two-cycle unused proof (stuckReadyPrior); a fenced node must
// be past the not-Ready window AND prove zero live workload pods —
// every unverifiable read fails closed.
func TestStuckTerminatingNodeDeadVerdicts(t *testing.T) {
	now := time.Now()
	va := vacAttachment("va-x", "node-1", now.Add(-time.Hour))

	readyNode := vacNode("node-1", corev1.ConditionTrue)
	fencedNode := vacNode("node-1", corev1.ConditionFalse, outOfService)

	newCleaner := func() *volumeAttachmentCleaner {
		return newVACleaner(fake.NewSimpleClientset(), func() time.Time { return now })
	}

	// Node object gone outright — nothing left to detach from.
	if !newCleaner().stuckTerminatingNodeDead(ctx, va, map[string]*corev1.Node{},
		map[string]podListProbe{}, nil, now) {
		t.Fatal("missing node must read dead")
	}
	// Ready node, no taints: only the prior-cycle unused proof opens
	// the strip — first sight stays closed.
	c := newCleaner()
	nodes := map[string]*corev1.Node{"node-1": readyNode}
	if c.stuckTerminatingNodeDead(ctx, va, nodes,
		map[string]podListProbe{}, map[string]bool{}, now) {
		t.Fatal("ready node without prior-cycle proof must stay closed")
	}
	if !c.stuckTerminatingNodeDead(ctx, va, nodes,
		map[string]podListProbe{}, map[string]bool{"va-x": true}, now) {
		t.Fatal("ready node with prior-cycle unused proof must open")
	}
	// Untainted but NOT Ready — the fenced window never started, the
	// plain node-fenced path owns this shape.
	notReady := vacNode("node-1", corev1.ConditionFalse)
	if newCleaner().stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": notReady},
		map[string]podListProbe{}, map[string]bool{"va-x": true}, now) {
		t.Fatal("unfenced not-ready node must stay closed")
	}
	// Fenced but Ready — the taint is stale and the attacher is
	// live; stripping could detach a mounted volume.
	fencedAlive := vacNode("node-1", corev1.ConditionTrue, outOfService)
	if newCleaner().stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedAlive},
		map[string]podListProbe{}, nil, now) {
		t.Fatal("fenced-but-Ready node must stay closed")
	}
	// Fenced + not-Ready inside the 15m window — the node
	// controller's own force-detach may still be in flight.
	c = newCleaner()
	c.nodeNotReadySince.Observe("node-1", now.Add(-5*time.Minute))
	if c.stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedNode},
		map[string]podListProbe{}, nil, now) {
		t.Fatal("fenced node inside the not-Ready window must stay closed")
	}
	// Past the window but a live workload pod remains — the mount
	// may still be real.
	c = newCleaner()
	c.nodeNotReadySince.Observe("node-1", now.Add(-vaOutOfServiceDownFor-time.Minute))
	livePods := map[string]podListProbe{"node-1": {pods: []corev1.Pod{
		*vacPVCUser("app", "web-0", "node-1", "claim-1")}}}
	if c.stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedNode}, livePods, nil, now) {
		t.Fatal("fenced node with a live pod must stay closed")
	}
	// Past the window, zero live pods — the wedged-detach shape.
	c = newCleaner()
	c.nodeNotReadySince.Observe("node-1", now.Add(-vaOutOfServiceDownFor-time.Minute))
	livePods = map[string]podListProbe{"node-1": {pods: []corev1.Pod{
		*vacPod("app", "web-0", "node-1", corev1.PodSucceeded), // terminal
		*vacPod("app", "ds-0", "node-1", corev1.PodRunning),    // DaemonSet-owned below
	}}}
	livePods["node-1"].pods[1].OwnerReferences = []metav1.OwnerReference{{Kind: "DaemonSet"}}
	if !c.stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedNode}, livePods, nil, now) {
		t.Fatal("fenced node past window with no live pods must open")
	}
	// Pod-list failure fails closed — and meters exactly once even
	// when the same probe is re-read.
	c = newCleaner()
	c.nodeNotReadySince.Observe("node-1", now.Add(-vaOutOfServiceDownFor-time.Minute))
	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	broken := map[string]podListProbe{"node-1": {
		err: errors.New("apiserver down")}}
	if c.stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedNode}, broken, nil, now) {
		t.Fatal("pod-list failure must fail closed")
	}
	if c.stuckTerminatingNodeDead(ctx, va,
		map[string]*corev1.Node{"node-1": fencedNode}, broken, nil, now) {
		t.Fatal("memoized pod-list failure must stay closed")
	}
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("pod-list failure metered %v times, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// podsUsingVolume — the mounted-claim census branches
// ---------------------------------------------------------------------------

// podsUsingVolume counts non-terminal pods on the node whose volumes
// resolve to pvName — through a bound PVC, a generic ephemeral
// volume's generated claim, or nothing. Terminal pods and pods on
// other nodes never count; a claim lookup failure fails closed.
func TestPodsUsingVolumeCountsMounts(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacClaim("app", "claim-data", "pv-target"),
		vacClaim("app", "batch-0-scratch", "pv-target"), // ephemeral claim shape
		vacClaim("app", "claim-other", "pv-other"))
	c := newVACleaner(cs, func() time.Time { return now })
	log := logf.FromContext(ctx)
	nodePods := map[string]podListProbe{"node-1": {pods: []corev1.Pod{
		// PVC mount on the target PV — counts.
		*vacPVCUser("app", "web-0", "node-1", "claim-data"),
		// Generic ephemeral volume — its claim is <pod>-<volume>.
		func() corev1.Pod {
			p := vacPod("app", "batch-0", "node-1", corev1.PodRunning)
			p.Spec.Volumes = []corev1.Volume{{
				Name:         "scratch",
				VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}}}
			return *p
		}(),
		// Terminal pod still holding the claim — nobody writes.
		func() corev1.Pod {
			p := vacPVCUser("app", "old-0", "node-1", "claim-data")
			p.Status.Phase = corev1.PodSucceeded
			return *p
		}(),
		// Same claim on ANOTHER node — fake clientsets ignore the
		// field selector, so the in-code node filter must skip it.
		*vacPVCUser("app", "web-9", "node-2", "claim-data"),
		// A claim bound to a different PV — not this volume.
		*vacPVCUser("app", "web-1", "node-1", "claim-other"),
	}}}

	using, err := c.podsUsingVolume(ctx, nodePods, map[string]pvcProbe{},
		"node-1", "pv-target", log)
	if err != nil {
		t.Fatalf("podsUsingVolume: %v", err)
	}
	if using != 2 {
		t.Fatalf("podsUsingVolume=%d, want 2 (pvc + ephemeral mounts)", using)
	}

	// A broken claim lookup fails the whole count closed.
	cs.PrependReactor("get", "persistentvolumeclaims",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.(ktesting.GetAction).GetName() == "claim-broken" {
				return true, nil, errors.New("api down")
			}
			return false, nil, nil
		})
	brokenPods := map[string]podListProbe{"node-1": {pods: []corev1.Pod{
		*vacPVCUser("app", "web-2", "node-1", "claim-broken")}}}
	if _, err := c.podsUsingVolume(ctx, brokenPods, map[string]pvcProbe{},
		"node-1", "pv-target", log); err == nil {
		t.Fatal("claim lookup failure must fail closed")
	}
	// A pod-list failure propagates as the probe's cached error.
	listErr := map[string]podListProbe{"node-1": {err: errors.New("list down")}}
	if _, err := c.podsUsingVolume(ctx, listErr, map[string]pvcProbe{},
		"node-1", "pv-target", log); err == nil {
		t.Fatal("pod-list failure must propagate")
	}
}

// ---------------------------------------------------------------------------
// volumeOnNode — the remaining fail-closed branches
// ---------------------------------------------------------------------------

// A CSI PV's unique name matches VolumesAttached (not just
// VolumesInUse); a missing PV object reads provably-absent; a PV
// lookup error fails closed and meters exactly once through the
// memoized probe.
func TestVolumeOnNodeAttachedAndLookupFailure(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(vacPV("pv-csi", "csi.driver", "vol-1"))
	c := newVACleaner(cs, func() time.Time { return now })
	log := logf.FromContext(ctx)
	node := vacNode("node-1", corev1.ConditionTrue)
	node.Status.VolumesAttached = []corev1.AttachedVolume{
		{Name: corev1.UniqueVolumeName("kubernetes.io/csi/csi.driver^vol-1")}}

	inUse, verifiable := c.volumeOnNode(ctx, map[string]pvProbe{}, node,
		"pv-csi", log)
	if !inUse || !verifiable {
		t.Fatalf("CSI PV in VolumesAttached = (%v,%v), want (true,true)", inUse, verifiable)
	}

	// PV object gone — provably unattached, still verifiable.
	inUse, verifiable = c.volumeOnNode(ctx, map[string]pvProbe{}, node,
		"pv-gone", log)
	if inUse || !verifiable {
		t.Fatalf("missing PV = (%v,%v), want (false,true)", inUse, verifiable)
	}

	// PV lookup error — unresolvable, metered once per cycle.
	cs.PrependReactor("get", "persistentvolumes",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.(ktesting.GetAction).GetName() == "pv-broken" {
				return true, nil, errors.New("api down")
			}
			return false, nil, nil
		})
	before := testutil.QueueErrorCount(t, "volumeattachment-cleaner")
	cache := map[string]pvProbe{}
	inUse, verifiable = c.volumeOnNode(ctx, cache, node, "pv-broken", log)
	if inUse || verifiable {
		t.Fatalf("PV lookup failure = (%v,%v), want (false,false)", inUse, verifiable)
	}
	c.volumeOnNode(ctx, cache, node, "pv-broken", log) // memoized re-read
	if got := testutil.QueueErrorCount(t, "volumeattachment-cleaner") - before; got != 1 {
		t.Fatalf("pv lookup failure metered %v times, want 1", got)
	}
}

// Package-wide test context shared by this package's _test files.
var ctx = context.Background()
