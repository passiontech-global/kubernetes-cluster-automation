// partition_evictor_pvc_test.go — the pinned-volume guard: node-pinned
// PVCs, generic-ephemeral and hostPath volumes are never evicted, and
// an unverifiable PVC view fails the eviction pass closed.
package partitionevictor

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// pinned-volume-guard — node-pinned volumes are never evicted.
// ---------------------------------------------------------------------------

// pePVC builds a PVC bound to a storage class; sc "" leaves
// spec.storageClassName unset.
func pePVC(ns, name, sc string) *corev1.PersistentVolumeClaim {
	p := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	if sc != "" {
		p.Spec.StorageClassName = &sc
	}
	return p
}

// pePodWithPVC is pePod plus a volume mounting the named PVC.
func pePodWithPVC(ns, nodeName, name, pvc string) *corev1.Pod {
	p := pePod(ns, nodeName, name)
	p.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: pvc,
			},
		},
	}}
	return p
}

// Pods on node-pinned volumes (local-path AND openebs-hostpath) are
// skipped: their PVs carry node affinity, so the replacement would
// land on the same broken node — pure churn. A pod on a cluster
// SC (or a PVC in another namespace) still evicts.
func TestPartitionEvictorSkipsNodePinnedPVC(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePVC("flux-system", "data-local", "local-path"),
		pePVC("flux-system", "data-openebs", "openebs-hostpath"),
		pePVC("flux-system", "data-csi", "longhorn"),
		pePodWithPVC("flux-system", "p1", "local-pod", "data-local"),
		pePodWithPVC("flux-system", "p1", "openebs-pod", "data-openebs"),
		pePodWithPVC("flux-system", "p1", "csi-pod", "data-csi"),
		// Same claim name in another namespace must not match — the
		// pinned set is keyed ns/name.
		pePodWithPVC("default", "p1", "foreign-pod", "data-local"),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"local-pod", "openebs-pod"} {
		if !testutil.PodExistsStrict(t, cs, "flux-system", name) {
			t.Fatalf("node-pinned pod %s evicted — replacement cannot leave the node", name)
		}
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "csi-pod") {
		t.Fatal("cluster-SC pod not evicted")
	}
	// "default" is not in the allow-list and the pod is unannotated —
	// it survives on membership grounds, not the PVC check.
	if !testutil.PodExistsStrict(t, cs, "default", "foreign-pod") {
		t.Fatal("unlisted-namespace pod evicted")
	}
}

// An annotated opt-in pod on a node-pinned volume is skipped too —
// the annotation opts into eviction, it cannot move a volume that is
// physically bound to the node.
func TestPartitionEvictorPinnedPVCBeatsAnnotation(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	p := pePodWithPVC("apps", "p1", "pinned-opted", "data-openebs")
	p.Annotations = map[string]string{partitionEvictAnno: "true"}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePVC("apps", "data-openebs", "openebs-hostpath"),
		p,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "apps", "pinned-opted") {
		t.Fatal("annotated node-pinned pod evicted — volume is bound to the node")
	}
}

// Generic-ephemeral and hostPath volumes pin a pod to its node just
// like a local-path PVC: the ephemeral PVC is provisioned on the node
// running the pod (and dies with it), and a hostPath only exists on
// this node — the replacement cannot land anywhere useful, so
// evicting is pure churn.
func TestPartitionEvictorSkipsEphemeralAndHostPathPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	ephemeral := pePod("flux-system", "p1", "eph-vol")
	ephemeral.Spec.Volumes = []corev1.Volume{{
		Name: "scratch",
		VolumeSource: corev1.VolumeSource{
			Ephemeral: &corev1.EphemeralVolumeSource{},
		},
	}}
	hostpath := pePod("flux-system", "p1", "hp-vol")
	hostpath.Spec.Volumes = []corev1.Volume{{
		Name: "host",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/data"},
		},
	}}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		ephemeral, hostpath,
		pePod("flux-system", "p1", "movable"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"eph-vol", "hp-vol"} {
		if !testutil.PodExistsStrict(t, cs, "flux-system", name) {
			t.Fatalf("volume-pinned pod %s evicted — its volumes cannot follow it", name)
		}
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "movable") {
		t.Fatal("volume-less pod not evicted — pinned-volume skip leaked")
	}
}

// A PVC list failure fails the eviction pass closed: taints still
// land (they fence scheduling) but no pod is deleted on an
// unverifiable volume view.
func TestPartitionEvictorPVCListErrorSkipsEviction(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("list", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pvc api down")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("pvc list failure must not error the run: %v", err)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted although the pinned-PVC view was unverifiable")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
}

// ---------------------------------------------------------------------------
// nodePinnedPVCs failure — the eviction pass fails closed.
// ---------------------------------------------------------------------------

// A PVC list failure skips the whole eviction pass — but the taints
// above still fence the flagged nodes and the sweep returns nil (the
// bash best-effort contract, no error to the periodic).
func TestPartitionEvictorPVCListErrorSkipsEvictionKeepsTaint(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("list", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	e := &partitionEvictor{cs: cs, queue: "partition-pod-evictor"}
	if err := e.run(ctx); err != nil {
		t.Fatalf("PVC list failure must not error the sweep: %v", err)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted despite the PVC list failing — pass must fail closed")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted — fencing must survive the eviction skip")
	}
}
