package volumeattachmentcleaner

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
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

// vacDSPod builds a DaemonSet-owned pod on node; claim names a PVC
// the pod mounts (empty = no claim-backed volume). claimKind switches
// the claim shape between a PVC claim and a generic ephemeral volume.
func vacDSPod(ns, name, node, claim string, ephemeral bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "DaemonSet",
				Name: "agent", Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if claim != "" {
		vol := corev1.Volume{Name: "data"}
		if ephemeral {
			vol.VolumeSource = corev1.VolumeSource{
				Ephemeral: &corev1.EphemeralVolumeSource{}}
		} else {
			vol.VolumeSource = corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claim,
				}}
		}
		p.Spec.Volumes = []corev1.Volume{vol}
	}
	return p
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
	Key:    kube.TaintNodeOutOfService,
	Value:  "nodeshutdown",
	Effect: corev1.TaintEffectNoExecute,
}

// ---------------------------------------------------------------------------
// Ready-node unused-volume branch fixtures
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
