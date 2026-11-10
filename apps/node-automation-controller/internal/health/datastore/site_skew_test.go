// site_skew_test.go — coverage for the site-skew endpoint placement
// resolver: endpointZone's Zone → Node → targetRef-pod fallback chain
// and workloadReadyInZone's selector/ready/zone matching for both the
// StatefulSet and CNPG candidate shapes.
package datastore

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// endpointZone resolves the first non-empty placement field in order —
// the slice's own zone hint, then the endpoint's nodeName through the
// node census, then the targetRef pod's node. A field that is SET but
// unresolvable returns "" immediately: it does not fall through to the
// next field (a nodeName that maps to no zone is not evidence the pod
// sits elsewhere).
func TestEndpointZoneFallbackChain(t *testing.T) {
	podNode := map[string]string{"ns/pod-1": "node-a"}
	nodeZone := map[string]string{"node-a": "datahub", "node-b": "lanit"}
	cases := []struct {
		name string
		e    kube.ReadyEndpoint
		want string
	}{
		{"zone hint wins over everything",
			kube.ReadyEndpoint{Zone: "lanit", Node: "node-a", PodKey: "ns/pod-1"}, "lanit"},
		{"node name resolves through the census",
			kube.ReadyEndpoint{Node: "node-b"}, "lanit"},
		{"node name with no zone reads unresolvable — no pod fallback",
			kube.ReadyEndpoint{Node: "ghost", PodKey: "ns/pod-1"}, ""},
		{"pod targetRef resolves pod→node→zone",
			kube.ReadyEndpoint{PodKey: "ns/pod-1"}, "datahub"},
		{"pod on an unzoned node reads unresolvable",
			kube.ReadyEndpoint{PodKey: "ns/pod-2"}, ""}, // podNode has no ns/pod-2
		{"empty endpoint is unresolvable",
			kube.ReadyEndpoint{}, ""},
	}
	for _, tc := range cases {
		if got := endpointZone(tc.e, podNode, nodeZone); got != tc.want {
			t.Errorf("%s: endpointZone=%q, want %q", tc.name, got, tc.want)
		}
	}
}

// workloadReadyInZone reports whether the candidate's workload has a
// Ready, non-deleting pod in the namespace matching its selector whose
// node sits in the given zone — the "the workload still serves the
// main site" half of skew trigger A. A StatefulSet matches through
// its selector; a CNPG Cluster (sts == nil) matches on the
// cnpg.io/cluster label.
func TestWorkloadReadyInZone(t *testing.T) {
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: "pg"},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "pg"}},
		},
	}
	stsCand := masterSvc{ns: "db", svc: "pg-master", sts: sts}
	cnpgCand := masterSvc{ns: "db", svc: "pg-ro", cnpg: "pg"}
	readyPod := func(name, node string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "db", Name: name,
				Labels: map[string]string{"app": "pg"}},
			Spec: corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
			},
		}
	}
	// cnpgPod carries the cnpg.io/cluster label the CNPG candidate
	// selector matches on — plus the app=pg label so it also proves
	// the STS selector path sees it.
	cnpgPod := func(name string) corev1.Pod {
		p := readyPod(name, "node-main")
		p.Labels[cnpgClusterLabel] = "pg"
		return p
	}
	podNode := map[string]string{
		"db/pg-0": "node-main", "db/pg-1": "node-dr", "db/pg-2": "node-unknown",
		"db/pg-1-abc": "node-main", "db/pg-9-xyz": "node-main"}
	nodeZone := map[string]string{"node-main": "datahub", "node-dr": "lanit"}

	if !workloadReadyInZone(stsCand, []corev1.Pod{readyPod("pg-0", "node-main")},
		podNode, nodeZone, "datahub") {
		t.Fatal("ready pod on a datahub node not detected")
	}
	if workloadReadyInZone(stsCand, []corev1.Pod{readyPod("pg-1", "node-dr")},
		podNode, nodeZone, "datahub") {
		t.Fatal("standby-zone pod counted as main-zone service")
	}
	// A pod in the wrong namespace never counts even when its node
	// sits in the target zone.
	otherNS := readyPod("pg-9", "node-main")
	otherNS.Namespace = "other"
	if workloadReadyInZone(stsCand, []corev1.Pod{otherNS},
		podNode, nodeZone, "datahub") {
		t.Fatal("foreign-namespace pod counted")
	}
	// A Ready pod whose node is unzoned cannot prove the zone.
	unzoned := readyPod("pg-2", "node-unknown")
	if workloadReadyInZone(stsCand, []corev1.Pod{unzoned},
		podNode, nodeZone, "datahub") {
		t.Fatal("pod on an unzoned node counted as in-zone")
	}
	// CNPG candidate: the cnpg.io/cluster label is the selector — a
	// pod of the cluster Ready on a main-zone node counts.
	if !workloadReadyInZone(cnpgCand, []corev1.Pod{cnpgPod("pg-1-abc")},
		podNode, nodeZone, "datahub") {
		t.Fatal("cnpg pod on a datahub node not detected")
	}
	// A pod of a DIFFERENT cnpg cluster never counts.
	otherCluster := cnpgPod("pg-9-xyz")
	otherCluster.Labels[cnpgClusterLabel] = "other"
	if workloadReadyInZone(cnpgCand, []corev1.Pod{otherCluster},
		podNode, nodeZone, "datahub") {
		t.Fatal("foreign cnpg cluster pod counted")
	}
}
