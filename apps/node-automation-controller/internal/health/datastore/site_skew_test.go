// site_skew_test.go — coverage for the site-skew endpoint placement
// resolver: endpointZone's Zone → Node → targetRef-pod fallback chain
// and workloadReadyInZone's selector/ready/zone matching for both the
// StatefulSet and CNPG candidate shapes.
package datastore

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// A failed placement census is "can't tell": the held skew series
// must be carried forward instead of being pruned by an empty
// reconcile, and the sweep reports the census failure as Infra.
func TestSiteSkewCloseCarriesOnCensusFailure(t *testing.T) {
	const key = "db/pg-master/pg/lanit"
	lv := []string{"db", "pg-master", "pg", statefulStandbySiteZone}
	t.Cleanup(func() { statefulMasterSiteSkewGauge.DeleteLabelValues(lv...) })
	w := &siteSkewWatch{}
	w.emitted.Emit(key, lv...)
	w.emitted.Prune(func(...string) bool { return false }) // commit as last sweep's series
	s := &siteSkewSweep{
		watch:    w,
		censusOK: false,
		infraErr: errors.New("placement census failed"),
	}
	s.close()
	if s.rep.Flagged() != 1 {
		t.Fatalf("census failure must carry the held tuple, got %d", s.rep.Flagged())
	}
	if s.rep.Verdict("", ", ").Infra == nil {
		t.Fatal("census failure must surface as Infra")
	}
	if _, ok := w.emitted.Last()[key]; !ok {
		t.Fatal("held skew series was pruned on a failed census")
	}
}

// A worker under remediation/out-of-service does not keep its zone's
// multi-site gate open — otherwise a dead standby site still lets
// every standby-pinned master read as a healthy skew.
func TestSiteSkewBeginIgnoresRemediatedWorker(t *testing.T) {
	main := testutil.Node("main", corev1.ConditionTrue,
		map[string]string{corev1.LabelTopologyZone: statefulMainSiteZone})
	dr := testutil.Node("dr", corev1.ConditionTrue,
		map[string]string{corev1.LabelTopologyZone: statefulStandbySiteZone},
		corev1.Taint{
			Key: kube.TaintKubeletUnresponsive, Effect: corev1.TaintEffectNoSchedule,
		})
	p := testProber(fake.NewSimpleClientset(main, dr))
	s := (&siteSkewWatch{}).begin(
		probetest.SweepCtx(ctx, p.Deps), logr.Discard(), p.Deps)
	if !s.censusOK {
		t.Fatal("census should succeed with the fake clientset")
	}
	if s.multiZone {
		t.Fatal("remediated standby worker must not satisfy the multi-zone gate")
	}
}

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
