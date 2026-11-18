package watchdogs

import (
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func zoneWorkerNode(name, zone string, ready, unschedulable bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{corev1.LabelTopologyZone: zone},
		},
		Spec: corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
}

func TestTopologySpreadZoneDeadlockRelaxAndAutoRestore(t *testing.T) {
	topologyZoneDeadlockGauge.Reset()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	isCtrl := true

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
						TopologyKey:       corev1.LabelTopologyZone,
						WhenUnsatisfiable: corev1.DoNotSchedule,
						MaxSkew:           1,
					}},
				},
			},
		},
	}
	dbDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "db-proxy"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"cnpg.io/cluster": "pg-main"}},
				Spec: corev1.PodSpec{
					TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{
						TopologyKey:       corev1.LabelTopologyZone,
						WhenUnsatisfiable: corev1.DoNotSchedule,
						MaxSkew:           1,
					}},
				},
			},
		},
	}
	rsAPI := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "api-rs",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", Controller: &isCtrl}},
		},
	}
	rsDB := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "db-rs",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "db-proxy", Controller: &isCtrl}},
		},
	}
	pendingPod := func(name, rsName string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: name,
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rsName, Controller: &isCtrl}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				Conditions: []corev1.PodCondition{{
					Type:               corev1.PodScheduled,
					Status:             corev1.ConditionFalse,
					Message:            "0/4 nodes are available: 4 node(s) didn't match pod topology spread constraints.",
					LastTransitionTime: metav1.NewTime(now.Add(-15 * time.Minute)),
				}},
			},
		}
	}

	nA := zoneWorkerNode("worker-a", "az-a", true, false)
	nB := zoneWorkerNode("worker-b", "az-b", false, false) // dead zone (NotReady)!

	cs := fake.NewSimpleClientset(nA, nB, dep, dbDep, rsAPI, rsDB,
		pendingPod("api-pod", "api-rs"), pendingPod("db-pod", "db-rs"))
	p := testProber(cs)
	p.Now = func() time.Time { return now }
	chk := probetest.MustCheck[*topologySpreadZoneDeadlockCheck](t, p)

	// Sweep 1 (T=0): zone dead window starts, NOT relaxed yet (<10m).
	res1 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res1.Pass {
		t.Fatalf("expected Pass before 10m dead-zone window, got %+v", res1)
	}

	// Sweep 2 (T+10m): dead zone >=10m -> metric=1, stateless Deployment api relaxed, DB quorum db-proxy untouched!
	now = now.Add(10 * time.Minute)
	res2 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res2.Pass {
		t.Fatalf("expected failure once dead zone + pending pods >=10m")
	}
	if v := ptestutil.ToFloat64(topologyZoneDeadlockGauge.WithLabelValues("apps", "api", "az-b")); v != 1 {
		t.Fatalf("expected topology deadlock gauge=1, got %v", v)
	}
	gotAPI, _ := cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
	if gotAPI.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatalf("expected api constraint relaxed to ScheduleAnyway, got %s", gotAPI.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable)
	}
	if gotAPI.Annotations[kube.AnnoTopologyRelaxedBy] == "" {
		t.Fatalf("expected AnnoTopologyRelaxedBy stamped on Deployment api")
	}
	gotDB, _ := cs.AppsV1().Deployments("apps").Get(ctx, "db-proxy", metav1.GetOptions{})
	if gotDB.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
		t.Fatalf("DB quorum Deployment db-proxy must remain DoNotSchedule")
	}

	// Zone az-b recovers -> wait 10m -> DoNotSchedule restored and annotation removed!
	nB.Spec.Unschedulable = false
	nB.Status.Conditions[0].Status = corev1.ConditionTrue
	_, _ = cs.CoreV1().Nodes().Update(ctx, nB, metav1.UpdateOptions{})
	p.InvalidateNodes(ctx)
	p.InvalidateDeployments(ctx)
	now = now.Add(5 * time.Minute)
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // first healthy sweep starts 10m restore timer

	// Still ScheduleAnyway before 10m healthy window elapses.
	gotAPI, _ = cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
	if gotAPI.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.ScheduleAnyway {
		t.Fatalf("expected ScheduleAnyway until 10m healthy window completes")
	}

	now = now.Add(30 * time.Minute) // clear 30m patch cooldown + >=10m healthy zone window
	p.InvalidateDeployments(ctx)
	resRestore := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !resRestore.Pass {
		t.Fatalf("expected Pass after zone recovery, got %+v", resRestore)
	}
	gotAPI, _ = cs.AppsV1().Deployments("apps").Get(ctx, "api", metav1.GetOptions{})
	if gotAPI.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != corev1.DoNotSchedule {
		t.Fatalf("expected api restored to DoNotSchedule, got %s", gotAPI.Spec.Template.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable)
	}
	if _, ok := gotAPI.Annotations[kube.AnnoTopologyRelaxedBy]; ok {
		t.Fatalf("expected AnnoTopologyRelaxedBy deleted after restore")
	}
}
