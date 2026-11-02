package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var ctx = context.Background()

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func node(name string, ready corev1.ConditionStatus, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: ready,
		}}},
	}
}

func getNode(t *testing.T, cs *fake.Clientset, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// helpers.go
// ---------------------------------------------------------------------------

func TestTaintHelpers(t *testing.T) {
	n := node("n1", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(n)

	if err := taintNode(ctx, cs, "n1", "node.ops/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("taintNode: %v", err)
	}
	got := getNode(t, cs, "n1")
	if !hasTaint(got.Spec.Taints, "node.ops/test") {
		t.Fatal("taint not applied")
	}
	if len(got.Spec.Taints) != 1 {
		t.Fatalf("expected 1 taint, got %d", len(got.Spec.Taints))
	}

	// Idempotent: same key is not duplicated.
	if err := taintNode(ctx, cs, "n1", "node.ops/test", "true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("taintNode idempotent: %v", err)
	}
	if l := len(getNode(t, cs, "n1").Spec.Taints); l != 1 {
		t.Fatalf("expected still 1 taint, got %d", l)
	}

	if err := untaintNode(ctx, cs, "n1", "node.ops/test"); err != nil {
		t.Fatalf("untaintNode: %v", err)
	}
	if hasTaint(getNode(t, cs, "n1").Spec.Taints, "node.ops/test") {
		t.Fatal("taint not removed")
	}
}

func TestDropTaintsByKey(t *testing.T) {
	in := []corev1.Taint{
		{Key: "a", Effect: corev1.TaintEffectNoSchedule},
		{Key: "a", Effect: corev1.TaintEffectNoExecute},
		{Key: "b", Effect: corev1.TaintEffectNoSchedule},
	}
	out := dropTaintsByKey(in, "a")
	if len(out) != 1 || out[0].Key != "b" {
		t.Fatalf("expected only taint b, got %+v", out)
	}
}

func TestNodeConditionHelpers(t *testing.T) {
	ready := node("w", corev1.ConditionTrue, nil)
	notReady := node("w2", corev1.ConditionFalse, nil)
	cp := node("cp", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})

	if !nodeReady(ready) || nodeReady(notReady) {
		t.Fatal("nodeReady wrong")
	}
	if !isControlPlane(cp) || isControlPlane(ready) {
		t.Fatal("isControlPlane wrong")
	}
}

func TestCountNotReadyNodes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("a", corev1.ConditionTrue, nil),
		node("b", corev1.ConditionFalse, nil),
		node("c", corev1.ConditionTrue, nil))
	n, err := countNotReadyNodes(ctx, cs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 NotReady, got %d", n)
	}
}

func TestDaemonSetSettled(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	if !daemonSetSettled(ds) {
		t.Fatal("expected settled")
	}
	ds.Status.NumberReady = 3
	if daemonSetSettled(ds) {
		t.Fatal("expected not settled when a replica is not ready")
	}
}

// ---------------------------------------------------------------------------
// konnectivity-patcher
// ---------------------------------------------------------------------------

func TestKonnectivityPatcher(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent", Namespace: "kube-system", Generation: 2,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: "konnectivity-agent"},
				}},
			},
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     2,
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            3,
		},
	}
	cs := fake.NewSimpleClientset(ds)
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got, err := cs.AppsV1().DaemonSets("kube-system").
		Get(ctx, "konnectivity-agent", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Spec.PriorityClassName != "system-node-critical" {
		t.Fatalf("priorityClassName not patched: %q",
			got.Spec.Template.Spec.PriorityClassName)
	}
	c := got.Spec.Template.Spec.Containers[0]
	if c.Resources.Requests.Cpu().Cmp(resource.MustParse("25m")) != 0 ||
		c.Resources.Requests.Memory().Cmp(resource.MustParse("32Mi")) != 0 {
		t.Fatalf("requests not patched: %+v", c.Resources.Requests)
	}

	// Second pass is a no-op (already drift-free).
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
}

func TestKonnectivityPatcherSkipsRollout(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent", Namespace: "kube-system", Generation: 2,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1, // rollout in flight
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberReady:            3,
		},
	}
	cs := fake.NewSimpleClientset(ds)
	r := &konnectivityPatcher{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, _ := cs.AppsV1().DaemonSets("kube-system").
		Get(ctx, "konnectivity-agent", metav1.GetOptions{})
	if got.Spec.Template.Spec.PriorityClassName != "" {
		t.Fatal("patched during an unsettled rollout — should have skipped")
	}
}

// ---------------------------------------------------------------------------
// descheduler-storm-gate
// ---------------------------------------------------------------------------

func deschedulerDeploy(replicas int32, annos map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "descheduler", Namespace: "kube-system", Annotations: annos,
		},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas},
	}
}

func getDeschedulerReplicas(t *testing.T, cs *fake.Clientset) int32 {
	t.Helper()
	d, err := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return *d.Spec.Replicas
}

func TestStormGateScalesDownAndBack(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionFalse, nil), // storm
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 during storm, got %d", got)
	}
	d, _ := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if d.Annotations[stormGateDecisionAnno] == "" {
		t.Fatal("decision annotation not recorded")
	}

	// Node recovers -> scale back to 1.
	n2, _ := cs.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	n2.Status.Conditions[0].Status = corev1.ConditionTrue
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, n2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("expected scale back to 1 when clear, got %d", got)
	}
}

func TestStormGateHold(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, map[string]string{stormGateHoldAnno: "true"}))
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("hold must skip scaling, replicas=%d", got)
	}
}

// ---------------------------------------------------------------------------
// cilium-taint-reaper
// ---------------------------------------------------------------------------

func ciliumPod(nodeName string, phase corev1.PodPhase, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-x", Namespace: "kube-system",
			Labels: map[string]string{"k8s-app": "cilium"},
		},
		Spec:   corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{Phase: phase},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}
	}
	return p
}

func TestCiliumTaintReaper(t *testing.T) {
	stale := corev1.Taint{Key: "node.cilium.io/agent-not-ready", Effect: corev1.TaintEffectNoSchedule}

	// Disabled: never touches taints.
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil, stale))
	r := &ciliumTaintReaper{cs: cs, enabled: false}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("disabled reaper removed taint")
	}

	// Enabled + healthy agent -> taint reaped.
	cs = fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodRunning, true))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("stale taint not reaped with healthy agent")
	}

	// Enabled + agent not ready -> taint kept.
	cs = fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodPending, false))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("taint removed while agent still not ready")
	}
}

// ---------------------------------------------------------------------------
// node-labeler
// ---------------------------------------------------------------------------

func TestNodeLabeler(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "labels.txt")
	if err := os.WriteFile(cfg,
		[]byte("# comment\n\npassiontech.dev/workload=app w1 w2 gone-node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := fake.NewSimpleClientset(
		node("cp1", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/control-plane": ""}),
		node("w1", corev1.ConditionTrue, nil),
		node("w2", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/worker": ""}),
	)
	r := &nodeLabeler{cs: cs, configPath: cfg}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}

	if _, ok := getNode(t, cs, "cp1").Labels["node-role.kubernetes.io/worker"]; ok {
		t.Fatal("control-plane got a worker label")
	}
	if _, ok := getNode(t, cs, "w1").Labels["node-role.kubernetes.io/worker"]; !ok {
		t.Fatal("worker role label not asserted")
	}
	if got := getNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied, got %q", got)
	}
	if got := getNode(t, cs, "w2").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied on w2, got %q", got)
	}
	// gone-node does not exist -> warn+continue, no error.
}

// ---------------------------------------------------------------------------
// admission-webhook-guard
// ---------------------------------------------------------------------------

func TestWebhookGuardRemovesOrphan(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: "keep.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "alive", Name: "svc",
					},
				},
			},
			{
				Name: "orphan.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: "dead-ns", Name: "svc",
					},
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "alive"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "alive", Name: "svc"}},
		mwc)
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, "cfg", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Webhooks) != 1 || got.Webhooks[0].Name != "keep.example.com" {
		t.Fatalf("orphan not pruned correctly: %+v", got.Webhooks)
	}
}

func TestWebhookGuardAbortsWithoutNamespaceSnapshot(t *testing.T) {
	cs := fake.NewSimpleClientset() // no kube-system -> API flap guard
	g := &webhookGuard{cs: cs}
	if err := g.run(ctx); err == nil {
		t.Fatal("expected abort when kube-system is missing from the list")
	}
}

// ---------------------------------------------------------------------------
// partition-pod-evictor
// ---------------------------------------------------------------------------

func TestPartitionEvictor(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	partitioned := node("p1", corev1.ConditionTrue, nil)
	partitioned.Status.Conditions = append(partitioned.Status.Conditions,
		corev1.NodeCondition{
			Type:               "HostNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
	healthy := node("h1", corev1.ConditionTrue, nil)
	others := []*corev1.Node{
		node("h2", corev1.ConditionTrue, nil),
		node("h3", corev1.ConditionTrue, nil),
	}
	podOnP1 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "src-ctrl", Namespace: "flux-system"},
		Spec: corev1.PodSpec{NodeName: "p1"}}

	objs := []runtime.Object{partitioned, healthy, podOnP1}
	for _, n := range others {
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}

	if !hasTaint(getNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("partitioned node not tainted")
	}
	_, err := cs.CoreV1().Pods("flux-system").Get(ctx, "src-ctrl", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatal("flux-system pod not evicted off partitioned node")
	}

	// Recovery: condition cleared -> taint removed on next sweep.
	p1 := getNode(t, cs, "p1")
	p1.Status.Conditions[1].Status = corev1.ConditionFalse
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, p1, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("taint not removed after recovery")
	}
}

func TestPartitionEvictorAbortsOnMajorityPartition(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	var objs []runtime.Object
	for _, name := range []string{"a", "b"} {
		n := node(name, corev1.ConditionTrue, nil)
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               "ClusterNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if hasTaint(getNode(t, cs, name).Spec.Taints, "node.ops/network-partitioned") {
			t.Fatalf("node %s tainted during a majority partition — guard failed", name)
		}
	}
}

// ---------------------------------------------------------------------------
// failed-jobs-janitor
// ---------------------------------------------------------------------------

func failedJob(ns, name string, age time.Duration) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type:               batchv1.JobFailed,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
		}}},
	}
}

func TestFailedJobsJanitor(t *testing.T) {
	old := failedJob("a", "old-failed", 25*time.Hour)
	recent := failedJob("a", "recent-failed", time.Hour)
	complete := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "done"},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{
			Type:               batchv1.JobComplete,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-72 * time.Hour)),
		}}},
	}
	cs := fake.NewSimpleClientset(old, recent, complete)
	j := &failedJobsJanitor{cs: cs}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.BatchV1().Jobs("a").Get(ctx, "old-failed", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("old failed job not deleted")
	}
	for _, name := range []string{"recent-failed", "done"} {
		if _, err := cs.BatchV1().Jobs("a").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("job %s wrongly deleted: %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// converge-trigger
// ---------------------------------------------------------------------------

func convergeCronJob(name string) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: "node-ops", Name: name},
		Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": "converge"},
					Annotations: map[string]string{"a": "b"},
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyNever,
							Containers:    []corev1.Container{{Name: "c", Image: "i"}},
						},
					},
				},
			},
		},
	}
}

func TestConvergeTriggerDebounceThenCreate(t *testing.T) {
	cs := fake.NewSimpleClientset(convergeCronJob("hub-converge"))
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	// First pass only arms the debounce — no Job yet.
	res, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "node-config-vars-abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != convergeSettle {
		t.Fatalf("expected %s requeue, got %s", convergeSettle, res.RequeueAfter)
	}
	jobs, _ := cs.BatchV1().Jobs("node-ops").List(ctx, metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatal("job created before the settle window elapsed")
	}

	// Settle timer fired -> drain -> Job cloned from the CronJob.
	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "node-config-vars-abc"}}); err != nil {
		t.Fatal(err)
	}
	jobs, _ = cs.BatchV1().Jobs("node-ops").List(ctx, metav1.ListOptions{})
	if len(jobs.Items) != 1 {
		t.Fatalf("expected exactly 1 trigger job, got %d", len(jobs.Items))
	}
	j := jobs.Items[0]
	if j.Labels["app.kubernetes.io/created-by"] != "node-ops-operator" {
		t.Fatal("created-by label missing")
	}
	if j.Labels["app"] != "converge" || j.Annotations["a"] != "b" {
		t.Fatal("JobTemplate metadata not cloned")
	}
}

func TestConvergeTriggerDedupe(t *testing.T) {
	recent := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: "node-ops", Name: "hub-converge-trigger-1",
		CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Second)),
	}}
	cs := fake.NewSimpleClientset(convergeCronJob("hub-converge"), recent)
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}

	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "node-config-vars-abc"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "node-config-vars-abc"}}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := cs.BatchV1().Jobs("node-ops").List(ctx, metav1.ListOptions{})
	if len(jobs.Items) != 1 {
		t.Fatalf("dedupe failed: %d jobs", len(jobs.Items))
	}
}
