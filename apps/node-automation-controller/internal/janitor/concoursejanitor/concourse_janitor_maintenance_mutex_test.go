package concoursejanitor

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// ---------------------------------------------------------------------------
// Module tests
// ---------------------------------------------------------------------------

// 2.7 maintenance mutex — any positive signal defers the whole wipe
// cycle before ATC login: no land, no stats, no delete. Signals
// tested: cordoned node, kured lock annotation, active autopilot plan.
func TestConcourseJanitorMaintenanceMutexDefers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		objs  []runtime.Object
		plans []runtime.Object
	}{
		{"cordoned node", []runtime.Object{func() *corev1.Node {
			n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w1"}}
			n.Spec.Unschedulable = true
			return n
		}()}, nil},
		{"kured lock", []runtime.Object{&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kured",
			Annotations: map[string]string{nodecond.KuredLockAnno: "w1"}}}}, nil},
		{"active plan", nil,
			[]runtime.Object{cjAutopilotPlan("autopilot", "InProgress")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			objs := append([]runtime.Object{
				cjWorkerSTS(1),
				cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
				cjLocalUsers(),
			}, tc.objs...)
			cs := fake.NewSimpleClientset(objs...)
			j := cjTestJanitor(cs,
				&cjFakeStats{events: &events, calls: map[string]int{},
					fn: func(string, int) (int64, int64, int64, error) {
						return 160 * gib, 200 * gib, 10 * gib, nil // would wipe
					}},
				&cjFakeATC{events: &events, states: map[string]string{}})
			j.dyn = cjPlanDynFake(tc.plans...)
			if err := j.run(ctx); err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatalf("wipe cycle ran during maintenance: events %v", events)
			}
			if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
				t.Fatalf("pod replaced during maintenance (uid %s)", got)
			}
		})
	}
}

// A nil dynamic client makes the autopilot mutex check unverifiable —
// the run errors like any other check failure: "unknown" must mean
// "no", never a silent "no signal".
func TestConcourseJanitorNilDynFailsClosed(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjReadySibling(),
		cjLocalUsers())
	j := cjTestJanitor(cs,
		&cjFakeStats{events: &events, calls: map[string]int{},
			fn: func(string, int) (int64, int64, int64, error) {
				return 160 * gib, 200 * gib, 10 * gib, nil // would wipe
			}},
		&cjFakeATC{events: &events, states: map[string]string{}})
	j.dyn = nil // wiring bug — must not read as "no maintenance"
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	if len(events) != 0 {
		t.Fatalf("wipe cycle ran with an unverifiable mutex check: %v", events)
	}
}

// The maintenance mutex is re-checked before EACH worker, not only
// once per run: a run replacing several workers takes up to hours
// (drain + waitReady per pod), so a cordon/drain, reboot lock or
// upgrade that starts mid-run must stop the remaining wipes. Here the
// first worker's stats read cordons a node mid-run — the second
// worker is deferred without its own stats read or delete.
func TestConcourseJanitorMaintenanceRecheckedPerWorker(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(2),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjWorkerPod("concourse-worker-1", "uid-1", "node-b", true, nil),
		cjLocalUsers(),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w1"}})
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			// A drain starts while the first worker is in flight.
			n, err := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
			if err != nil {
				return 0, 0, 0, err
			}
			n.Spec.Unschedulable = true // fail-closed cordon evidence
			if _, err := cs.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{}); err != nil {
				return 0, 0, 0, err
			}
			return 160 * gib, 200 * gib, 10 * gib, nil // would wipe worker-1
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	// worker-1 was replaced before the cordon; worker-0 is untouched.
	if got := cjPod(t, cs, "concourse-worker-1").UID; got != "uid-new-concourse-worker-1" {
		t.Fatalf("worker-1 not replaced before the cordon: uid %s", got)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("worker-0 replaced although maintenance went active mid-run (uid %s)", got)
	}
	for _, e := range events {
		if e == "stats:node-a" || e == "delete:concourse-worker-0" {
			t.Fatalf("worker-0 processed after maintenance went active: %v", events)
		}
	}
}
