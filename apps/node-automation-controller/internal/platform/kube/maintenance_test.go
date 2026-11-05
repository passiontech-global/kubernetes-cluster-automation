package kube

import (
	"errors"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// maintenanceDynFake returns a dynamic fake that knows the PlanList
// kind — shared cannot reach testutil.NewDynamicClient (testutil
// imports shared), so the list-kind map is spelled out here like the
// module test files do.
func maintenanceDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			AutopilotPlanGVR: "PlanList",
		},
		objs...)
}

// maintenancePlan builds a Plan CR in `state` — "" renders no status
// at all (a brand-new Plan before the controller writes one).
func maintenancePlan(name, state string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autopilot.k0sproject.io/v1beta2",
		"kind":       "Plan",
		"metadata":   map[string]any{"name": name},
	}}
	if state != "" {
		u.Object["status"] = map[string]any{"state": state}
	}
	return u
}

// maintenanceKured builds the kured DaemonSet carrying `annos`.
func maintenanceKured(annos map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: KuredDaemonSetNS, Name: KuredDaemonSetName,
		Annotations: annos}}
}

// maintenanceCordoned builds a node cordoned `ago` — a negative ago
// yields a timestamp-less cordon (unverifiable → fail closed).
func maintenanceCordoned(name string, ago time.Duration) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: true},
	}
	if ago >= 0 {
		t := metav1.NewTime(time.Now().Add(-ago))
		n.Spec.Taints = []corev1.Taint{
			{Key: UnschedulableTaintKey, TimeAdded: &t}}
	}
	return n
}

// Signal (a): only an ACTIVE cordon is evidence — a node cordoned
// past the 45m window is deliberate static state and yields none.
func TestNodeCordonEvidence(t *testing.T) {
	fresh := maintenanceCordoned("w1", 10*time.Minute)
	stale := maintenanceCordoned("w2", 2*time.Hour)
	cs := fake.NewSimpleClientset(fresh, stale)
	ev, err := NodeCordonEvidence(ctx, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ev, []string{"node w1 actively cordoned"}) {
		t.Fatalf("evidence = %v, want only the fresh cordon", ev)
	}
}

// A node LIST failure is an error — never a silent clear.
func TestNodeCordonEvidenceListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	if _, err := NodeCordonEvidence(ctx, cs); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// Signal (b): the held lock is evidence; an unlocked or absent kured
// DaemonSet is none.
func TestKuredLockEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		objs []runtime.Object
		want []string
	}{
		{"absent daemonset", nil, nil},
		{"no lock annotation", []runtime.Object{maintenanceKured(nil)}, nil},
		{"lock held", []runtime.Object{maintenanceKured(
			map[string]string{KuredLockAnno: "w1"})},
			[]string{"kured lock held by w1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			ev, err := KuredLockEvidence(ctx, cs)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ev, tc.want) {
				t.Fatalf("evidence = %v, want %v", ev, tc.want)
			}
		})
	}
}

// Signal (c): a nil dyn is a wiring bug (error), terminal plans are
// not evidence, and a Plan outside {Schedulable, Completed} —
// including one with no status.state at all — is.
func TestAutopilotPlanEvidence(t *testing.T) {
	if _, err := AutopilotPlanEvidence(ctx, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	for _, tc := range []struct {
		name  string
		plans []runtime.Object
		want  []string
	}{
		{"no plans", nil, nil},
		{"terminal plans", []runtime.Object{
			maintenancePlan("a", "Schedulable"),
			maintenancePlan("b", "Completed")}, nil},
		{"active plan", []runtime.Object{
			maintenancePlan("up", "InProgress")},
			[]string{"autopilot plan up state=InProgress"}},
		// A status-less plan is not provably terminal — fail closed.
		{"stateless plan", []runtime.Object{
			maintenancePlan("new", "")},
			[]string{"autopilot plan new state="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := AutopilotPlanEvidence(ctx,
				maintenanceDynFake(tc.plans...))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ev, tc.want) {
				t.Fatalf("evidence = %v, want %v", ev, tc.want)
			}
		})
	}
}

// MaintenanceActive keeps the historical short-circuit: the FIRST
// held signal answers the verdict and the later checks never run —
// proven here by a cordoned node masking a nil dyn (which would
// error if the autopilot check were reached).
func TestMaintenanceActiveShortCircuitsOnCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(maintenanceCordoned("w1", time.Minute))
	held, why, err := MaintenanceActive(ctx, cs, nil)
	if err != nil {
		t.Fatalf("cordoned node must answer before the nil-dyn check: %v", err)
	}
	if !held || why != "node w1 actively cordoned" {
		t.Fatalf("held=%v why=%q, want the cordon evidence", held, why)
	}
}

// A nil dyn still fails closed when reached — the mutex never reads
// "cannot verify" as "clear".
func TestMaintenanceActiveNilDynFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, _, err := MaintenanceActive(ctx, cs, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
}

// MaintenanceEvidence reports EVERY active signal at once — the
// storm-gate-style verdict shape — where MaintenanceActive reports
// only the first.
func TestMaintenanceEvidenceCollectsAllSignals(t *testing.T) {
	cs := fake.NewSimpleClientset(
		maintenanceCordoned("w1", time.Minute),
		maintenanceKured(map[string]string{KuredLockAnno: "w2"}))
	dyn := maintenanceDynFake(maintenancePlan("up", "InProgress"))
	ev, err := MaintenanceEvidence(ctx, cs, dyn)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"node w1 actively cordoned",
		"kured lock held by w2",
		"autopilot plan up state=InProgress",
	}
	if !slices.Equal(ev, want) {
		t.Fatalf("evidence = %v, want %v", ev, want)
	}
}
