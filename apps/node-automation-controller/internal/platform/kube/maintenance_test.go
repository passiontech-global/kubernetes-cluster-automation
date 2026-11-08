package kube

import (
	"errors"
	"slices"
	"strings"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

// maintenanceDynFake returns a dynamic fake that knows the PlanList
// kind (and every other CRD the modules list) via the shared
// platform/testhelp table — the leaf-level home for the fake
// testutil cannot host (testutil imports internal/shared).
func maintenanceDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testhelp.NewDynamicClient(objs...)
}

// maintenancePlan builds a Plan CR in `state` — "" renders no status
// at all (a brand-new Plan before the controller writes one).
func maintenancePlan(name, state string) *unstructured.Unstructured {
	u := testhelp.Unstructured(
		AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", name, nil)
	if state != "" {
		u.Object["status"] = map[string]any{"state": state}
	}
	return u
}

// maintenanceKured builds the kured DaemonSet carrying `annos`.
func maintenanceKured(annos map[string]string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: kuredDaemonSetNS, Name: kuredDaemonSetName,
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
func TestNodeCordonEvidenceFreshOnly(t *testing.T) {
	fresh := maintenanceCordoned("w1", 10*time.Minute)
	stale := maintenanceCordoned("w2", 2*time.Hour)
	cs := fake.NewSimpleClientset(fresh, stale)
	ev, err := nodeCordonEvidence(ctx, cs)
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
	if _, err := nodeCordonEvidence(ctx, cs); err == nil {
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

// Signal (d): live medik8s remediation objects hold the mutex — a
// SelfNodeRemediation/FenceAgentsRemediation exists only while its
// fencing is in flight and a non-Succeeded NodeMaintenance is a live
// NMO cordon+drain. Succeeded NodeMaintenance records and absent
// CRDs are no evidence; a nil dyn stays unverifiable.
func TestMaintenanceActiveMedik8sRemediation(t *testing.T) {
	remObj := func(gvr schema.GroupVersionResource, kind, ns, name, phase string) *unstructured.Unstructured {
		u := testhelp.Unstructured(
			gvr.GroupVersion().WithKind(kind), ns, name, nil)
		if phase != "" {
			u.Object["status"] = map[string]any{"phase": phase}
		}
		return u
	}

	if _, err := Medik8sRemediationEvidence(ctx, nil); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	// No remediation objects — no signal, and MaintenanceActive
	// stays clear through the whole signal chain.
	cs := fake.NewSimpleClientset()
	if held, why, err := MaintenanceActive(ctx, cs, maintenanceDynFake()); err != nil || held {
		t.Fatalf("empty cluster: held=%v why=%q err=%v", held, why, err)
	}
	for _, tc := range []struct {
		name string
		objs []runtime.Object
		held bool
	}{
		{"self-node-remediation", []runtime.Object{remObj(
			GVRSelfNodeRemediation, "SelfNodeRemediation", "medik8s", "w1-snr", "")}, true},
		{"fence-agents-remediation", []runtime.Object{remObj(
			GVRFenceAgentsRemediation, "FenceAgentsRemediation", "medik8s", "w1-far", "")}, true},
		{"node-maintenance running", []runtime.Object{remObj(
			GVRNodeMaintenance, "NodeMaintenance", "", "w1", "Running")}, true},
		{"node-maintenance succeeded", []runtime.Object{remObj(
			GVRNodeMaintenance, "NodeMaintenance", "", "w1", "Succeeded")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			held, why, err := MaintenanceActive(ctx, cs,
				maintenanceDynFake(tc.objs...))
			if err != nil {
				t.Fatal(err)
			}
			if held != tc.held {
				t.Fatalf("held=%v (why %q), want %v", held, why, tc.held)
			}
			if tc.held && !strings.Contains(why, "medik8s remediation") {
				t.Fatalf("why=%q, want medik8s remediation evidence", why)
			}
		})
	}
}

// W12 P0-1 — a node cordoned BY node-hang-precordon (the defensive
// quarantine, stamped AnnoPreCordonedBy) is not maintenance: its
// fresh unschedulable taint must not hold the mutex, or every
// heal.AllowedV-gated remediation freezes for 45m exactly while the
// cluster is sick.
func TestMaintenanceActiveIgnoresPreCordoned(t *testing.T) {
	n := maintenanceCordoned("w1", time.Minute)
	n.Annotations = map[string]string{
		AnnoPreCordonedBy: "node-hang-precordon"}
	cs := fake.NewSimpleClientset(n)
	held, why, err := MaintenanceActive(ctx, cs, maintenanceDynFake())
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatalf("pre-cordoned node held the mutex: %q", why)
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

// A held signal's evidence is the verdict's `why` — the first
// active signal in canonical order answers (the cordon beats a
// held kured lock and a live Plan here).
func TestMaintenanceActiveWhyIsFirstSignalEvidence(t *testing.T) {
	cs := fake.NewSimpleClientset(
		maintenanceCordoned("w1", time.Minute),
		maintenanceKured(map[string]string{KuredLockAnno: "w2"}))
	dyn := maintenanceDynFake(maintenancePlan("up", "InProgress"))
	held, why, err := MaintenanceActive(ctx, cs, dyn)
	if err != nil {
		t.Fatal(err)
	}
	if !held || why != "node w1 actively cordoned" {
		t.Fatalf("held=%v why=%q, want the cordon evidence", held, why)
	}
}
