package fluentbitroller

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// fluent-bit-config-roller
// ---------------------------------------------------------------------------

const (
	fluentNS     = "fluent-system"
	pipelineName = "passiontech-pipeline"
)

func pipelineSecret(annos map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: pipelineName, Namespace: fluentNS, Annotations: annos,
		},
	}
}

// fluentBitDS builds a DaemonSet. The roller's settled check is the
// bash one: observed == generation AND updated == desired — NumberReady
// is deliberately NOT consulted.
func fluentBitDS(generation, observed int64, desired, updated int32) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fluent-bit", Namespace: fluentNS, Generation: generation,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     observed,
			DesiredNumberScheduled: desired,
			UpdatedNumberScheduled: updated,
		},
	}
}

func getPipelineSecret(t *testing.T, cs *fake.Clientset) *corev1.Secret {
	t.Helper()
	s, err := cs.CoreV1().Secrets(fluentNS).Get(context.Background(), pipelineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	return s
}

func getFluentBitDS(t *testing.T, cs *fake.Clientset) *appsv1.DaemonSet {
	t.Helper()
	ds, err := cs.AppsV1().DaemonSets(fluentNS).Get(context.Background(), "fluent-bit", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get daemonset: %v", err)
	}
	return ds
}

// dsRestartedAt is the rollout-restart stamp the roller writes on the
// DS pod template (kubectl rollout restart equivalent).
func dsRestartedAt(ds *appsv1.DaemonSet) string {
	return ds.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]
}

func rolledHash(s *corev1.Secret) string {
	return s.Annotations["passiontech.dev/rolled-config-hash"]
}

// A disabled module (Deps.Disabled stamped by setupModules for
// FLUENTBIT_ROLLER_ENABLED=false) means Setup never registers the
// reconciler (see TestSetupDisabled) — there is no in-Reconcile
// disabled path to test.

// No pipeline secret on this cluster — NotFound is a clean no-op.
func TestFluentBitRollerSecretAbsent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := newRoller(cs)
	res, err := r.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}
}

// config-hash already rolled — no DS patch, restartedAt stays absent.
func TestFluentBitRollerNoDrift(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pipelineSecret(map[string]string{
			"fluent.io/config-hash":              "h1",
			"passiontech.dev/rolled-config-hash": "h1",
		}),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
		t.Fatalf("roller restarted the DS with no drift: %q", got)
	}
}

// Drifted config + all nodes Ready + settled DS => rollout restart:
// restartedAt lands on the pod template and rolled-config-hash records
// the hash that was rolled.
func TestFluentBitRollerRollsOnDrift(t *testing.T) {
	for name, rolled := range map[string]string{
		"rolled annotation absent": "",
		"rolled annotation stale":  "h0",
	} {
		t.Run(name, func(t *testing.T) {
			annos := map[string]string{"fluent.io/config-hash": "h1"}
			if rolled != "" {
				annos["passiontech.dev/rolled-config-hash"] = rolled
			}
			cs := fake.NewSimpleClientset(
				pipelineSecret(annos),
				testutil.Node("n1", corev1.ConditionTrue, nil),
				testutil.Node("n2", corev1.ConditionTrue, nil),
				fluentBitDS(2, 2, 3, 3))
			r := newRoller(cs)
			res, err := r.Reconcile(context.Background(), reconcile.Request{})
			if err != nil {
				t.Fatal(err)
			}
			if res.RequeueAfter != 30*time.Minute {
				t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
			}

			ts := dsRestartedAt(getFluentBitDS(t, cs))
			if ts == "" {
				t.Fatal("restartedAt annotation not set on the DS pod template")
			}
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				t.Fatalf("restartedAt %q is not RFC3339: %v", ts, err)
			}

			sec := getPipelineSecret(t, cs)
			if got := rolledHash(sec); got != "h1" {
				t.Fatalf("rolled-config-hash = %q, want h1", got)
			}
			if got := sec.Annotations["fluent.io/config-hash"]; got != "h1" {
				t.Fatalf("config-hash clobbered: %q", got)
			}
		})
	}
}

// Storm gate: any NotReady node suppresses the roll entirely — no
// restartedAt, rolled-config-hash untouched (so the drift is retried).
func TestFluentBitRollerSkipsOnNotReadyNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pipelineSecret(map[string]string{"fluent.io/config-hash": "h1"}),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		testutil.Node("n2", corev1.ConditionFalse, nil),
		fluentBitDS(2, 2, 3, 3))
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
		t.Fatal("roller restarted the DS during a node outage")
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
		t.Fatal("rolled-config-hash written although the roll was skipped")
	}
}

// cordonedRollerNode builds a node with a timestamp-less unschedulable
// taint — the fail-closed shape: the cordon age is unverifiable, so
// the maintenance mutex MUST read as held (same fixture the
// cert-drift-auditor tests use).
func cordonedRollerNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key: kube.UnschedulableTaintKey,
			}},
		},
	}
}

// The DS rollout restart is a LIVE-workload mutation: with the
// maintenance mutex reading HELD (all nodes Ready — the NotReady
// storm pre-gate above does not cover it), the roll must defer — no
// restartedAt patch, rolled-config-hash untouched so the drift
// retries once maintenance lifts.
func TestFluentBitRollerSkipsDuringMaintenance(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pipelineSecret(map[string]string{"fluent.io/config-hash": "h1"}),
		cordonedRollerNode("n1"),
		fluentBitDS(2, 2, 3, 3))
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
		t.Fatalf("roller restarted the DS while maintenance was active: %q", got)
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
		t.Fatal("rolled-config-hash written although the roll was skipped")
	}
}

// A previous rollout still in flight suppresses a new restart.
func TestFluentBitRollerSkipsWhileDSUnsettled(t *testing.T) {
	for name, ds := range map[string]*appsv1.DaemonSet{
		"observed generation behind": fluentBitDS(3, 2, 3, 3),
		"updated replicas behind":    fluentBitDS(2, 2, 3, 1),
	} {
		t.Run(name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(
				pipelineSecret(map[string]string{"fluent.io/config-hash": "h1"}),
				testutil.Node("n1", corev1.ConditionTrue, nil),
				ds)
			r := newRoller(cs)
			if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
				t.Fatal(err)
			}
			if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
				t.Fatal("roller restarted the DS mid-rollout")
			}
			if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
				t.Fatal("rolled-config-hash written although the roll was skipped")
			}
		})
	}
}

// Older fluent-operators never write fluent.io/config-hash — the
// drift hash falls back to a content hash of the secret's data. The
// resourceVersion must NOT be used: stamping rolled-config-hash bumps
// the RV itself, so RV-based drift would never settle and the DS
// would restart on every requeue.
func TestFluentBitRollerResourceVersionFallback(t *testing.T) {
	sec := pipelineSecret(nil)
	sec.ResourceVersion = "777"
	sec.Data = map[string][]byte{"fluent-bit.conf": []byte("[INPUT]\n  Name tail\n")}
	cs := fake.NewSimpleClientset(
		sec,
		testutil.Node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got == "" {
		t.Fatal("DS not rolled on the content-hash fallback")
	}
	got := rolledHash(getPipelineSecret(t, cs))
	if got == "" || got == "777" {
		t.Fatalf("rolled-config-hash = %q, want the data content hash (not the resourceVersion)", got)
	}
	if got != secretDataHash(sec) {
		t.Fatalf("rolled-config-hash = %q, want data hash %q", got, secretDataHash(sec))
	}
}

// The content-hash fallback must be stable across the stamp write:
// a second reconcile on the fallback path sees hash == rolled and
// does NOT restart the DS again (the old resourceVersion fallback
// looped forever because the stamp PATCH moved the RV).
func TestFluentBitRollerFallbackNoReroll(t *testing.T) {
	sec := pipelineSecret(nil)
	sec.Data = map[string][]byte{"fluent-bit.conf": []byte("config v1")}
	cs := fake.NewSimpleClientset(
		sec,
		testutil.Node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got == "" {
		t.Fatal("first reconcile did not roll on drift")
	}
	patches := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "daemonsets" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("daemonset patch count = %d, want 1", patches)
	}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	patches = 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "daemonsets" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("second reconcile re-rolled the DS: daemonset patch count = %d, want 1", patches)
	}
}

// driftedFixture wires a drifted secret + healthy nodes + a settled DS —
// the state right before the restart patch.
func driftedFixture() *fake.Clientset {
	return fake.NewSimpleClientset(
		pipelineSecret(map[string]string{"fluent.io/config-hash": "h1"}),
		testutil.Node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
}

// newRoller builds the reconciler with the dynamic fake the
// maintenance mutex reads its autopilot signal through — a nil dyn
// fails closed (mutex unverifiable), so every non-mutex test needs
// the real seam.
func newRoller(cs *fake.Clientset) *fluentBitRoller {
	return &fluentBitRoller{cs: cs, dyn: testutil.NewDynWithCRDs()}
}

// A secret GET that is not NotFound is a real error — only NotFound
// is the "no pipeline on this cluster" no-op.
func TestFluentBitRollerSecretGetError(t *testing.T) {
	cs := driftedFixture()
	cs.PrependReactor("get", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("etcd wedged")
		})
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the secret get fails")
	}
}

// The storm gate reads the node list — its failure must abort the roll.
func TestFluentBitRollerNodeListError(t *testing.T) {
	cs := driftedFixture()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A DaemonSet get failure aborts before any patch.
func TestFluentBitRollerDSGetError(t *testing.T) {
	cs := driftedFixture()
	cs.PrependReactor("get", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the daemonset get fails")
	}
}

// Restart ordering: rolled-config-hash is written only AFTER the
// rollout-restart patch succeeds — a restart failure must leave the
// drift marker unset so the next reconcile retries.
func TestFluentBitRollerRestartPatchErrorKeepsDriftMarker(t *testing.T) {
	cs := driftedFixture()
	cs.PrependReactor("patch", "daemonsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the restart patch fails")
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
		t.Fatal("rolled-config-hash written although the restart failed")
	}
}

// The state patch is the last write — its failure errors the reconcile
// even though the DS already restarted (retry is safe: the patch is
// idempotent and restartedAt just moves forward).
func TestFluentBitRollerStatePatchError(t *testing.T) {
	cs := driftedFixture()
	cs.PrependReactor("patch", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("secret patch rejected")
		})
	r := newRoller(cs)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the state patch fails")
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got == "" {
		t.Fatal("restart patch did not land before the state patch")
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
		t.Fatal("rolled-config-hash written despite the failed patch")
	}
}
