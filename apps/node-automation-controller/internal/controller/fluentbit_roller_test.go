package controller

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
	s, err := cs.CoreV1().Secrets(fluentNS).Get(ctx, pipelineName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	return s
}

func getFluentBitDS(t *testing.T, cs *fake.Clientset) *appsv1.DaemonSet {
	t.Helper()
	ds, err := cs.AppsV1().DaemonSets(fluentNS).Get(ctx, "fluent-bit", metav1.GetOptions{})
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

// FLUENTBIT_ROLLER_ENABLED=false: never touches anything, even with
// obvious drift on the secret.
func TestFluentBitRollerDisabled(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pipelineSecret(map[string]string{"fluent.io/config-hash": "h1"}),
		node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := &fluentBitRoller{cs: cs, enabled: false}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
		t.Fatalf("disabled roller restarted the DS: %q", got)
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "" {
		t.Fatalf("disabled roller wrote rolled-config-hash: %q", got)
	}
}

// No pipeline secret on this cluster — NotFound is a clean no-op.
func TestFluentBitRollerSecretAbsent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	r := &fluentBitRoller{cs: cs, enabled: true}
	res, err := r.Reconcile(ctx, reconcile.Request{})
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
		node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := &fluentBitRoller{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
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
				node("n1", corev1.ConditionTrue, nil),
				node("n2", corev1.ConditionTrue, nil),
				fluentBitDS(2, 2, 3, 3))
			r := &fluentBitRoller{cs: cs, enabled: true}
			res, err := r.Reconcile(ctx, reconcile.Request{})
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
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionFalse, nil),
		fluentBitDS(2, 2, 3, 3))
	r := &fluentBitRoller{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got != "" {
		t.Fatal("roller restarted the DS during a node outage")
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
				node("n1", corev1.ConditionTrue, nil),
				ds)
			r := &fluentBitRoller{cs: cs, enabled: true}
			if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
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
// secret's resourceVersion is the fallback drift hash (bash parity),
// and it is what gets recorded as rolled.
func TestFluentBitRollerResourceVersionFallback(t *testing.T) {
	sec := pipelineSecret(nil)
	sec.ResourceVersion = "777"
	cs := fake.NewSimpleClientset(
		sec,
		node("n1", corev1.ConditionTrue, nil),
		fluentBitDS(2, 2, 3, 3))
	r := &fluentBitRoller{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := dsRestartedAt(getFluentBitDS(t, cs)); got == "" {
		t.Fatal("DS not rolled on the resourceVersion fallback")
	}
	if got := rolledHash(getPipelineSecret(t, cs)); got != "777" {
		t.Fatalf("rolled-config-hash = %q, want the secret resourceVersion 777", got)
	}
}
