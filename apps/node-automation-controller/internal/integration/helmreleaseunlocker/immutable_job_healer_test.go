// immutable_job_healer_test.go — the W8-GO1 immutable-Job heal path:
// the happy-path reap, and the NotFound race on the delete being a
// benign skip (no IncError, no cooldown stamp — cilium-identity
// janitor parity).
package helmreleaseunlocker

import (
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// immutableKust builds a Kustomization stuck Ready=False >=15m on the
// classic `Job.batch "<job>" is invalid: … field is immutable` apply
// error naming jobName.
func immutableKust(ns, name, jobName string) *unstructured.Unstructured {
	k := testutil.Unstructured(fluxKustomizationGVR.GroupVersion().WithKind("Kustomization"),
		ns, name, nil)
	k.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":               "Ready",
			"status":             "False",
			"reason":             "ApplyFailed",
			"message":            `M adapting Deployments: Job.batch "` + jobName + `" is invalid: spec.template: field is immutable`,
			"lastTransitionTime": time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339),
		}},
	}
	return k
}

// completedJob builds a Job that ran to completion — the pure-residue
// shape the healer reaps.
func completedJob(ns, name string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: batchv1.JobStatus{
			Succeeded: 1,
			Conditions: []batchv1.JobCondition{{
				Type:   batchv1.JobComplete,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// A completed immutable Job blocking a Kustomization apply is reaped,
// and both cooldown halves stamp — the in-RAM ledger immediately, the
// persisted annotation on the Kustomization.
func TestImmutableJobHealReapsCompletedJob(t *testing.T) {
	k := immutableKust("apps", "web", "web-migrate")
	dyn := newDynFake(k)
	cs := kfake.NewSimpleClientset(completedJob("apps", "web-migrate"))
	u := newUnlocker(cs, dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if jobExists(t, cs, "apps", "web-migrate") {
		t.Fatal("completed immutable Job not reaped")
	}
	if _, ok := u.immutableJob.healed.Last("apps/web"); !ok {
		t.Fatal("in-RAM heal ledger not stamped")
	}
	if got := hrAnnotation(t, dyn, fluxKustomizationGVR, "apps", "web", immutableJobHealAnno); got == "" {
		t.Fatal("persisted heal stamp missing on the Kustomization")
	}
}

// A delete losing the race to kustomize-controller's own recreate
// (NotFound) is a benign skip: no IncError and NO cooldown stamp — the
// next sweep may still need a real heal.
func TestImmutableJobHealDeleteNotFoundIsBenign(t *testing.T) {
	k := immutableKust("apps", "web", "web-migrate")
	dyn := newDynFake(k)
	cs := kfake.NewSimpleClientset(completedJob("apps", "web-migrate"))
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				batchv1.Resource("jobs"), "web-migrate")
		})
	u := newUnlocker(cs, dyn, 0, "")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a NotFound race must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got != 0 {
		t.Fatalf("NotFound immutable-Job delete counted as an error: +%v", got)
	}
	if _, ok := u.immutableJob.healed.Last("apps/web"); ok {
		t.Fatal("heal ledger stamped although the delete raced away")
	}
	if got := hrAnnotation(t, dyn, fluxKustomizationGVR, "apps", "web", immutableJobHealAnno); got != "" {
		t.Fatal("persisted heal stamp written although the delete raced away")
	}
}
