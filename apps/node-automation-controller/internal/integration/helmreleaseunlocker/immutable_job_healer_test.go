// immutable_job_healer_test.go — the immutable-job-heal immutable-Job heal path:
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
	"k8s.io/utils/ptr"

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

func TestImmutableJobHealSkipsActiveParallelJobs(t *testing.T) {
	now := metav1.NewTime(time.Now())
	cases := []struct {
		name       string
		job        *batchv1.Job
		wantDelete bool
	}{
		{
			name: "multi-completion parallel job with Succeeded=1 and Active=2 is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Spec:       batchv1.JobSpec{Completions: ptr.To(int32(3)), Parallelism: ptr.To(int32(2))},
				Status:     batchv1.JobStatus{Succeeded: 1, Active: 2},
			},
			wantDelete: false,
		},
		{
			name: "multi-completion parallel job between waves (Active=0, no JobComplete) is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Spec:       batchv1.JobSpec{Completions: ptr.To(int32(3))},
				Status:     batchv1.JobStatus{Succeeded: 1, Active: 0},
			},
			wantDelete: false,
		},
		{
			name: "work-queue parallel job (Completions=nil, Succeeded=1, Active=2) is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Spec:       batchv1.JobSpec{Parallelism: ptr.To(int32(3))},
				Status:     batchv1.JobStatus{Succeeded: 1, Active: 2},
			},
			wantDelete: false,
		},
		{
			name: "JobComplete=True while Active=1 (draining pods) is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Status: batchv1.JobStatus{
					Succeeded:  1,
					Active:     1,
					Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}},
				},
			},
			wantDelete: false,
		},
		{
			name: "JobFailed=True while Active=1 (draining pods) is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Status: batchv1.JobStatus{
					Active:     1,
					Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}},
				},
			},
			wantDelete: false,
		},
		{
			name: "already-terminating job (DeletionTimestamp set) is skipped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate", DeletionTimestamp: &now},
				Status: batchv1.JobStatus{
					Succeeded:  1,
					Active:     0,
					Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}},
				},
			},
			wantDelete: false,
		},
		{
			name: "failed job with Active=0 is deleted and cooldown stamped",
			job: &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-migrate"},
				Status: batchv1.JobStatus{
					Failed:     1,
					Active:     0,
					Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}},
				},
			},
			wantDelete: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := immutableKust("apps", "web", "web-migrate")
			dyn := newDynFake(k)
			cs := kfake.NewSimpleClientset(tc.job)
			var deleteCalls int
			cs.PrependReactor("delete", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
				deleteCalls++
				return false, nil, nil
			})
			u := newUnlocker(cs, dyn, 0, "")
			if err := u.run(ctx); err != nil {
				t.Fatal(err)
			}
			if tc.wantDelete {
				if deleteCalls != 1 || jobExists(t, cs, "apps", "web-migrate") {
					t.Fatalf("expected job deleted once (deleteCalls=%d)", deleteCalls)
				}
				if _, ok := u.immutableJob.healed.Last("apps/web"); !ok {
					t.Fatal("expected cooldown stamped after delete")
				}
			} else {
				if deleteCalls != 0 {
					t.Fatalf("unexpected delete calls = %d, want 0", deleteCalls)
				}
				if _, ok := u.immutableJob.healed.Last("apps/web"); ok {
					t.Fatal("unexpected cooldown stamp when job was skipped")
				}
			}
		})
	}
}
