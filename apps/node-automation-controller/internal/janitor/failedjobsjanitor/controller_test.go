package failedjobsjanitor

import (
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// failed-jobs-janitor
// ---------------------------------------------------------------------------

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
	j := &failedJobsJanitor{cs: cs, now: time.Now}
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
