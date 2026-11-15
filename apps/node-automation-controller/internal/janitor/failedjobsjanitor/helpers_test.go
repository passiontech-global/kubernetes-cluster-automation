package failedjobsjanitor

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var ctx = context.Background()

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

func TestVaAttachedToPV(t *testing.T) {
	pvA := "pv-a"
	pvB := "pv-b"
	now := metav1.Now()
	j := &failedJobsJanitor{
		cs: fake.NewSimpleClientset(
			&storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "va-attached"},
				Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvA}},
				Status:     storagev1.VolumeAttachmentStatus{Attached: true},
			},
			&storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "va-terminating"},
				Spec:       storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvB}},
				Status:     storagev1.VolumeAttachmentStatus{Attached: false},
				// DeletionTimestamp set + Attached=false -> not attached
			},
		),
	}
	if attached, err := j.vaAttachedToPV(ctx, pvA); err != nil || !attached {
		t.Fatalf("vaAttachedToPV(pv-a) = (%v,%v), want (true,nil)", attached, err)
	}
	// Non-terminating VA with Attached=false still fails closed (returns true).
	if attached, err := j.vaAttachedToPV(ctx, pvB); err != nil || !attached {
		t.Fatalf("vaAttachedToPV(pv-b live unconfirmed) = (%v,%v), want (true,nil)", attached, err)
	}
	if attached, err := j.vaAttachedToPV(ctx, "pv-none"); err != nil || attached {
		t.Fatalf("vaAttachedToPV(pv-none) = (%v,%v), want (false,nil)", attached, err)
	}
	_ = now
}
