// snapshot_index_test.go — unit tests for Deps snapshot indexes,
// Deps.OwnerGone census resolution, EndpointSlicesForService,
// LeasesFetchedAt, Service, and PodsOnNode.
package probefw

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDeps_WorkloadIndexesAndOwnerGone(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1", UID: "pod-uid"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs1", UID: "rs-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dep1", UID: "dep-uid"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sts1", UID: "sts-uid"}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds1", UID: "ds-uid"}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cj1", UID: "cj-uid"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job1", UID: "job-uid"}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pdb1"}},
	)
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(context.Background())

	// Workload index lookups: hits and misses.
	if dep, err := d.Deployment(ctx, "ns", "dep1"); err != nil || dep == nil || dep.UID != "dep-uid" {
		t.Fatalf("Deployment(dep1) = %v, %v", dep, err)
	}
	if dep, err := d.Deployment(ctx, "ns", "missing"); err != nil || dep != nil {
		t.Fatalf("Deployment(missing) = %v, %v", dep, err)
	}
	if sts, err := d.StatefulSet(ctx, "ns", "sts1"); err != nil || sts == nil || sts.UID != "sts-uid" {
		t.Fatalf("StatefulSet(sts1) = %v, %v", sts, err)
	}
	if ds, err := d.DaemonSet(ctx, "ns", "ds1"); err != nil || ds == nil || ds.UID != "ds-uid" {
		t.Fatalf("DaemonSet(ds1) = %v, %v", ds, err)
	}
	if rs, err := d.ReplicaSet(ctx, "ns", "rs1"); err != nil || rs == nil || rs.UID != "rs-uid" {
		t.Fatalf("ReplicaSet(rs1) = %v, %v", rs, err)
	}
	if cj, err := d.CronJob(ctx, "ns", "cj1"); err != nil || cj == nil || cj.UID != "cj-uid" {
		t.Fatalf("CronJob(cj1) = %v, %v", cj, err)
	}
	if job, err := d.Job(ctx, "ns", "job1"); err != nil || job == nil || job.UID != "job-uid" {
		t.Fatalf("Job(job1) = %v, %v", job, err)
	}
	if pdbs, err := d.AllPDBs(ctx); err != nil || len(pdbs) != 1 {
		t.Fatalf("AllPDBs = %d, %v", len(pdbs), err)
	}

	// Deps.OwnerGone across all 7 census-backed kinds: matching UID -> live (gone=false, resolved=true).
	liveRefs := []metav1.OwnerReference{
		{Kind: "Pod", Name: "p1", UID: "pod-uid"},
		{Kind: "ReplicaSet", Name: "rs1", UID: "rs-uid"},
		{Kind: "Deployment", Name: "dep1", UID: "dep-uid"},
		{Kind: "StatefulSet", Name: "sts1", UID: "sts-uid"},
		{Kind: "DaemonSet", Name: "ds1", UID: "ds-uid"},
		{Kind: "CronJob", Name: "cj1", UID: "cj-uid"},
		{Kind: "Job", Name: "job1", UID: "job-uid"},
	}
	for i := range liveRefs {
		gone, resolved := d.OwnerGone(ctx, "ns", &liveRefs[i], liveRefs[i].Kind)
		if gone || !resolved {
			t.Errorf("%s live ref: got gone=%v resolved=%v, want false/true", liveRefs[i].Kind, gone, resolved)
		}
	}

	// Different UID on same-name object -> different incarnation -> gone=true, resolved=true.
	staleRef := metav1.OwnerReference{Kind: "Deployment", Name: "dep1", UID: "old-uid"}
	if gone, resolved := d.OwnerGone(ctx, "ns", &staleRef, "Deployment"); !gone || !resolved {
		t.Errorf("stale UID ref: got gone=%v resolved=%v, want true/true", gone, resolved)
	}

	// Census miss falls through to GET -> NotFound -> gone=true, resolved=true.
	missRef := metav1.OwnerReference{Kind: "Deployment", Name: "nonexistent", UID: "x"}
	if gone, resolved := d.OwnerGone(ctx, "ns", &missRef, "Deployment"); !gone || !resolved {
		t.Errorf("missing ref: got gone=%v resolved=%v, want true/true", gone, resolved)
	}
}

func TestDeps_ClusterIndexesAndPodsOnNode(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC)
	cs := fake.NewClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "svc1"}},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      "svc1-abc",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "svc1"},
			},
		},
		&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "l1"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p-node1"},
			Spec:       corev1.PodSpec{NodeName: "node1"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p-unsched"},
		},
	)
	d := &Deps{
		CS:  cs,
		Now: func() time.Time { return fixedNow },
	}

	// Outside sweep: LeasesFetchedAt falls back to d.Now().
	if got := d.LeasesFetchedAt(context.Background()); !got.Equal(fixedNow) {
		t.Fatalf("LeasesFetchedAt outside sweep = %v, want %v", got, fixedNow)
	}

	ctx := WithSweepSnapshot(context.Background())
	// Before AllLeases loads, LeasesFetchedAt also falls back to d.Now().
	if got := d.LeasesFetchedAt(ctx); !got.Equal(fixedNow) {
		t.Fatalf("LeasesFetchedAt before load = %v, want %v", got, fixedNow)
	}
	if _, err := d.AllLeases(ctx); err != nil {
		t.Fatalf("AllLeases: %v", err)
	}
	if got := d.LeasesFetchedAt(ctx); got.IsZero() {
		t.Fatal("expected non-zero LeasesFetchedAt after AllLeases")
	}

	// Service lookup hit & miss.
	if svc, err := d.Service(ctx, "ns", "svc1"); err != nil || svc == nil {
		t.Fatalf("Service(svc1) = %v, %v", svc, err)
	}
	if svc, err := d.Service(ctx, "ns", "missing"); err != nil || svc != nil {
		t.Fatalf("Service(missing) = %v, %v", svc, err)
	}

	// EndpointSlicesForService called twice to exercise elemSliceSame cache hit.
	for i := range 2 {
		eps, err := d.EndpointSlicesForService(ctx, "ns", "svc1")
		if err != nil || len(eps) != 1 || eps[0].Name != "svc1-abc" {
			t.Fatalf("call %d EndpointSlicesForService(svc1) = %v, %v", i, eps, err)
		}
	}
	if eps, err := d.EndpointSlicesForService(ctx, "ns", "missing"); err != nil || len(eps) != 0 {
		t.Fatalf("EndpointSlicesForService(missing) = %v, %v", eps, err)
	}

	// PodsOnNode for scheduled and unscheduled pods.
	if pods, err := d.PodsOnNode(ctx, "node1"); err != nil || len(pods) != 1 || pods[0].Name != "p-node1" {
		t.Fatalf("PodsOnNode(node1) = %v, %v", pods, err)
	}
	if pods, err := d.PodsOnNode(ctx, ""); err != nil || len(pods) != 1 || pods[0].Name != "p-unsched" {
		t.Fatalf("PodsOnNode(\"\") = %v, %v", pods, err)
	}
}

func TestDeps_SnapshotIndexErrorPropagation(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset()
	cs.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("list boom")
	})
	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(context.Background())

	if _, err := d.Deployment(ctx, "ns", "d"); err == nil {
		t.Error("expected Deployment error")
	}
	if _, err := d.Service(ctx, "ns", "s"); err == nil {
		t.Error("expected Service error")
	}
	if _, err := d.EndpointSlicesForService(ctx, "ns", "s"); err == nil {
		t.Error("expected EndpointSlicesForService error")
	}
	if _, err := d.PodsOnNode(ctx, "n"); err == nil {
		t.Error("expected PodsOnNode error")
	}
}
