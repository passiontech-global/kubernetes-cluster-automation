package wdeps_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

func TestCycleEnvPodByUIDAndPodProtection(t *testing.T) {
	ce := &wdeps.CycleEnv{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "p1", UID: "uid-1"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "p2", UID: "uid-2"}},
		},
	}
	m1 := ce.PodByUID()
	m2 := ce.PodByUID()
	if len(m1) != 2 || m1["uid-1"].Name != "p1" || m2["uid-2"].Name != "p2" {
		t.Fatalf("unexpected PodByUID map: %+v", m1)
	}

	stsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet"}},
		},
	}
	if !wdeps.OwnedByStatefulSet(stsPod) || !wdeps.IsEvictProtectedPod(stsPod) {
		t.Fatal("expected StatefulSet-owned pod to be protected")
	}

	dbKeyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"cnpg.io/instanceRole": "primary"},
		},
	}
	if !wdeps.CarriesDBQuorumLabel(dbKeyPod) || !wdeps.IsEvictProtectedPod(dbKeyPod) {
		t.Fatal("expected CNPG instanceRole pod to be protected")
	}

	dbValPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": "my-scylla-node"},
		},
	}
	if !wdeps.CarriesDBQuorumLabel(dbValPod) {
		t.Fatal("expected scylla label value pod to carry DB quorum label")
	}

	plainPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
	}
	if wdeps.OwnedByStatefulSet(plainPod) || wdeps.CarriesDBQuorumLabel(plainPod) || wdeps.IsEvictProtectedPod(plainPod) {
		t.Fatal("expected plain pod not to be protected")
	}
}

func TestDepsPodEventsDeleteAndCoordGates(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "worker-pod",
			UID:       "pod-uid-1",
		},
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node"},
	}
	e := fixture(t, pod, node)
	ctx := context.Background()

	// EmitPodEvent with and without suffix.
	if err := e.D.EmitPodEvent(ctx, pod, "oom", "OOMKilled", "note1"); err != nil {
		t.Fatalf("EmitPodEvent with suffix: %v", err)
	}
	if err := e.D.EmitPodEvent(ctx, pod, "", "TestReason", "note2"); err != nil {
		t.Fatalf("EmitPodEvent without suffix: %v", err)
	}

	// Nil Coord paths.
	e.D.Cfg.Coord = nil
	if e.D.HoldLocalAction(ctx) {
		t.Fatal("expected HoldLocalAction=false with nil Coord")
	}
	if e.D.HoldEmergencyHeal(ctx) {
		t.Fatal("expected HoldEmergencyHeal=false with nil Coord")
	}
	e.D.StampLocalRemediation(ctx)
	e.D.StampPodHealed(ctx, pod.Namespace, pod.Name)

	// Wired Coord paths.
	e.D.Cfg.Coord = nodecoord.NewKube("test-node", e.D.Cfg.Client)
	_ = e.D.HoldLocalAction(ctx)
	_ = e.D.HoldEmergencyHeal(ctx)
	e.D.StampLocalRemediation(ctx)
	e.D.StampPodHealed(ctx, pod.Namespace, pod.Name)

	// DeletePodGraceful deletes the pod from fake clientset.
	if err := e.D.DeletePodGraceful(ctx, pod); err != nil {
		t.Fatalf("DeletePodGraceful: %v", err)
	}
	if _, err := e.D.Cfg.Client.CoreV1().Pods("default").Get(ctx, "worker-pod", metav1.GetOptions{}); err == nil {
		t.Fatal("expected worker-pod to be deleted")
	}
}

func TestProbeHTTPStatusSeriesAndDiskMaxUsageRatio(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	calls := 0
	e.D.Cfg.Seams.Probe.ProbeHTTPStatus = func(_ context.Context, _ string, _ string, _ time.Duration) (int, error) {
		calls++
		if calls == 1 {
			return 503, nil
		}
		return 200, nil
	}
	err := e.D.ProbeHTTPStatusSeries(ctx, "http://127.0.0.1/healthz", "tok", 3, time.Second, time.Millisecond,
		func(code int) (bool, error) {
			if code == 200 {
				return true, nil
			}
			return false, errors.New("not ready")
		})
	if err != nil || calls != 2 {
		t.Fatalf("ProbeHTTPStatusSeries = %v (calls=%d), want nil (calls=2)", err, calls)
	}

	e.D.Cfg.Seams.Probe.ProbeHTTPStatus = func(_ context.Context, _ string, _ string, _ time.Duration) (int, error) {
		return 0, errors.New("conn refused")
	}
	if err := e.D.ProbeHTTPStatusSeries(ctx, "http://127.0.0.1/healthz", "", 1, time.Second, time.Millisecond,
		func(int) (bool, error) { return true, nil }); err == nil {
		t.Fatal("expected error when probe fails")
	}

	e.D.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = 80 // 20% block usage
		st.Files = 100
		st.Ffree = 10 // 90% inode usage
		return nil
	}
	ratio, ok := e.D.DiskMaxUsageRatio("/var/lib/kubelet")
	if !ok || ratio < 0.89 || ratio > 0.91 {
		t.Fatalf("DiskMaxUsageRatio = (%v, %v), want (~0.9, true)", ratio, ok)
	}

	e.D.Cfg.Seams.Host.StatfsFn = func(_ string, _ *unix.Statfs_t) error {
		return errors.New("statfs failed")
	}
	if _, ok := e.D.DiskMaxUsageRatio("/bad"); ok {
		t.Fatal("expected ok=false on statfs error")
	}
}
