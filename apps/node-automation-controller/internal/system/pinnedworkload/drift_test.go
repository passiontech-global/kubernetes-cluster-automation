// drift_test.go — the shared drift predicates: each clause the three
// patchers duplicate must read identically here (nil replicas count
// as drift under an enabled pin, missing probes drift, only pinned
// resource keys are judged with a nil half skipped, any set affinity
// drifts).
package pinnedworkload

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReplicaDrifted(t *testing.T) {
	replicas := int32(3)
	pinned := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "d"},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
	}
	unpinned := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d"}}

	// Disabled pin never drifts — the patch body must also omit
	// spec.replicas then, or a disabled pin would fight autoscalers.
	if ReplicaDrifted(pinned, 0) || ReplicaDrifted(unpinned, 0) {
		t.Fatal("disabled pin reported drift")
	}
	if ReplicaDrifted(pinned, 3) {
		t.Fatal("matching replica count reported drift")
	}
	if !ReplicaDrifted(pinned, 4) {
		t.Fatal("drifted replica count not reported")
	}
	// nil .spec.replicas counts as drift under an enabled pin — it
	// means "never pinned", not "matches the API's default 1".
	if !ReplicaDrifted(unpinned, 3) {
		t.Fatal("nil spec.replicas not reported as drift")
	}
}

func probeContainer() *corev1.Container {
	return &corev1.Container{
		Name:           "coredns",
		LivenessProbe:  &corev1.Probe{TimeoutSeconds: 5},
		ReadinessProbe: &corev1.Probe{TimeoutSeconds: 5},
	}
}

func TestProbeTimeoutsDrifted(t *testing.T) {
	if ProbeTimeoutsDrifted(probeContainer()) {
		t.Fatal("pinned 5s probes reported drift")
	}
	c := probeContainer()
	c.LivenessProbe.TimeoutSeconds = 4
	if !ProbeTimeoutsDrifted(c) {
		t.Fatal("drifted liveness timeout not reported")
	}
	c = probeContainer()
	c.ReadinessProbe = nil
	if !ProbeTimeoutsDrifted(c) {
		t.Fatal("missing readiness probe not reported")
	}
	c = probeContainer()
	c.LivenessProbe = nil
	if !ProbeTimeoutsDrifted(c) {
		t.Fatal("missing liveness probe not reported")
	}
}

func TestResourcesDrifted(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	c := &corev1.Container{Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    q("100m"),
			corev1.ResourceMemory: q("170Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    q("1"),
			corev1.ResourceMemory: q("170Mi"),
		},
	}}
	wantReq := corev1.ResourceList{
		corev1.ResourceCPU:    q("100m"),
		corev1.ResourceMemory: q("170Mi"),
	}
	wantLim := corev1.ResourceList{
		corev1.ResourceCPU:    q("1"),
		corev1.ResourceMemory: q("170Mi"),
	}

	if ResourcesDrifted(c, wantReq, wantLim) {
		t.Fatal("matching pinned quantities reported drift")
	}
	// One drifted key is enough — the patchers' four-way || chain.
	bad := c.DeepCopy()
	bad.Resources.Limits[corev1.ResourceMemory] = q("1Gi")
	if !ResourcesDrifted(bad, wantReq, wantLim) {
		t.Fatal("drifted limit not reported")
	}
	// A missing key reads as zero — drift against any non-zero want.
	missing := c.DeepCopy()
	delete(missing.Resources.Requests, corev1.ResourceCPU)
	if !ResourcesDrifted(missing, wantReq, wantLim) {
		t.Fatal("missing pinned request not reported as drift")
	}
	// Extra container quantities are NOT drift — only pinned keys
	// are judged (the patch never touches them).
	extra := c.DeepCopy()
	extra.Resources.Limits[corev1.ResourceEphemeralStorage] = q("1Gi")
	if ResourcesDrifted(extra, wantReq, wantLim) {
		t.Fatal("unpinned extra quantity reported drift")
	}
	// A nil wanted half is skipped — konnectivity pins requests only.
	if ResourcesDrifted(c, wantReq, nil) {
		t.Fatal("nil limits half reported drift")
	}
}

func TestAffinitySet(t *testing.T) {
	if AffinitySet(corev1.PodSpec{}) {
		t.Fatal("nil affinity reported as set")
	}
	if !AffinitySet(corev1.PodSpec{Affinity: &corev1.Affinity{}}) {
		t.Fatal("set affinity not reported")
	}
}
