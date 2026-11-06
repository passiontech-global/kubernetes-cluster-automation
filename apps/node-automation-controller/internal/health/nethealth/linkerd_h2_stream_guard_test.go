// linkerd_h2_stream_guard_test.go — coverage for the
// linkerd-h2-stream-guard check: storm-signature delete with a
// Ready sibling, and the no-sibling skip.
package nethealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// meshedPod builds a Running+Ready pod with a linkerd-proxy
// container, owned by controller `owner`.
func meshedPod(ns, name string, ready bool, owner types.UID) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Spec.Containers = []corev1.Container{
		{Name: "app"}, {Name: linkerdProxyContainer},
	}
	pod.OwnerReferences = []metav1.OwnerReference{{
		Kind: "ReplicaSet", Name: "rs-" + name,
		UID: owner, Controller: ptr.To(true)}}
	return pod
}

func TestLinkerdH2StormDeletesPodWithReadySibling(t *testing.T) {
	owner := types.UID("rs-shared")
	bad := meshedPod("apps", "web-1", true, owner)
	// The sibling is an UNMESHED pod under the same owner — the fake
	// log reactor returns the same body for every pod, so a meshed
	// sibling would read as storming too and be deleted alongside.
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR Http2 stream error: ENHANCE_YOUR_CALM\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("h2 storm signature must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("storming pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("Ready sibling must survive: %v", err)
	}
}

func TestLinkerdH2StormSkipsPodWithoutSibling(t *testing.T) {
	// The storming pod is the ONLY Ready replica of its owner —
	// deleting it blackholes the workload.
	owner := types.UID("rs-solo")
	bad := meshedPod("apps", "web-1", true, owner)
	cs := fake.NewSimpleClientset(bad)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR too_many_pings\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("h2 storm signature must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("lone-replica pod must not be deleted: %v", err)
	}
}

func TestLinkerdH2CleanLogsPass(t *testing.T) {
	pod := meshedPod("apps", "web-1", true, types.UID("rs-1"))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("clean proxy log must pass: %+v", res)
	}
}
