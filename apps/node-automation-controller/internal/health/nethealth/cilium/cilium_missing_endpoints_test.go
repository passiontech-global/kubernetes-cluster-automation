// cilium_missing_endpoints_test.go — coverage for the
// cilium-missing-endpoint check: 2-sweep persistence, per-pod
// delete, and the same-node agent bounce.
package cilium

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// cepObj builds a CiliumEndpoint CR for pod ns/name with the given
// identity id (0 leaves identity.id absent).
func cepObj(ns, name string, identityID int64) *unstructured.Unstructured {
	obj := testutil.Unstructured(
		kube.GVRCiliumEndpoint.GroupVersion().WithKind("CiliumEndpoint"), ns, name,
		map[string]any{"status": map[string]any{
			"networking": map[string]any{
				"addressing": []any{map[string]any{"ipv4": "10.0.0.9"}},
			},
		}})
	if identityID > 0 {
		_ = unstructured.SetNestedField(obj.Object, identityID,
			"status", "identity", "id")
	}
	return obj
}

func TestCiliumMissingCEPDeletesPodAfterPersistence(t *testing.T) {
	pod := probetest.PodWithPhase("apps", "app-1", corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = "w1"
	// A lone-pod delete needs a controller owner — ownerless pods
	// are never recreated, so the check refuses to delete one.
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "app-1-rs", UID: "rs-uid", Controller: new(bool),
	}}
	*pod.OwnerReferences[0].Controller = true
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs) // no CEP seeded -> missing endpoint
	chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first sighting inside streak window must pass: %+v", res)
	}
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("persistent missing CEP must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod without CEP should be deleted, err=%v", err)
	}
}

// An ownerless pod (no controller ownerRef) is never deleted — a
// delete would be destruction, not healing, since nothing recreates it.
func TestCiliumMissingCEPOwnerlessPodSurvives(t *testing.T) {
	pod := probetest.PodWithPhase("apps", "app-bare", corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = "w1"
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs) // no CEP seeded -> missing endpoint
	chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("persistent missing CEP must still fail (signature)")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-bare", metav1.GetOptions{}); err != nil {
		t.Fatalf("ownerless pod must survive the CEP-missing heal: %v", err)
	}
}

func TestCiliumMissingCEPAgentBounceOnNodeMassMiss(t *testing.T) {
	agent := probetest.PodWithPhase("kube-system", "cilium-abc",
		corev1.PodRunning, true, time.Hour)
	agent.Labels = map[string]string{"k8s-app": "cilium"}
	agent.Spec.NodeName = "w9"
	objs := []runtime.Object{agent}
	names := []string{"app-0", "app-1", "app-2"}
	for _, name := range names {
		pod := probetest.PodWithPhase("apps", name,
			corev1.PodRunning, true, time.Hour)
		pod.Spec.NodeName = "w9"
		objs = append(objs, pod)
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProber(cs)
	chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("mass missing CEP must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "cilium-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("cilium agent on the mass-miss node should be restarted, err=%v", err)
	}
	for _, name := range names {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("workload pod %s must survive — the agent bounce covers it: %v", name, err)
		}
	}
}

func TestCiliumProgrammedEndpointPasses(t *testing.T) {
	pod := probetest.PodWithPhase("apps", "app-ok", corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = "w1"
	cs := fake.NewSimpleClientset(pod)
	cep := cepObj("apps", "app-ok", 4242)
	p := testProberDyn(cs, probetest.OpDyn(cep))
	if res := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("programmed endpoint must pass: %+v", res)
	}
}

func TestCiliumReservedWorldIdentityIsUnprogrammed(t *testing.T) {
	pod := probetest.PodWithPhase("apps", "app-world", corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = "w1"
	cs := fake.NewSimpleClientset(pod)
	cep := cepObj("apps", "app-world", 2) // reserved:world
	p := testProberDyn(cs, probetest.OpDyn(cep))
	chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("reserved:world identity must fail: %+v", res)
	}
}

// A 403 on the CEP census — the shape a Calico cluster produces,
// where the opt-in cilium-identity grant does not exist — must
// skip cleanly: no Infra error, and tuples held from a previous
// sweep carry forward instead of flapping off. A non-403 failure
// still reports Infra.
func TestCiliumMissingCEPForbiddenSkipsAndCarries(t *testing.T) {
	pod := probetest.PodWithPhase("apps", "app-bare", corev1.PodRunning, true, time.Hour)
	pod.Spec.NodeName = "w1"
	// Ownerless: the pod survives the heal delete so the emitted
	// tuple stays held into the forbidden sweep.
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("persistent missing CEP must fail to seed the held tuple")
	}
	dynBlocked := probetest.OpDyn()
	dynBlocked.PrependReactor("list", "ciliumendpoints",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: "cilium.io", Resource: "ciliumendpoints"},
				"", errors.New("forbidden"))
		})
	chk.Dyn = dynBlocked
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass || res.Infra != nil {
		t.Fatalf("403 census must pass with nil Infra, got %+v", res)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_cilium_missing_cep_pods",
		map[string]string{"namespace": "apps", "pod": "app-bare", "node": "w1"}); !ok || v != 1 {
		t.Fatalf("held tuple must carry through the 403 sweep: %v,%v", v, ok)
	}
	// A non-403 census failure still reports Infra.
	dynErr := probetest.OpDyn()
	dynErr.PrependReactor("list", "ciliumendpoints",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver timeout")
		})
	chk.Dyn = dynErr
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Infra == nil {
		t.Fatalf("transient census failure must report Infra, got %+v", res)
	}
	ciliumMissingCEPPodsGauge.DeleteLabelValues("apps", "app-bare", "w1")
}

func makeOwnedPodWithNet(ns, name, node, podIP, hostIP string, uid types.UID) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	pod.UID = uid
	pod.Spec.NodeName = node
	pod.Status.PodIP = podIP
	pod.Status.HostIP = hostIP
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       name + "-rs",
		UID:        "rs-uid-" + uid,
		Controller: ptr.To(true),
	}}
	return pod
}

func cepObjFull(ns, name string, identityID int64, ipv4, nodeIP string, ownerPodUID types.UID) *unstructured.Unstructured {
	netObj := map[string]any{
		"addressing": []any{map[string]any{"ipv4": ipv4}},
	}
	if nodeIP != "" {
		netObj["node"] = nodeIP
	}
	obj := testutil.Unstructured(
		kube.GVRCiliumEndpoint.GroupVersion().WithKind("CiliumEndpoint"), ns, name,
		map[string]any{"status": map[string]any{
			"identity":   map[string]any{"id": identityID},
			"networking": netObj,
		}})
	if ownerPodUID != "" {
		obj.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       name,
			UID:        ownerPodUID,
		}})
	}
	return obj
}

func TestCiliumStaleCEPMismatchDetectionAndHeal(t *testing.T) {
	t.Run("stale CEP PodIP detected after 2 sweeps and pod deleted", func(t *testing.T) {
		pod := makeOwnedPodWithNet("apps", "adapter-1", "lanit-02", "10.0.0.89", "172.29.0.16", "pod-uid-live")
		cep := cepObjFull("apps", "adapter-1", 4242, "10.0.0.74", "172.29.0.16", "pod-uid-live")
		cs := fake.NewSimpleClientset(pod)
		p := testProberDyn(cs, probetest.OpDyn(cep))
		chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)

		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
			t.Fatalf("first sighting inside streak window must pass: %+v", res)
		}
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatalf("stale CEP PodIP mismatch must fail on 2nd sweep: %+v", res)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "adapter-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("pod with stale CEP PodIP should be deleted to heal, err=%v", err)
		}
		ciliumMissingCEPPodsGauge.DeleteLabelValues("apps", "adapter-1", "lanit-02")
	})

	t.Run("stale CEP HostIP/node detected after 2 sweeps and pod deleted", func(t *testing.T) {
		pod := makeOwnedPodWithNet("apps", "adapter-2", "lanit-02", "10.0.0.89", "172.29.0.16", "pod-uid-2")
		cep := cepObjFull("apps", "adapter-2", 4242, "10.0.0.89", "172.29.0.15", "pod-uid-2")
		cs := fake.NewSimpleClientset(pod)
		p := testProberDyn(cs, probetest.OpDyn(cep))
		chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)

		chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatalf("stale CEP networking.node mismatch must fail on 2nd sweep: %+v", res)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "adapter-2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("pod with stale CEP HostIP should be deleted to heal, err=%v", err)
		}
		ciliumMissingCEPPodsGauge.DeleteLabelValues("apps", "adapter-2", "lanit-02")
	})

	t.Run("stale CEP ownerReferences Pod UID mismatch detected after 2 sweeps and pod deleted", func(t *testing.T) {
		pod := makeOwnedPodWithNet("apps", "adapter-3", "lanit-02", "10.0.0.89", "172.29.0.16", "pod-uid-new")
		cep := cepObjFull("apps", "adapter-3", 4242, "10.0.0.89", "172.29.0.16", "pod-uid-old")
		cs := fake.NewSimpleClientset(pod)
		p := testProberDyn(cs, probetest.OpDyn(cep))
		chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)

		chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatalf("stale CEP ownerReference Pod UID mismatch must fail on 2nd sweep: %+v", res)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "adapter-3", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("pod with stale CEP owner UID should be deleted to heal, err=%v", err)
		}
		ciliumMissingCEPPodsGauge.DeleteLabelValues("apps", "adapter-3", "lanit-02")
	})

	t.Run("matching PodIP HostIP and owner UID passes cleanly", func(t *testing.T) {
		pod := makeOwnedPodWithNet("apps", "adapter-ok", "lanit-02", "10.0.0.89", "172.29.0.16", "pod-uid-ok")
		cep := cepObjFull("apps", "adapter-ok", 4242, "10.0.0.89", "172.29.0.16", "pod-uid-ok")
		cs := fake.NewSimpleClientset(pod)
		p := testProberDyn(cs, probetest.OpDyn(cep))
		chk := probetest.MustCheck[*ciliumMissingEndpointsCheck](t, p)

		chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
			t.Fatalf("matching CEP must pass cleanly: %+v", res)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "adapter-ok", metav1.GetOptions{}); err != nil {
			t.Fatalf("healthy pod must not be deleted: %v", err)
		}
	})
}
