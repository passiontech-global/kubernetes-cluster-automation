// unmeshed_pod_auditor_test.go — coverage for the unmeshed-pod
// auditor duty: the injection opt-in matrix, the emitted gauge's
// ledger hygiene, the bounded eviction remediation and its
// fail-closed gates (injector health, maintenance mutex).
package unmeshed

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (up-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

func upNamespace(name, inject string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if inject != "" {
		ns.Annotations = map[string]string{kube.LinkerdInjectKey: inject}
	}
	return ns
}

func upOwner() metav1.OwnerReference {
	return metav1.OwnerReference{Kind: "ReplicaSet", Name: "rs-x",
		Controller: ptr.To(true)}
}

// upPod builds a Running, owned, old-enough pod in ns with one app
// container and no sidecar — the unmeshed candidate shape.
func upPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			OwnerReferences:   []metav1.OwnerReference{upOwner()},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// upInjectorCfg builds a healthy MutatingWebhookConfiguration whose
// linkerd-proxy-injector entry fails closed against linkerd/linkerd-proxy-injector.
func upInjectorCfg() *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "linkerd-proxy-injector-webhook-config"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "linkerd-proxy-injector.linkerd.io",
			FailurePolicy: ptr.To(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("linkerd", "linkerd-proxy-injector"),
			},
		}},
	}
}

// upReadySlice gives linkerd/linkerd-proxy-injector one Ready endpoint.
func upReadySlice() *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "linkerd", Name: "linkerd-proxy-injector-abc",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "linkerd-proxy-injector",
			},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	}
}

func upPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// upSeed builds the audit-sweep clientset: the baseline kube-system
// (unlabeled) and meshed (inject=enabled) namespaces, then thirdNS
// (nil omits it) and the scenario objects the test varies — each
// seed stays explicit about what it changes.
func upSeed(thirdNS *corev1.Namespace, extra ...runtime.Object) *fake.Clientset {
	objs := []runtime.Object{
		upNamespace("kube-system", ""),
		upNamespace("meshed", "enabled"),
	}
	if thirdNS != nil {
		objs = append(objs, thirdNS)
	}
	return fake.NewSimpleClientset(append(objs, extra...)...)
}

func upGuard(cs *fake.Clientset) (*Auditor, *guardstate.Guard) {
	return &Auditor{},
		&guardstate.Guard{CS: cs, Dyn: wgDyn(), Now: time.Now}
}

// ---------------------------------------------------------------------------
// Audit (gauge)
// ---------------------------------------------------------------------------

// A Running pod in an inject=enabled namespace without the sidecar
// exports the gauge; ns-level opt-in fires even when the pod carries
// no annotation at all.
func TestUnmeshedAuditFlagsUnmeshedPod(t *testing.T) {
	testutil.CleanupMetric(t, metrics.UnmeshedPods, "meshed", "web-abc")

	cs := upSeed(
		upNamespace("plain", ""),
		upPod("meshed", "web-abc"),
		upPod("plain", "other-abc"))
	a, g := upGuard(cs)

	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(
		metrics.UnmeshedPods.WithLabelValues("meshed", "web-abc")); got != 1 {
		t.Fatalf("unmeshed gauge = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(
		metrics.UnmeshedPods.WithLabelValues("plain", "other-abc")); got != 0 {
		t.Fatalf("plain-namespace pod flagged: %v", got)
	}
}

// The skip matrix — hostNetwork, Job/CronJob children, explicit
// opt-out and sidecar'd pods are never flagged.
func TestUnmeshedAuditSkips(t *testing.T) {
	hostNet := upPod("meshed", "hostnet")
	hostNet.Spec.HostNetwork = true

	jobPod := upPod("meshed", "job-pod")
	jobPod.OwnerReferences = []metav1.OwnerReference{{
		Kind: "Job", Name: "j", Controller: ptr.To(true)}}

	optedOut := upPod("meshed", "opted-out")
	optedOut.Annotations = map[string]string{kube.LinkerdInjectKey: "disabled"}

	meshed := upPod("meshed", "meshed")
	meshed.Spec.Containers = append(meshed.Spec.Containers,
		corev1.Container{Name: kube.LinkerdProxyContainer})

	initMeshed := upPod("meshed", "init-meshed")
	initMeshed.Spec.InitContainers = []corev1.Container{{Name: kube.LinkerdProxyContainer}}

	cs := upSeed(
		nil,
		hostNet, jobPod, optedOut, meshed, initMeshed)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if len(a.unmeshedEmitted.Last()) != 0 {
		t.Fatalf("skippable pods flagged: %v", a.unmeshedEmitted.Last())
	}
}

// Pod-level inject=enabled opts in even inside a plain namespace;
// pod-level inject=disabled opts out inside an enabled namespace.
func TestUnmeshedAuditPodDirectiveOverridesNamespace(t *testing.T) {
	podEnabled := upPod("plain", "pod-enabled")
	podEnabled.Annotations = map[string]string{kube.LinkerdInjectKey: "enabled"}
	nsEnabledPodDisabled := upPod("meshed", "ns-enabled-pod-disabled")
	nsEnabledPodDisabled.Annotations = map[string]string{kube.LinkerdInjectKey: "disabled"}

	testutil.CleanupMetric(t, metrics.UnmeshedPods, "plain", "pod-enabled")

	cs := upSeed(
		upNamespace("plain", ""),
		podEnabled, nsEnabledPodDisabled)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(
		metrics.UnmeshedPods.WithLabelValues("plain", "pod-enabled")); got != 1 {
		t.Fatalf("pod-level enabled not flagged: %v", got)
	}
	if _, ok := a.unmeshedEmitted.Last()["meshed/ns-enabled-pod-disabled"]; ok {
		t.Fatal("pod-level disabled flagged inside an enabled ns")
	}
}

// A pending pod is out of scope — only Running pods are audited.
func TestUnmeshedAuditSkipsNonRunning(t *testing.T) {
	pending := upPod("meshed", "pending")
	pending.Status.Phase = corev1.PodPending
	cs := upSeed(
		nil,
		pending)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if len(a.unmeshedEmitted.Last()) != 0 {
		t.Fatalf("pending pod flagged: %v", a.unmeshedEmitted.Last())
	}
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

// Healthy injector + remediation on: unmeshed, owned, old pods are
// evicted — capped at 2 per cycle — and counted.
func TestUnmeshedRemediationDeletesUpToTwo(t *testing.T) {
	testutil.CleanupMetric(t, metrics.UnmeshedPodsRecreatedTotal, "meshed")

	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"), upPod("meshed", "web-b"), upPod("meshed", "web-c"))
	emulateEviction(cs)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	deleted := 0
	for _, n := range []string{"web-a", "web-b", "web-c"} {
		if !upPodExists(t, cs, "meshed", n) {
			deleted++
		}
	}
	if deleted != unmeshedDeleteCap {
		t.Fatalf("deleted %d pods, want cap of %d", deleted, unmeshedDeleteCap)
	}
	if got := ptestutil.ToFloat64(
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues("meshed")); got != 2 {
		t.Fatalf("recreated counter = %v, want 2", got)
	}
}

// A circuit-broken injector (recorded in guardstate.CircuitBrokenAnno) means
// pods recreate unmeshed again — remediation must stay off on the
// annotation ALONE, even with failurePolicy still Fail and endpoints
// up. Isolated from the Ignore-policy guard so each half is proven
// sufficient by itself (the health check ORs them into one skip).
func TestUnmeshedRemediationSkipsCircuitBrokenInjector(t *testing.T) {
	broken := upInjectorCfg() // failurePolicy stays Fail
	broken.Annotations = map[string]string{
		guardstate.CircuitBrokenAnno: "linkerd-proxy-injector.linkerd.io"}
	cs := upSeed(
		upNamespace("linkerd", ""),
		broken, upReadySlice(),
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted while the injector is circuit-broken")
	}
}

// A fail-open injector (failurePolicy=Ignore — a tripped breaker
// leaves it behind, or an operator set it manually) means pod
// creation sails through unmeshed — remediation must stay off on the
// policy ALONE, with no circuit-breaker annotation present.
func TestUnmeshedRemediationSkipsIgnorePolicyInjector(t *testing.T) {
	failOpen := upInjectorCfg()
	failOpen.Webhooks[0].FailurePolicy = ptr.To(admissionv1.Ignore)
	cs := upSeed(
		upNamespace("linkerd", ""),
		failOpen, upReadySlice(),
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted while the injector fails open (Ignore)")
	}
}

// Zero Ready endpoints behind the injector Service — the webhook is
// not provably healthy, so nothing is deleted.
func TestUnmeshedRemediationSkipsDeadEndpoints(t *testing.T) {
	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), // no EndpointSlice at all
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted with 0 ready injector endpoints")
	}
}

// A lookalike webhook name must not satisfy the injector health
// check — the match is exact, not substring.
func TestUnmeshedInjectorHealthRequiresExactName(t *testing.T) {
	lookalike := upInjectorCfg()
	lookalike.Webhooks[0].Name = "acme-linkerd-proxy-injector.example.com"
	cs := upSeed(
		upNamespace("linkerd", ""),
		lookalike, upReadySlice(),
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted — a lookalike webhook name satisfied injector health")
	}
}

// UNMESHED_POD_REMEDIATION_ENABLED=false pins the auditor to
// gauge-only even with a healthy injector.
func TestUnmeshedRemediationDisabledByEnv(t *testing.T) {
	t.Setenv("UNMESHED_POD_REMEDIATION_ENABLED", "false")
	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted with remediation disabled")
	}
}

// Deletion requires a CONTROLLER owner AND >2m of age: a fresh
// unmeshed pod, an orphan (no ownerReferences) and a pod with only
// a bare (non-controller) ownerReference are flagged but never
// deleted.
func TestUnmeshedRemediationRequiresOwnerAndAge(t *testing.T) {
	fresh := upPod("meshed", "fresh")
	fresh.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Minute))
	orphan := upPod("meshed", "orphan")
	orphan.OwnerReferences = nil
	bareOwner := upPod("meshed", "bare-owner")
	bareOwner.OwnerReferences = []metav1.OwnerReference{
		{Kind: "ReplicaSet", Name: "rs-x"}} // controller flag unset

	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		fresh, orphan, bareOwner)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"fresh", "orphan", "bare-owner"} {
		if !upPodExists(t, cs, "meshed", n) {
			t.Fatalf("pod %s deleted — age/owner gate failed", n)
		}
	}
	if len(a.unmeshedEmitted.Last()) != 3 {
		t.Fatalf("fresh/orphan/bare-owner pods not flagged: %v", a.unmeshedEmitted.Last())
	}
}

// A pod already terminating needs no second delete — its replacement
// re-admits meshed — and a mirror pod (controller ownerReference of
// kind Node) only reflects a static manifest: deleting it changes
// nothing. Both still count in the gauge but are never touched.
func TestUnmeshedRemediationSkipsTerminatingAndMirror(t *testing.T) {
	terminating := upPod("meshed", "terminating")
	termAt := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &termAt

	mirror := upPod("meshed", "mirror")
	mirror.OwnerReferences = []metav1.OwnerReference{{
		Kind: "Node", Name: "worker-1", Controller: ptr.To(true)}}

	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		terminating, mirror)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"terminating", "mirror"} {
		if !upPodExists(t, cs, "meshed", n) {
			t.Fatalf("pod %s deleted — terminating/mirror skip failed", n)
		}
	}
	if len(a.unmeshedEmitted.Last()) != 2 {
		t.Fatalf("terminating/mirror pods not flagged: %v", a.unmeshedEmitted.Last())
	}
}

// The all-namespaces pod list pages through the apiserver's continue
// token: a first page that hands back Continue is followed until the
// server stops continuing — pods on a later page are still audited.
func TestUnmeshedAuditPaginatesPodList(t *testing.T) {
	testutil.CleanupMetric(t, metrics.UnmeshedPods, "meshed", "web-a")

	cs := upSeed(
		nil,
		upPod("meshed", "web-a"))
	calls := 0
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			calls++
			if calls == 1 {
				// Page 1: empty, but continued — the tracker page
				// (with the pod) only arrives on the follow-up.
				return true, &corev1.PodList{
					ListMeta: metav1.ListMeta{Continue: "page-2"},
				}, nil
			}
			return false, nil, nil // passthrough — page 2 from the tracker
		})
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("pod list calls = %d, want 2 (continue followed)", calls)
	}
	if _, ok := a.unmeshedEmitted.Last()["meshed/web-a"]; !ok {
		t.Fatal("pod on the continued page was not audited")
	}
}

// The unmeshed eviction carries a UID precondition on the Eviction's
// DeleteOptions — a same-named pod recreated between the list
// snapshot and the evict (admitted after the injector recovered) is
// not the pod this sweep vetted.
func TestUnmeshedRemediationDeleteUIDPrecondition(t *testing.T) {
	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	var gotUID *types.UID
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			if ev.DeleteOptions != nil && ev.DeleteOptions.Preconditions != nil {
				gotUID = ev.DeleteOptions.Preconditions.UID
			}
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil {
		t.Fatal("eviction missing the UID precondition")
	}
	if upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod still exists — eviction never landed")
	}
}

// A persistently failing eviction must not storm the API: the sweep
// gives up after unmeshedDeleteAttempts and retries next cycle.
func TestUnmeshedRemediationCapsDeleteAttempts(t *testing.T) {
	objs := []runtime.Object{
		upNamespace("kube-system", ""),
		upNamespace("meshed", "enabled"),
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice()}
	for i := 0; i < 8; i++ {
		objs = append(objs, upPod("meshed", fmt.Sprintf("web-%d", i)))
	}
	cs := fake.NewSimpleClientset(objs...)
	evictions := 0
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			evictions++
			return true, nil, errors.New("apiserver wedged")
		})
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if evictions != unmeshedDeleteAttempts {
		t.Fatalf("eviction attempts = %d, want cap of %d",
			evictions, unmeshedDeleteAttempts)
	}
	for i := 0; i < 8; i++ {
		if !upPodExists(t, cs, "meshed", fmt.Sprintf("web-%d", i)) {
			t.Fatalf("pod web-%d deleted through the failing reactor", i)
		}
	}
}

// ---------------------------------------------------------------------------
// W7-C1 — Eviction API, PDB deferral & maintenance mutex
// ---------------------------------------------------------------------------

// A PDB-refused eviction (HTTP 429 — disruptionsAllowed==0) is a
// deferral, not a failure: the pod is kept, no error counts, and the
// sweep moves on to the next candidate — which still evicts.
func TestUnmeshedRemediationPDBRefusalDefers(t *testing.T) {
	testutil.CleanupMetric(t, metrics.UnmeshedPodsRecreatedTotal, "meshed")

	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"), upPod("meshed", "web-b"))
	refused := false
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			if ev.Name == "web-a" {
				refused = true
				return true, nil, apierrors.NewTooManyRequests(
					"pdb allows no disruptions", 0)
			}
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !refused {
		t.Fatal("web-a eviction never attempted")
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("PDB-refused pod was deleted anyway")
	}
	if upPodExists(t, cs, "meshed", "web-b") {
		t.Fatal("PDB refusal on web-a must not block web-b's eviction")
	}
	// The refusal is a deferral — web-b's eviction counted, web-a's
	// did not error.
	if got := ptestutil.ToFloat64(
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues("meshed")); got != 1 {
		t.Fatalf("recreated counter = %v, want 1 (only web-b)", got)
	}
}

// An ACTIVELY cordoned node means a drain is in flight — the
// maintenance mutex defers the whole remediation even though the
// injector is healthy. The fixture carries a fresh unschedulable
// taint: the canonical NodeActivelyCordoned check wants the cordon
// provably inside the 45m window, not just spec.unschedulable.
func TestUnmeshedRemediationMaintenanceDefers(t *testing.T) {
	fresh := metav1.NewTime(time.Now())
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &fresh,
			}},
		},
	}
	cs := fake.NewSimpleClientset(cordoned,
		upNamespace("kube-system", ""),
		upNamespace("meshed", "enabled"),
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	evictions := 0
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if ok && ca.GetSubresource() == "eviction" {
				evictions++
			}
			return true, nil, errors.New("must not evict")
		})
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if evictions != 0 {
		t.Fatalf("eviction attempted during maintenance: %d", evictions)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted during maintenance")
	}
}

// A STATICALLY cordoned node — unschedulable held past the 45m
// cordon window — is deliberate state, not maintenance: the
// canonical NodeActivelyCordoned check does not hold the mutex for
// it, so remediation still evicts. (The removed nil-dyn degraded
// copy checked spec.unschedulable alone and would have deferred
// forever — this is the regression test for that drift.)
func TestUnmeshedRemediationStaticCordonDoesNotDefer(t *testing.T) {
	stale := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &stale,
			}},
		},
	}
	cs := fake.NewSimpleClientset(cordoned,
		upNamespace("kube-system", ""),
		upNamespace("meshed", "enabled"),
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	emulateEviction(cs)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("static cordon held the mutex — remediation must not defer")
	}
}

// The kured reboot lock is the second mutex signal — honored like
// every other caller of the shared check.
func TestUnmeshedRemediationKuredLockDefers(t *testing.T) {
	kured := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kured",
			Annotations: map[string]string{
				"weave.works/kured-node-lock": "node-42"}},
	}
	cs := fake.NewSimpleClientset(kured,
		upNamespace("kube-system", ""),
		upNamespace("meshed", "enabled"),
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted while kured holds the reboot lock")
	}
}

// With a real dyn wired the full mutex runs: an in-flight autopilot
// Plan (state neither Schedulable nor Completed) defers remediation
// even when no node is cordoned.
func TestUnmeshedRemediationAutopilotPlanDefers(t *testing.T) {
	plan := testutil.Unstructured(
		kube.AutopilotPlanGVR.GroupVersion().WithKind("Plan"), "", "upgrade-1", nil)
	_ = unstructured.SetNestedField(plan.Object, "Running", "status", "state")
	dyn := wgDyn(plan)
	cs := upSeed(
		upNamespace("linkerd", ""),
		upInjectorCfg(), upReadySlice(),
		upPod("meshed", "web-a"))
	a := &Auditor{}
	g := &guardstate.Guard{CS: cs, Dyn: dyn, Now: time.Now}
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if !upPodExists(t, cs, "meshed", "web-a") {
		t.Fatal("pod deleted while an autopilot plan is in flight")
	}
}

// ---------------------------------------------------------------------------
// W15-CP0 — heartbeat-resource audit + critical-ns auto-patch.
// ---------------------------------------------------------------------------

// cpValidatingHook builds a fail-closed validating webhook entry with
// an optional namespaceSelector and one admission rule carrying
// resources (nil/empty resources = no rules at all).
func cpValidatingHook(name string, sel *metav1.LabelSelector,
	fp admissionv1.FailurePolicyType, resources []string) admissionv1.ValidatingWebhook {
	w := admissionv1.ValidatingWebhook{
		Name:          name,
		FailurePolicy: ptr.To(fp),
		ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
	}
	if sel != nil {
		w.NamespaceSelector = sel
	}
	if len(resources) > 0 {
		w.Rules = []admissionv1.RuleWithOperations{{
			Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
			Rule: admissionv1.Rule{
				APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: resources,
			},
		}}
	}
	return w
}

func cpFullExclusion() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   slices.Clone(criticalSelfHealingNamespaces),
		}},
	}
}

// Kube-node-lease joined the critical self-healing set (W15-CP0): an
// exclusion covering only the pre-W15 trio still matches the node
// heartbeat namespace and must flag; the full four-namespace exclusion
// must not.
func TestCriticalNSAuditCoversKubeNodeLease(t *testing.T) {
	oldTrio := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"kube-system", "node-ops", "medik8s"},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "w15-lease-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			cpValidatingHook("lease-exposed.example.com", oldTrio, admissionv1.Fail, nil),
			cpValidatingHook("lease-excluded.example.com", cpFullExclusion(), admissionv1.Fail, nil),
		},
	}
	for _, wh := range vwc.Webhooks {
		testutil.CleanupMetric(t, metrics.WebhookMissingCriticalNSExclusion,
			guardstate.KindValidating, "w15-lease-vwc", wh.Name)
	}
	cs := fake.NewSimpleClientset(upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
		guardstate.KindValidating, "w15-lease-vwc", "lease-exposed.example.com")); got != 1 {
		t.Fatalf("kube-node-lease not covered: lease-exposed = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookMissingCriticalNSExclusion.WithLabelValues(
		guardstate.KindValidating, "w15-lease-vwc", "lease-excluded.example.com")); got != 0 {
		t.Fatalf("full exclusion still flagged: %v, want 0", got)
	}
}

// Fail-closed webhooks whose rules intercept a heartbeat resource
// while their selector still matches a critical namespace emit one
// series per matched resource literal (wildcards stay wildcards);
// excluded selectors, Ignore policies and non-heartbeat resources
// emit nothing. Mutating configs audit under the mutating kind.
func TestWebhookHeartbeatResourceExposedDetection(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "w15-hb-mwc"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "eviction.example.com",
			FailurePolicy: ptr.To(admissionv1.Fail),
			ClientConfig:  admissionv1.WebhookClientConfig{Service: wgSvcRef("alive", "svc")},
			Rules: []admissionv1.RuleWithOperations{{
				Operations: []admissionv1.OperationType{admissionv1.Create},
				Rule: admissionv1.Rule{
					APIGroups: []string{""}, APIVersions: []string{"v1"},
					Resources: []string{"pods/eviction"},
				},
			}},
		}},
	}
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "w15-hb-vwc"},
		Webhooks: []admissionv1.ValidatingWebhook{
			cpValidatingHook("node-status.example.com", nil, admissionv1.Fail, []string{"nodes/status"}),
			cpValidatingHook("multi.example.com", nil, admissionv1.Fail, []string{"leases", "pods/status"}),
			cpValidatingHook("wildcard-star.example.com", nil, admissionv1.Fail, []string{"*"}),
			cpValidatingHook("wildcard-slashstar.example.com", nil, admissionv1.Fail, []string{"*/*"}),
			cpValidatingHook("excluded.example.com", cpFullExclusion(), admissionv1.Fail, []string{"leases"}),
			cpValidatingHook("ignore-policy.example.com", nil, admissionv1.Ignore, []string{"*"}),
			cpValidatingHook("innocent.example.com", nil, admissionv1.Fail, []string{"configmaps", "pods"}),
		},
	}
	cleanup := func(kind, cfg, wh, res string) {
		testutil.CleanupMetric(t, metrics.WebhookHeartbeatResourceExposed, kind, cfg, wh, res)
	}
	for _, w := range vwc.Webhooks {
		for _, r := range w.Rules {
			for _, res := range r.Resources {
				cleanup(guardstate.KindValidating, "w15-hb-vwc", w.Name, res)
			}
		}
	}
	cleanup(guardstate.KindMutating, "w15-hb-mwc", "eviction.example.com", "pods/eviction")

	cs := fake.NewSimpleClientset(
		upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), mwc, vwc)
	a, g := upGuard(cs)
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, cfg, wh, res string }{
		{guardstate.KindValidating, "w15-hb-vwc", "node-status.example.com", "nodes/status"},
		{guardstate.KindValidating, "w15-hb-vwc", "multi.example.com", "leases"},
		{guardstate.KindValidating, "w15-hb-vwc", "multi.example.com", "pods/status"},
		{guardstate.KindValidating, "w15-hb-vwc", "wildcard-star.example.com", "*"},
		{guardstate.KindValidating, "w15-hb-vwc", "wildcard-slashstar.example.com", "*/*"},
		{guardstate.KindMutating, "w15-hb-mwc", "eviction.example.com", "pods/eviction"},
	} {
		if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
			tc.kind, tc.cfg, tc.wh, tc.res)); got != 1 {
			t.Fatalf("heartbeat %s/%s/%s/%s = %v, want 1", tc.kind, tc.cfg, tc.wh, tc.res, got)
		}
	}
	for _, tc := range []struct{ kind, cfg, wh, res string }{
		// The excluded selector already rules out every critical
		// namespace — no exposure to report.
		{guardstate.KindValidating, "w15-hb-vwc", "excluded.example.com", "leases"},
		// An Ignore webhook cannot wedge admission.
		{guardstate.KindValidating, "w15-hb-vwc", "ignore-policy.example.com", "*"},
		// pods (no subresource) and configmaps are not heartbeat-path.
		{guardstate.KindValidating, "w15-hb-vwc", "innocent.example.com", "pods"},
		{guardstate.KindValidating, "w15-hb-vwc", "innocent.example.com", "configmaps"},
	} {
		if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
			tc.kind, tc.cfg, tc.wh, tc.res)); got != 0 {
			t.Fatalf("heartbeat %s/%s/%s/%s = %v, want 0", tc.kind, tc.cfg, tc.wh, tc.res, got)
		}
	}
	// Changing the offending webhook's rules prunes its stale series
	// on the next sweep.
	vwc.Webhooks[0].Rules = nil
	if _, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Update(ctx, vwc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookHeartbeatResourceExposed.WithLabelValues(
		guardstate.KindValidating, "w15-hb-vwc", "node-status.example.com", "nodes/status")); got != 0 {
		t.Fatalf("stale heartbeat series not pruned after rule change: %v", got)
	}
}

// The W15-CP0 auto-patch: off (default) touches nothing; on, it
// injects the four-namespace NotIn into every flagged fail-closed
// webhook — replacing a partial exclusion wholesale, preserving
// matchLabels — while Ignore-policy and allowlisted entries stay
// untouched.
func TestCriticalNSAutoPatch(t *testing.T) {
	newCS := func(hooks ...admissionv1.ValidatingWebhook) *fake.Clientset {
		vwc := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "w15-patch-vwc"},
			Webhooks:   hooks,
		}
		return fake.NewSimpleClientset(
			upNamespace("kube-system", ""), upNamespace("meshed", "enabled"), vwc)
	}
	fetchVWC := func(t *testing.T, cs *fake.Clientset) []admissionv1.ValidatingWebhook {
		t.Helper()
		got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Get(ctx, "w15-patch-vwc", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return got.Webhooks
	}
	hookByName := func(t *testing.T, hooks []admissionv1.ValidatingWebhook, name string) admissionv1.ValidatingWebhook {
		t.Helper()
		for _, w := range hooks {
			if w.Name == name {
				return w
			}
		}
		t.Fatalf("webhook %s vanished from the config", name)
		return admissionv1.ValidatingWebhook{}
	}
	assertNotInInjected := func(t *testing.T, w admissionv1.ValidatingWebhook) {
		t.Helper()
		sel := w.NamespaceSelector
		if sel == nil || len(sel.MatchExpressions) != 1 {
			t.Fatalf("webhook %s missing the injected NotIn selector: %+v", w.Name, sel)
		}
		expr := sel.MatchExpressions[0]
		if expr.Key != "kubernetes.io/metadata.name" || expr.Operator != metav1.LabelSelectorOpNotIn {
			t.Fatalf("webhook %s wrong expression: %+v", w.Name, expr)
		}
		got := map[string]bool{}
		for _, v := range expr.Values {
			got[v] = true
		}
		for _, ns := range criticalSelfHealingNamespaces {
			if !got[ns] {
				t.Fatalf("webhook %s NotIn missing %s: %v", w.Name, ns, expr.Values)
			}
		}
	}

	t.Run("off by default — config untouched", func(t *testing.T) {
		cs := newCS(cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil))
		a, g := upGuard(cs)
		if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if w := hookByName(t, fetchVWC(t, cs), "matchall.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("namespaceSelector patched with the gate off: %+v", w.NamespaceSelector)
		}
	})

	t.Run("explicit false — config untouched", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "false")
		cs := newCS(cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil))
		a, g := upGuard(cs)
		if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if w := hookByName(t, fetchVWC(t, cs), "matchall.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("namespaceSelector patched with the gate false: %+v", w.NamespaceSelector)
		}
	})

	t.Run("on — exclusion injected, partial replaced, matchLabels preserved", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		pinnedToSystem := &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}
		partial := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"kube-system"},
			}},
		}
		cs := newCS(
			cpValidatingHook("matchall.example.com", nil, admissionv1.Fail, nil),
			cpValidatingHook("pinned.example.com", pinnedToSystem, admissionv1.Fail, nil),
			cpValidatingHook("partial.example.com", partial, admissionv1.Fail, nil),
			cpValidatingHook("ignore.example.com", nil, admissionv1.Ignore, nil),
		)
		a, g := upGuard(cs)
		if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		hooks := fetchVWC(t, cs)
		assertNotInInjected(t, hookByName(t, hooks, "matchall.example.com"))
		assertNotInInjected(t, hookByName(t, hooks, "partial.example.com"))
		pinned := hookByName(t, hooks, "pinned.example.com")
		assertNotInInjected(t, pinned)
		if pinned.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "kube-system" {
			t.Fatalf("matchLabels clobbered by the patch: %+v", pinned.NamespaceSelector)
		}
		if w := hookByName(t, hooks, "ignore.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("Ignore-policy webhook patched: %+v", w.NamespaceSelector)
		}
	})

	t.Run("allowlisted entry untouched", func(t *testing.T) {
		t.Setenv("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", "true")
		criticalNSPatchAllowlist["w15-patch-vwc/keep.example.com"] = true
		t.Cleanup(func() { delete(criticalNSPatchAllowlist, "w15-patch-vwc/keep.example.com") })
		cs := newCS(cpValidatingHook("keep.example.com", nil, admissionv1.Fail, nil))
		a, g := upGuard(cs)
		if err := a.Sweep(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if w := hookByName(t, fetchVWC(t, cs), "keep.example.com"); w.NamespaceSelector != nil {
			t.Fatalf("allowlisted webhook patched: %+v", w.NamespaceSelector)
		}
	})
}
