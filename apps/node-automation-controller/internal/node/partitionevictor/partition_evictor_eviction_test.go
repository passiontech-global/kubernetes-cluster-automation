// partition_evictor_eviction_test.go — the eviction pass: per-run
// caps, the namespace allow-list and opt-in annotation, UID-
// preconditioned policy/v1 evictions, tolerated errors and PDB
// refusal deferrals.
package partitionevictor

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// The eviction cap bounds churn at partitionEvictCap (8) pods per run:
// with 9 flux-system pods on the flagged node exactly 8 are deleted.
func TestPartitionEvictorEvictionCap(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := range partitionEvictCap + 1 {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
	remaining, err := cs.CoreV1().Pods(partitionPodNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 1 {
		t.Fatalf("expected exactly 1 survivor after cap=%d, got %d: %v",
			partitionEvictCap, len(remaining.Items), remaining.Items)
	}
}

// Pods outside flux-system on a flagged node are never evicted, while
// the flux-system pod on the same node is.
func TestPartitionEvictorLeavesOtherNamespaces(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "ClusterNetworkProblems", 30*time.Minute),
		pePod("flux-system", "p1", "victim"),
		pePod("default", "p1", "unrelated"),
		pePod("monitoring", "p1", "prom-agent"),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("flux-system pod on flagged node not evicted")
	}
	for _, p := range [][2]string{{"default", "unrelated"}, {"monitoring", "prom-agent"}} {
		if !testutil.PodExistsStrict(t, cs, p[0], p[1]) {
			t.Fatalf("pod %s/%s outside %s must not be evicted", p[0], p[1], partitionPodNS)
		}
	}
}

// The eviction cap bounds pod churn, never fencing: when the first
// flagged node alone exhausts partitionEvictCap, every OTHER flagged
// node must still be tainted in the same run (previously a cap-break
// skipped their taint until the next cycle).
func TestPartitionEvictorTaintsAllFlaggedBeforeCap(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePartitionedNode("p2", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 3)...) // 2/5 flagged < 50%
	for i := range partitionEvictCap + 1 {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	objs = append(objs, pePod("flux-system", "p2", "pod-p2"))
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		if !kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s left untainted by the eviction cap", name)
		}
	}
	// The cap still held: p1's 9 pods shed exactly cap victims and
	// p2's pod never got a turn this run.
	if !testutil.PodExistsStrict(t, cs, "flux-system", "pod-p2") {
		t.Fatal("cap broke — p2's pod was evicted")
	}
}

// The eviction carries a UID precondition in its DeleteOptions — a
// same-named pod recreated after the list must never be killed in
// the victim's place. It must also travel through the policy/v1
// pods/eviction subresource, not a raw pod Delete: the apiserver
// enforces PodDisruptionBudgets on the subresource only.
func TestPartitionEvictorEvictsViaPolicyV1WithUIDPrecondition(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	victim := pePod("flux-system", "p1", "victim")
	victim.UID = "uid-victim-123"
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		victim,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	var subresource string
	var got *metav1.Preconditions
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok && ca.GetSubresource() == "eviction" {
				subresource = ca.GetSubresource()
				got = ca.GetObject().(*policyv1.Eviction).DeleteOptions.Preconditions
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if subresource != "eviction" {
		t.Fatalf("eviction traveled as subresource %q, want pods/eviction", subresource)
	}
	if got == nil || got.UID == nil || *got.UID != victim.UID {
		t.Fatalf("eviction missing UID precondition, got %+v", got)
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod still exists — eviction never landed")
	}
}

// A failing eviction (non-429, non-NotFound API error) is tolerated
// (logged, counted) — the run must not error, the pod stays and the
// taint is still applied.
func TestPartitionEvictorEvictionErrorTolerated(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "undeletable"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok && ca.GetSubresource() == "eviction" {
				return true, nil, errors.New("apiserver wedged")
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("an eviction failure must not error the run: %v", err)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "undeletable") {
		t.Fatal("pod evicted despite the failing eviction call")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
}

// A NotFound eviction is already the goal state (another actor
// finished the eviction first) — tolerated without error accounting,
// the run continues and the taint still lands.
func TestPartitionEvictorNotFoundEvictionTolerated(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "already-gone"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok && ca.GetSubresource() == "eviction" {
				return true, nil, apierrors.NewNotFound(
					corev1.Resource("pods"), "already-gone")
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("a NotFound eviction must not error the run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
}

// A failed partition taint is logged ("taint failed") and the node
// is excluded from the pod sweep — without the NoSchedule fence
// landed, evicted pods would reschedule straight back onto the
// blackholed host.
func TestPartitionEvictorTaintErrorSkipsPodEviction(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append(
		[]runtime.Object{
			pePartitionedNode("p1", "ClusterNetworkProblems", 20*time.Minute),
			pePod("flux-system", "p1", "src-ctrl"),
		},
		peHealthyNodes("h", 3)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("taint failure must not fail the run: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("taint applied despite the rejected patch")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off an unfenced node — no taint, no eviction")
	}
}

// ---------------------------------------------------------------------------
// QW3 — PARTITION_EVICT_NAMESPACES allow-list + opt-in annotation.
// ---------------------------------------------------------------------------

// partitionEvictNamespaces: unset and whitespace-only values keep the
// bash default (flux-system); a real value REPLACES it — the flag is
// an allow-list, not an append-list.
func TestPartitionEvictNamespacesParsing(t *testing.T) {
	// Unset: save + clear the ambient value so the default branch is
	// deterministic regardless of the shell the test runs under.
	if old, had := os.LookupEnv(partitionNSsEnv); had {
		t.Cleanup(func() { _ = os.Setenv(partitionNSsEnv, old) })
	}
	if err := os.Unsetenv(partitionNSsEnv); err != nil {
		t.Fatal(err)
	}
	got := partitionEvictNamespaces()
	if len(got) != 1 || !nsSetHas(got, partitionPodNS) {
		t.Fatalf("unset env produced %v, want {%s}", got, partitionPodNS)
	}

	// Whitespace-only is the same as unset — a ConfigMap value of
	// " " must not become a namespace named " ".
	t.Setenv(partitionNSsEnv, "   ")
	got = partitionEvictNamespaces()
	if len(got) != 1 || !nsSetHas(got, partitionPodNS) {
		t.Fatalf("whitespace env produced %v, want {%s}", got, partitionPodNS)
	}

	// Comma-separated with stray whitespace and empty entries —
	// "a, ,b," must parse to exactly {a, b} (no phantom namespace).
	t.Setenv(partitionNSsEnv, " apps , ,monitoring,")
	got = partitionEvictNamespaces()
	if len(got) != 2 || !nsSetHas(got, "apps") || !nsSetHas(got, "monitoring") {
		t.Fatalf("env ' apps , ,monitoring,' produced %v, want {apps monitoring}", got)
	}
	if nsSetHas(got, partitionPodNS) {
		t.Fatal("explicit allow-list must replace the flux-system default")
	}
}

func nsSetHas(set map[string]struct{}, ns string) bool {
	_, ok := set[ns]
	return ok
}

// A pod carrying passiontech.dev/evict-on-partition=true in an UNLISTED
// namespace is evicted off the flagged node; an identical unannotated
// pod in the same namespace is left alone.
func TestPartitionEvictorAnnotatedPodInUnlistedNamespace(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	optedIn := pePod("apps", "p1", "webhook-svc")
	optedIn.Annotations = map[string]string{partitionEvictAnno: "true"}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		optedIn,
		pePod("apps", "p1", "unannotated"),
		pePod("flux-system", "p1", "listed-victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if testutil.PodExistsStrict(t, cs, "apps", "webhook-svc") {
		t.Fatal("annotated pod in unlisted namespace not evicted")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "listed-victim") {
		t.Fatal("listed-namespace pod not evicted")
	}
	if !testutil.PodExistsStrict(t, cs, "apps", "unannotated") {
		t.Fatal("unannotated pod in unlisted namespace evicted — annotation leaked")
	}
}

// The annotation opts IN the pod, it never overrides the safety
// classes: terminal pods, DaemonSet pods and static mirror pods are
// skipped even when annotated.
func TestPartitionEvictorAnnotationSkipsProtectedPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	anno := map[string]string{partitionEvictAnno: "true"}

	terminal := pePod("flux-system", "p1", "done-job")
	terminal.Status.Phase = corev1.PodSucceeded
	terminal.Annotations = anno

	failed := pePod("flux-system", "p1", "crashed")
	failed.Status.Phase = corev1.PodFailed
	failed.Annotations = anno

	ds := pePod("flux-system", "p1", "daemon-xyz")
	ds.Annotations = anno
	ds.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "DaemonSet", Name: "daemon", UID: "u1",
	}}

	mirror := pePod("flux-system", "p1", "static-etcd")
	mirror.Annotations = map[string]string{
		partitionEvictAnno: "true",
		mirrorPodAnno:      "0123456789abcdef",
	}

	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		terminal, failed, ds, mirror,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"done-job", "crashed", "daemon-xyz", "static-etcd"} {
		if !testutil.PodExistsStrict(t, cs, "flux-system", name) {
			t.Fatalf("protected pod flux-system/%s was evicted", name)
		}
	}
}

// The cap is global per run — annotated pods from other namespaces
// share the same budget as allow-listed pods: 5 listed + 5 annotated
// must still stop at partitionEvictCap deletions.
func TestPartitionEvictorCapCoversAnnotatedPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := range 5 {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("listed-%02d", i)))
	}
	for i := range 5 {
		p := pePod("apps", "p1", fmt.Sprintf("opted-%02d", i))
		p.Annotations = map[string]string{partitionEvictAnno: "true"}
		objs = append(objs, p)
	}
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for _, ns := range []string{"flux-system", "apps"} {
		l, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		remaining += len(l.Items)
	}
	if want := 10 - partitionEvictCap; remaining != want {
		t.Fatalf("cap not respected across membership classes: %d pods left, want %d", remaining, want)
	}
}

// An explicit allow-list REPLACES the flux-system default — with
// PARTITION_EVICT_NAMESPACES=monitoring a flux-system pod is left
// alone while the monitoring pod is evicted.
func TestPartitionEvictorEnvAllowListReplacesDefault(t *testing.T) {
	t.Setenv(partitionNSsEnv, "monitoring, logging")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "no-longer-listed"),
		pePod("monitoring", "p1", "prom-victim"),
		pePod("logging", "p1", "fluent-victim"),
		pePod("default", "p1", "still-unlisted"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"monitoring", "prom-victim"}, {"logging", "fluent-victim"}} {
		if testutil.PodExistsStrict(t, cs, p[0], p[1]) {
			t.Fatalf("listed-namespace pod %s/%s not evicted", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{"flux-system", "no-longer-listed"}, {"default", "still-unlisted"}} {
		if !testutil.PodExistsStrict(t, cs, p[0], p[1]) {
			t.Fatalf("unlisted-namespace pod %s/%s evicted", p[0], p[1])
		}
	}
}

// ---------------------------------------------------------------------------
// evictNamespaces — the Setup-stamped allow-list and its lazy fallback.
// ---------------------------------------------------------------------------

// A literally-built fixture with a nil namespaces field resolves the
// env allow-list lazily instead of silently evicting nothing; a
// stamped field is passed through untouched (env ignored).
func TestPartitionEvictorEvictNamespacesLazyFallbackAndPassThrough(t *testing.T) {
	t.Setenv(partitionNSsEnv, " apps ,monitoring ")

	// Stamped field wins — env drift must not redefine Setup's list.
	stamped := &partitionEvictor{namespaces: map[string]struct{}{"stamped": {}}}
	got := stamped.evictNamespaces()
	if len(got) != 1 || !nsSetHas(got, "stamped") {
		t.Fatalf("stamped allow-list not passed through: got %v", got)
	}

	// Nil field falls back to the env parse.
	lazy := &partitionEvictor{}
	got = lazy.evictNamespaces()
	if !nsSetHas(got, "apps") || !nsSetHas(got, "monitoring") {
		t.Fatalf("nil-field fallback ignored PARTITION_EVICT_NAMESPACES: got %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("env parse produced phantom namespaces: %v", got)
	}
}

// ---------------------------------------------------------------------------
// policy/v1 eviction — PDB refusal semantics (deferral, no cap, no error).
// ---------------------------------------------------------------------------

// A PDB with disruptionsAllowed==0 refuses the eviction (HTTP 429) —
// a deferral, never a failure: every pod on the flagged node is still
// ATTEMPTED (a refusal must not consume the per-sweep cap — an
// attempt that made no progress must not starve the victims behind
// it), no pod is deleted, nothing is metered (no IncError), and the
// run stays nil.
func TestPartitionEvictorPDBRefusalDefersWithoutCapOrError(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := range partitionEvictCap + 1 {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	attempts := 0
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok && ca.GetSubresource() == "eviction" {
				attempts++
				return true, nil, apierrors.NewTooManyRequests(
					"Too many disruptions", 0)
			}
			return false, nil, nil
		})
	before := testutil.QueueErrorCount(t, "partition-pod-evictor")
	e := &partitionEvictor{cs: cs, queue: "partition-pod-evictor"}
	if err := e.run(ctx); err != nil {
		t.Fatalf("PDB refusals must not error the run: %v", err)
	}
	if attempts != partitionEvictCap+1 {
		t.Fatalf("eviction attempts = %d, want all %d — a refusal consumed the cap",
			attempts, partitionEvictCap+1)
	}
	for i := range partitionEvictCap + 1 {
		if !testutil.PodExistsStrict(t, cs, "flux-system", fmt.Sprintf("pod-%02d", i)) {
			t.Fatalf("pod-%02d was deleted despite the 429 refusal", i)
		}
	}
	if got := testutil.QueueErrorCount(t, "partition-pod-evictor") - before; got != 0 {
		t.Fatalf("PDB refusal metered %v errors — a deferral counts no error", got)
	}
}

// A fenced node hosting only non-evictable pods (e.g. an unlisted
// namespace without the opt-in annotation) never calls heal.Gate and
// spends zero fleet budget tokens.
func TestPartitionEvictorNoEligiblePodSpendsNoBudget(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("unlisted-ns", "p1", "stay-put"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs, dyn: testutil.NewDynamicClient()}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, testutil.NewDynamicClient(), "probe", time.Now())
	if !proceed || unverifiable {
		t.Fatalf("partition sweep with 0 eligible pods spent a budget token: Gate = (%v,%v)",
			proceed, unverifiable)
	}
}
