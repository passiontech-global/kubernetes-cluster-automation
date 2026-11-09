// linkerd_endpoint_sync_test.go — coverage for the
// linkerd-endpoint-sync check (netns-endpoint-sync/endpoint-sync-heal): healthy/desync
// census, oldest-destination bounce, gauge cleanup, and the
// stale-EndpointSlice delete selection.
package linkerd

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// netns-endpoint-sync — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// Synced headless service: Ready pod IP == Ready EndpointSlice
// address — the check passes and no gauge series appears.
func TestCheckLinkerdEndpointSyncHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.5"),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("synced endpoints must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge emitted on a synced service")
	}
}

// Namespaces without linkerd.io/inject=enabled are never audited.
func TestCheckLinkerdEndpointSyncSkipsUninjected(t *testing.T) {
	plain := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}
	cs := fake.NewSimpleClientset(
		plain,
		probetest.HeadlessService("plain", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("plain", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// No EndpointSlice at all — would desync if audited.
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("uninjected namespace must pass: %+v", res)
	}
}

// A desynced headless service fails only after the 10m persistence
// window; past it the gauge fires and the OLDEST linkerd-destination
// pod is bounced.
func TestCheckLinkerdEndpointSyncDesyncHeal(t *testing.T) {
	base := time.Now()
	older := linkerdDestinationPod(kube.LinkerdDestinationName+"-old-111", 2*time.Hour)
	newer := linkerdDestinationPod(kube.LinkerdDestinationName+"-new-222", time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// EndpointSlice holds a stale IP — the Ready pod IP is missing.
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9"),
		older, newer,
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// First sighting: tracked, still passing.
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen desync must pass: %+v", res)
	}
	// Inside the window: still quiet.
	p.Now = func() time.Time { return base.Add(5 * time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("desync inside window must pass: %+v", res)
	}
	// Past the window: FAIL + gauge + oldest destination pod gone.
	at := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("desync gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, older.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("oldest linkerd-destination pod not bounced")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, newer.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("newer linkerd-destination pod bounced — not oldest-first")
	}

	// Inside the 1h per-service cooldown the newer pod survives even
	// though the desync persists.
	p.Now = func() time.Time { return at.Add(30 * time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync stopped failing inside cooldown")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, newer.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("linkerd-destination bounced inside the 1h cooldown")
	}
}

// A resolved desync clears the gauge series instead of leaking a
// stale 1.
func TestCheckLinkerdEndpointSyncResyncClears(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9"), // stale
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync did not fail")
	}
	// EndpointSlice resyncs — the tuple must drop off /metrics.
	if err := cs.DiscoveryV1().EndpointSlices("app").Delete(ctx,
		"headless-svc-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("app").Create(ctx,
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.5"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Now = func() time.Time { return base.Add(2*linkerdEndpointDesyncMinAge + time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("resynced service must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge not cleared after resync")
	}
}

// A single linkerd-destination replica is never bounced — the
// Ready-sibling gate refuses the delete (bouncing the last replica
// blackholes the endpoint table it is supposed to rebuild).
func TestLinkerdEndpointSyncBounceRefusedWithoutSibling(t *testing.T) {
	base := time.Now()
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-lone-111", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "lone-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "lone-svc", "10.244.0.9"),
		dest,
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(5 * time.Minute) }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync must still fail past the window")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("lone linkerd-destination pod bounced without a Ready sibling")
	}
}

// Restart-resume: a Service carrying a persisted first-seen stamp
// older than the desync window trips it on the FIRST sweep — the
// in-RAM ledger is empty (operator restarted) but the annotation
// proves the desync held continuously.
func TestCheckLinkerdEndpointSyncPersistedFirstSeenResume(t *testing.T) {
	base := time.Now()
	svc := probetest.HeadlessService("app", "resume-svc",
		map[string]string{"app": "x"})
	svc.Annotations = map[string]string{
		kube.AnnoFirstSeenLinkerdEndpointSync: `{"app/resume-svc":"` +
			base.Add(-20*time.Minute).UTC().Format(time.RFC3339) + `"}`,
	}
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-old-111", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		svc,
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// EndpointSlice holds a stale IP — the Ready pod IP is missing.
		probetest.EndpointSliceForService("app", "resume-svc", "10.244.0.9"),
		dest,
		// Ready sibling — the bounce gate requires one surviving
		// Ready replica under the destination's controller.
		linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	testutil.CleanupMetric(t, linkerdEndpointDesyncGauge, "app", "resume-svc")

	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync must fail on the first post-restart sweep")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "resume-svc"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("desync gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced on the resumed window")
	}
}

// The destination bounce gate is cooldown-ONLY — the heal's budget
// token was already granted by HealAllowedPersisted up front. With
// the whole sweep budget at ONE grant the bounce must still deliver:
// a second HealAllowed at the bounce site would find the budget spent
// and skip the delete (the double-spend this pins).
func TestLinkerdDestinationBounceSpendsOneBudgetToken(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	base := time.Now()
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-old-111", 2*time.Hour)
	sibling := linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour)
	svc := probetest.HeadlessService("app", "budget-svc", map[string]string{"app": "x"})
	svc.Annotations = map[string]string{
		kube.AnnoFirstSeenLinkerdEndpointSync: `{"app/budget-svc":"` +
			base.Add(-20*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		svc,
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// EndpointSlice holds a stale IP — the Ready pod IP is missing.
		probetest.EndpointSliceForService("app", "budget-svc", "10.244.0.9"),
		dest, sibling,
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted desync must fail")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("destination bounce must deliver on a 1-grant budget — the bounce gate spends no token of its own")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, sibling.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("only the oldest destination pod may be bounced: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bounce escalation + persisted heal stamp — a desync the managed-by
// delete can never fix must not bounce linkerd-destination forever.
// ---------------------------------------------------------------------------

// Three consecutive ineffective bounces escalate the per-service
// cooldown 1h→6h→24h and then STOP the bouncing entirely, while the
// gauge stays at 1 — the alert carries a desync no delete can fix.
func TestCheckLinkerdEndpointSyncBounceEscalatesAndStops(t *testing.T) {
	base := time.Now()
	dests := []*corev1.Pod{
		linkerdDestinationPod(kube.LinkerdDestinationName+"-a-111", 4*time.Hour),
		linkerdDestinationPod(kube.LinkerdDestinationName+"-b-222", 3*time.Hour),
		linkerdDestinationPod(kube.LinkerdDestinationName+"-c-333", 2*time.Hour),
		linkerdDestinationPod(kube.LinkerdDestinationName+"-d-444", 1*time.Hour),
	}
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// A stale slice WITHOUT the managed-by label — the heal never
		// deletes it, so the desync can never converge.
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9"),
		dests[0], dests[1], dests[2], dests[3],
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	run := func(at time.Time) probefw.Result {
		p.Now = func() time.Time { return at }
		return probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	}
	alive := func(name string) bool {
		_, err := cs.CoreV1().Pods(kube.LinkerdNS).
			Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}
	testutil.CleanupMetric(t, linkerdEndpointDesyncGauge, "app", "headless-svc")

	if res := run(base); !res.Pass {
		t.Fatalf("first-seen desync must pass: %+v", res)
	}
	// Bounce 1 — the base tier fires past the persistence window.
	b1 := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	if res := run(b1); res.Pass {
		t.Fatal("persisted desync did not fail")
	}
	if alive(dests[0].Name) {
		t.Fatal("bounce 1 did not delete the oldest destination pod")
	}
	// 2h later: the escalated 6h cooldown still suppresses bounce 2.
	if res := run(b1.Add(2 * time.Hour)); res.Pass {
		t.Fatal("desync stopped failing during the escalated cooldown")
	}
	if !alive(dests[1].Name) {
		t.Fatal("destination bounced inside the escalated 6h cooldown")
	}
	// Bounce 2 — fires only once 6h passed since bounce 1.
	b2 := b1.Add(6*time.Hour + time.Minute)
	run(b2)
	if alive(dests[1].Name) {
		t.Fatal("bounce 2 did not fire after the 6h cooldown")
	}
	if !alive(dests[2].Name) {
		t.Fatal("bounce 3 fired early — 24h cooldown not applied")
	}
	// Bounce 3 — fires only once 24h passed since bounce 2.
	b3 := b2.Add(24*time.Hour + time.Minute)
	run(b3)
	if alive(dests[2].Name) {
		t.Fatal("bounce 3 did not fire after the 24h cooldown")
	}
	if !alive(dests[3].Name) {
		t.Fatal("fourth bounce fired — the ladder must stop at three")
	}
	// Past even a fresh 24h window: the ladder is exhausted and the
	// bouncing never resumes, but the alert series stays up.
	b4 := b3.Add(24*time.Hour + time.Minute)
	if res := run(b4); res.Pass {
		t.Fatal("exhausted desync stopped failing — alert lost")
	}
	if !alive(dests[3].Name) {
		t.Fatal("bouncing resumed after the ladder was exhausted")
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("desync gauge = %v, want 1 (alert must survive the stop)", m)
	}
}

// A converged desync resets the escalation ladder: after one
// ineffective bounce, a resync followed by a FRESH desync bounces on
// the base 1h tier again — a new failure must not inherit the old
// streak.
func TestCheckLinkerdEndpointSyncConvergeResetsLadder(t *testing.T) {
	base := time.Now()
	destA := linkerdDestinationPod(kube.LinkerdDestinationName+"-a-111", 2*time.Hour)
	destB := linkerdDestinationPod(kube.LinkerdDestinationName+"-b-222", time.Hour)
	destC := linkerdDestinationPod(kube.LinkerdDestinationName+"-c-333", 30*time.Minute)
	stale := probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9")
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		stale, destA, destB, destC,
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	run := func(at time.Time) probefw.Result {
		p.Now = func() time.Time { return at }
		return probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	}
	testutil.CleanupMetric(t, linkerdEndpointDesyncGauge, "app", "headless-svc")

	// Track, then bounce 1 past the window.
	run(base)
	b1 := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	run(b1)
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, destA.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("bounce 1 did not delete the oldest destination pod")
	}
	// The slices resync — the sweep converges and must reset the
	// bounce-failure streak.
	if err := cs.DiscoveryV1().EndpointSlices("app").Delete(ctx,
		stale.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("app").Create(ctx,
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.5"),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := run(b1.Add(15 * time.Minute)); !res.Pass {
		t.Fatalf("resynced service must converge: %+v", res)
	}
	// A FRESH desync arms its own window; the heal must fire on the
	// BASE 1h tier (b1+2h clears both the window and the base
	// cooldown — a 6h escalated cooldown would still suppress it).
	if err := cs.DiscoveryV1().EndpointSlices("app").Delete(ctx,
		"headless-svc-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("app").Create(ctx,
		stale, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	run(b1.Add(16 * time.Minute))
	if res := run(b1.Add(2 * time.Hour)); res.Pass {
		t.Fatal("fresh desync did not fail past its window")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, destB.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("fresh desync did not bounce on the reset (1h) tier")
	}
}

// The bounce stamp persists on the Service: a fresh post-restart
// process reads passiontech.dev/last-linkerd-endpoint-sync-heal off
// the Service and defers the bounce inside the cooldown window with
// an empty in-RAM ledger — then bounces once the window clears.
func TestCheckLinkerdEndpointSyncHealStampSurvivesRestart(t *testing.T) {
	base := time.Now()
	destA := linkerdDestinationPod(kube.LinkerdDestinationName+"-a-111", 2*time.Hour)
	destB := linkerdDestinationPod(kube.LinkerdDestinationName+"-b-222", time.Hour)
	testutil.CleanupMetric(t, linkerdEndpointDesyncGauge, "app", "headless-svc")

	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		probetest.HeadlessService("app", "headless-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9"), // stale
		destA,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-a-222", time.Hour), // Ready sibling for the bounce gate
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	at := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	p.Now = func() time.Time { return at }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, destA.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("bounce did not delete the destination pod")
	}
	svc, err := cs.CoreV1().Services("app").
		Get(ctx, "headless-svc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stamp, ok := kube.AnnoTime(svc, linkerdDestHealAnno)
	if !ok {
		t.Fatalf("service missing %s stamp", linkerdDestHealAnno)
	}
	if stamp.Before(at.Add(-time.Minute)) || stamp.After(at.Add(time.Minute)) {
		t.Fatalf("heal stamp = %v, want ~%v (RFC3339 on the Service)", stamp, at)
	}

	// Restart: a fresh check against the same cluster objects — the
	// Service carries BOTH persisted stamps (first-seen + heal), so
	// the annotation alone suppresses the bounce inside the window.
	svcPatched, err := cs.CoreV1().Services("app").
		Get(ctx, "headless-svc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cs2 := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"), svcPatched,
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "headless-svc", "10.244.0.9"), // stale
		destB,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-b-333", 30*time.Minute), // Ready sibling for the bounce gate
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p2 := testProberDyn(cs2, probetest.OpDyn())
	p2.Now = func() time.Time { return at.Add(30 * time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p2).Run(ctx); res.Pass {
		t.Fatal("desync stopped failing across the restart")
	}
	if _, err := cs2.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, destB.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("post-restart bounce ignored the persisted Service stamp")
	}
	// Past the window the bounce resumes — at the BASE tier, since a
	// fresh process starts the ladder from zero.
	p2.Now = func() time.Time { return at.Add(2 * time.Hour) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p2).Run(ctx); res.Pass {
		t.Fatal("desync stopped failing after the stamp expired")
	}
	if _, err := cs2.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, destB.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("bounce did not resume after the persisted stamp expired")
	}
}

// ---------------------------------------------------------------------------
// staleLinkerdSlices — pure selection logic
// ---------------------------------------------------------------------------

func TestStaleLinkerdSlices(t *testing.T) {
	live := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	// .1 Ready past the fuse; .2 Ready but inside it (not in aged).
	aged := map[string]bool{"10.0.0.1": true}
	s1 := linkerdSliceRef{ns: "desyncapp", name: "svc-a",
		addrs: map[string]bool{"10.0.0.1": true}}
	s2 := linkerdSliceRef{ns: "desyncapp", name: "svc-b",
		addrs: map[string]bool{"10.0.0.9": true}} // dead IP — no live pod owns it
	s3 := linkerdSliceRef{ns: "desyncapp", name: "svc-c",
		addrs: map[string]bool{"10.0.0.2": true}}

	// A slice retaining a dead IP is stale on its own — only that
	// slice is returned, healthy siblings survive.
	got := staleLinkerdSlices([]linkerdSliceRef{s1, s2, s3}, aged, live)
	if len(got) != 1 || got[0].name != "svc-b" {
		t.Fatalf("dead-IP selection = %+v, want only svc-b", got)
	}

	// An aged Ready pod IP absent from the whole managed set makes
	// the SET incomplete — every managed slice is a delete candidate.
	got = staleLinkerdSlices([]linkerdSliceRef{s1, s3},
		map[string]bool{"10.0.0.7": true}, live)
	if len(got) != 2 {
		t.Fatalf("missing-IP selection = %+v, want both slices", got)
	}

	// The same absence inside the Ready fuse is propagation lag, not
	// staleness — nothing is returned.
	got = staleLinkerdSlices([]linkerdSliceRef{s1},
		map[string]bool{}, live)
	if got != nil {
		t.Fatalf("fresh-missing selection = %+v, want nil", got)
	}

	// Healthy set: union covers the aged IPs and no slice holds a
	// dead address.
	got = staleLinkerdSlices([]linkerdSliceRef{s1, s3}, aged, live)
	if got != nil {
		t.Fatalf("healthy selection = %+v, want nil", got)
	}

	// No managed slices at all — nothing to delete.
	if got := staleLinkerdSlices(nil, aged, live); got != nil {
		t.Fatalf("empty selection = %+v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// endpoint-sync-heal — stale EndpointSlice deletion inside linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// A managed EndpointSlice missing a >3m-Ready pod IP is deleted once
// the desync survives the window — endpointslice-controller rebuilds
// it — and the destination pod still gets its bounce.
func TestLinkerdEndpointSyncDeletesSliceMissingReadyIP(t *testing.T) {
	base := time.Now()
	slice := managedEndpointSlice("desyncapp", "desync-svc") // empty — misses the Ready pod IP
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-aaa-111", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		probetest.HeadlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, base); res.Pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("stale EndpointSlice missing a Ready pod IP not deleted")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced alongside slice delete")
	}
}

// A managed EndpointSlice retaining a deleted pod's Ready address is
// deleted even when the live pod IP is still present — the dead IP
// alone marks the slice stale.
func TestLinkerdEndpointSyncDeletesSliceWithDeadIP(t *testing.T) {
	base := time.Now()
	slice := managedEndpointSlice("desyncapp", "desync-svc",
		"10.244.0.5", "10.244.0.9") // .9 belongs to a pod that no longer exists
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-bbb-222", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		probetest.HeadlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, base); res.Pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("EndpointSlice retaining a dead IP not deleted")
	}
}

// A synced headless service passes and its managed slice is left
// untouched — the delete path only fires on proven staleness.
func TestLinkerdEndpointSyncKeepsHealthySlice(t *testing.T) {
	base := time.Now()
	slice := managedEndpointSlice("desyncapp", "desync-svc", "10.244.0.5")
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		probetest.HeadlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice,
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("synced endpoints must pass: %+v", res)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("healthy EndpointSlice deleted")
	}
}

// A pod IP missing from the slices inside linkerdSliceHealMinAge is
// propagation lag, not staleness — the slice survives while the
// destination pod still bounces (the desync itself is real).
func TestLinkerdEndpointSyncKeepsSliceInsideReadyFuse(t *testing.T) {
	base := time.Now()
	slice := managedEndpointSlice("desyncapp", "desync-svc", "10.244.0.5")
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-ccc-333", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		probetest.HeadlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		// pod-old: Ready well past the fuse, IP present in the slice.
		readyPodIPSince("desyncapp", "pod-old", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-time.Hour)),
		// pod-new: Ready=True but its LastTransitionTime lands 9m
		// after base — at heal time (base+11m) it is only ~2m Ready,
		// inside linkerdSliceHealMinAge, so its absence from the
		// slice must NOT mark the slice stale.
		readyPodIPSince("desyncapp", "pod-new", "10.244.0.6",
			map[string]string{"desyncapp": "x"}, base.Add(9*time.Minute)),
		slice, dest,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, base); res.Pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("slice deleted for a pod still inside the Ready fuse")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced")
	}
}

// Only endpointslice-controller-owned slices are delete candidates —
// a stale slice without the managed-by label (mirror/third-party)
// survives; the destination bounce still runs.
func TestLinkerdEndpointSyncKeepsNonManagedSlice(t *testing.T) {
	base := time.Now()
	slice := probetest.EndpointSliceForService("desyncapp", "desync-svc", "10.244.0.9") // stale, no managed-by
	dest := linkerdDestinationPod(kube.LinkerdDestinationName+"-ddd-444", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		probetest.HeadlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		linkerdDestinationPod(kube.LinkerdDestinationName+"-sib-999", time.Hour),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, base); res.Pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-managed EndpointSlice deleted — not ours to reap")
	}
	if _, err := cs.CoreV1().Pods(kube.LinkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced")
	}
}

// ---------------------------------------------------------------------------
// Widened Service census — the audit covers every selector-bearing
// Service in an injected namespace, not just headless ones.
// ---------------------------------------------------------------------------

// A non-headless ClusterIP Service in an injected namespace is audited
// the same way: a Ready pod IP missing from the EndpointSlice desyncs
// it and fails the check past the persistence window.
func TestLinkerdEndpointSyncAuditsClusterIPService(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		clusterIPService("app", "web-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.EndpointSliceForService("app", "web-svc", "10.244.0.9"), // stale IP
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, base); res.Pass {
		t.Fatal("desynced ClusterIP service did not fail the check")
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "web-svc"}); m == nil {
		t.Fatal("desync gauge missing for ClusterIP service")
	}
}

// Excluded service shapes — a desync on any of these must never
// flag, even after the persistence window would have elapsed.
func TestLinkerdEndpointSyncSkipsExcludedServices(t *testing.T) {
	externalName := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "ext-svc"},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "example.com",
			Selector:     map[string]string{"app": "x"},
		},
	}
	publishNotReady := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "pnr-svc"},
		Spec: corev1.ServiceSpec{
			ClusterIP:                "10.96.0.20",
			Selector:                 map[string]string{"app": "x"},
			PublishNotReadyAddresses: true,
		},
	}
	selectorless := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "no-sel-svc"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.30"},
	}
	for _, tc := range []struct {
		name string
		svc  *corev1.Service
	}{
		{"ExternalName", externalName},
		{"PublishNotReadyAddresses", publishNotReady},
		{"no selector", selectorless},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Now()
			cs := fake.NewSimpleClientset(
				linkerdInjectedNamespace("app"),
				tc.svc,
				// A Ready pod the selector WOULD have matched + an
				// empty managed slice — desync material if audited.
				probetest.ReadyPodWithIP("app", "pod-0", "10.244.0.5",
					map[string]string{"app": "x"}),
				probetest.ReadyWorkerNode("w1", "", 0, false))
			p := testProberDyn(cs, probetest.OpDyn())
			if res := driveEndpointDesync(t, p, base); !res.Pass {
				t.Fatalf("%s service must never be audited: %+v", tc.name, res)
			}
			if m := probetest.FindMetric(t, "node_automation_linkerd_endpoint_desync",
				map[string]string{"namespace": "app", "service": tc.svc.Name}); m != nil {
				t.Fatalf("desync gauge emitted for excluded %s service", tc.name)
			}
		})
	}
}

// A selector Service OUTSIDE an injected namespace is still skipped —
// the widened census keeps the namespace gate.
func TestLinkerdEndpointSyncSkipsClusterIPOutsideMesh(t *testing.T) {
	plain := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}
	cs := fake.NewSimpleClientset(
		plain,
		clusterIPService("plain", "web-svc", map[string]string{"app": "x"}),
		probetest.ReadyPodWithIP("plain", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := driveEndpointDesync(t, p, time.Now()); !res.Pass {
		t.Fatalf("uninjected ClusterIP service must pass: %+v", res)
	}
}

// clusterIPService builds a routable (non-headless) ClusterIP Service
// with a pod selector — the shape the widened census now audits
// alongside headless Services.
func clusterIPService(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Selector:  selector,
			Ports:     []corev1.ServicePort{{Port: 80}},
		},
	}
}

// linkerdInjectedNamespace builds a namespace opted into linkerd injection.
func linkerdInjectedNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   name,
		Labels: map[string]string{kube.LinkerdInjectKey: "enabled"},
	}}
}

// readyPodIPSince builds a Running+Ready pod whose PodReady
// LastTransitionTime is the explicit `readySince` — the EndpointSlice
// heal's missing-IP fuse (linkerdSliceHealMinAge) reads that clock,
// and tests need Ready ages both inside and outside it.
func readyPodIPSince(ns, name, ip string, lbls map[string]string,
	readySince time.Time) *corev1.Pod {
	p := probetest.ReadyPodWithIP(ns, name, ip, lbls)
	p.Status.Conditions[0].LastTransitionTime = metav1.NewTime(readySince)
	return p
}

// managedEndpointSlice builds an EndpointSlice carrying the
// managed-by=endpointslice-controller.k8s.io label — the only slice
// kind the desync heal deletes (KCM recreates those; mirror and
// third-party slices are left alone).
func managedEndpointSlice(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := probetest.EndpointSliceForService(ns, svc, addrs...)
	s.Labels[discoveryv1.LabelManagedBy] = linkerdSliceManagedByESC
	return s
}

// linkerdDestinationPod builds a Running+Ready linkerd-destination
// pod under one shared controller owner (UID "dest-ctrl") — the
// bounce target the heal picks (oldest match wins), and the shape the
// Ready-sibling bounce gate reads: any two of these pods are
// each other's Ready siblings.
func linkerdDestinationPod(name string, age time.Duration) *corev1.Pod {
	ctrl := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         kube.LinkerdNS,
			Name:              name,
			UID:               types.UID("uid-" + name),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: "linkerd-destination-rs", UID: "dest-ctrl",
				Controller: &ctrl,
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// driveEndpointDesync runs the check at base, inside the window, and
// past it — the same three-sweep shape as
// TestCheckLinkerdEndpointSyncDesyncHeal — returning the final
// probefw.Result.
func driveEndpointDesync(t *testing.T, p *probetest.Prober, base time.Time) probefw.Result {
	t.Helper()
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(5 * time.Minute) }
	probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	return probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
}

// ---------------------------------------------------------------------------
// socket-lb-vs-linkerd — Cilium socket-LB vs Linkerd compatibility audit
// ---------------------------------------------------------------------------

// ciliumConfig builds the kube-system/cilium-config ConfigMap the
// socket-LB audit reads.
func ciliumConfig(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "cilium-config"}, Data: data}
}

// linkerdNamespace is the control-plane namespace whose mere
// presence means the mesh is installed.
func linkerdNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: kube.LinkerdNS}}
}

// bpf-lb-sock on Linkerd with NEITHER compatibility knob fails the
// check and raises the conflict gauge.
func TestLinkerdSockLBConflictFlagged(t *testing.T) {
	cs := fake.NewSimpleClientset(
		linkerdNamespace(),
		ciliumConfig(map[string]string{"bpf-lb-sock": "true"}),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("socket-LB conflict must fail: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_cilium_linkerd_socklb_conflict",
		map[string]string{})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("socklb conflict gauge = %v, want 1", m)
	}
	t.Cleanup(func() { ciliumLinkerdSockLBConflictGauge.Set(0) })
}

// Either compatibility knob — cni-exclusive=false or
// bpf-lb-sock-hostns-only=true — makes the shape safe; socket-LB
// off entirely is safe too; no cilium-config means no Cilium.
func TestLinkerdSockLBSafeShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		data map[string]string
	}{
		{"cni-exclusive=false", map[string]string{
			"bpf-lb-sock": "true", "cni-exclusive": "false"}},
		{"hostns-only", map[string]string{
			"bpf-lb-sock": "true", "bpf-lb-sock-hostns-only": "true"}},
		{"socklb disabled", map[string]string{"bpf-lb-sock": "false"}},
		{"no socklb key", map[string]string{"debug": "false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(
				linkerdNamespace(),
				ciliumConfig(tc.data),
				probetest.ReadyWorkerNode("w1", "", 0, false))
			p := testProberDyn(cs, probetest.OpDyn())
			res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx)
			if !res.Pass {
				t.Fatalf("%s must pass: %+v", tc.name, res)
			}
			m := probetest.FindMetric(t,
				"node_automation_cilium_linkerd_socklb_conflict",
				map[string]string{})
			if m == nil || m.GetGauge().GetValue() != 0 {
				t.Fatalf("socklb conflict gauge = %v, want 0", m)
			}
		})
	}
}

// No Cilium ConfigMap (no Cilium) and no linkerd namespace (no mesh)
// both read as no-conflict — the conflict needs both sides present.
func TestLinkerdSockLBNoCiliumNoMesh(t *testing.T) {
	cs := fake.NewSimpleClientset(
		linkerdNamespace(),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no cilium-config must pass: %+v", res)
	}

	cs = fake.NewSimpleClientset(
		ciliumConfig(map[string]string{"bpf-lb-sock": "true"}),
		probetest.ReadyWorkerNode("w1", "", 0, false))
	p = testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*linkerdEndpointSyncCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no linkerd namespace must pass: %+v", res)
	}
}
