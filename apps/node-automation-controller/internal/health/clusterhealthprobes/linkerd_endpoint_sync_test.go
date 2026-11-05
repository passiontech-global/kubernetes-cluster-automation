// linkerd_endpoint_sync_test.go — coverage for the
// linkerd-endpoint-sync check (W9-NM2/W10-FIX7): healthy/desync
// census, oldest-destination bounce, gauge cleanup, and the
// stale-EndpointSlice delete selection.
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// W9-NM2 — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// Synced headless service: Ready pod IP == Ready EndpointSlice
// address — the check passes and no gauge series appears.
func TestCheckLinkerdEndpointSyncHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		headlessService("app", "headless-svc", map[string]string{"app": "x"}),
		readyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		endpointSliceForService("app", "headless-svc", "10.244.0.5"),
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("synced endpoints must pass: %+v", res)
	}
	if m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge emitted on a synced service")
	}
}

// Namespaces without linkerd.io/inject=enabled are never audited.
func TestCheckLinkerdEndpointSyncSkipsUninjected(t *testing.T) {
	plain := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}
	cs := fake.NewSimpleClientset(
		plain,
		headlessService("plain", "headless-svc", map[string]string{"app": "x"}),
		readyPodWithIP("plain", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// No EndpointSlice at all — would desync if audited.
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("uninjected namespace must pass: %+v", res)
	}
}

// A desynced headless service fails only after the 10m persistence
// window; past it the gauge fires and the OLDEST linkerd-destination
// pod is bounced.
func TestCheckLinkerdEndpointSyncDesyncHeal(t *testing.T) {
	base := time.Now()
	older := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-old-111",
			UID:               types.UID("u-old"),
			CreationTimestamp: metav1.NewTime(base.Add(-2 * time.Hour)),
		},
	}
	newer := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-new-222",
			UID:               types.UID("u-new"),
			CreationTimestamp: metav1.NewTime(base.Add(-time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("app"),
		headlessService("app", "headless-svc", map[string]string{"app": "x"}),
		readyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// EndpointSlice holds a stale IP — the Ready pod IP is missing.
		endpointSliceForService("app", "headless-svc", "10.244.0.9"),
		older, newer,
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	// First sighting: tracked, still passing.
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("first-seen desync must pass: %+v", res)
	}
	// Inside the window: still quiet.
	p.now = func() time.Time { return base.Add(5 * time.Minute) }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("desync inside window must pass: %+v", res)
	}
	// Past the window: FAIL + gauge + oldest destination pod gone.
	at := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	p.now = func() time.Time { return at }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("desync gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, older.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("oldest linkerd-destination pod not bounced")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, newer.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("newer linkerd-destination pod bounced — not oldest-first")
	}

	// Inside the 1h per-service cooldown the newer pod survives even
	// though the desync persists.
	p.now = func() time.Time { return at.Add(30 * time.Minute) }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); res.pass {
		t.Fatal("persisted desync stopped failing inside cooldown")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
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
		headlessService("app", "headless-svc", map[string]string{"app": "x"}),
		readyPodWithIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		endpointSliceForService("app", "headless-svc", "10.244.0.9"), // stale
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); res.pass {
		t.Fatal("persisted desync did not fail")
	}
	// EndpointSlice resyncs — the tuple must drop off /metrics.
	if err := cs.DiscoveryV1().EndpointSlices("app").Delete(ctx,
		"headless-svc-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	cs.DiscoveryV1().EndpointSlices("app").Create(ctx,
		endpointSliceForService("app", "headless-svc", "10.244.0.5"), metav1.CreateOptions{})
	p.now = func() time.Time { return base.Add(2*linkerdEndpointDesyncMinAge + time.Minute) }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("resynced service must pass: %+v", res)
	}
	if m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge not cleared after resync")
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
// W10-FIX7 — stale EndpointSlice deletion inside linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// A managed EndpointSlice missing a >3m-Ready pod IP is deleted once
// the desync survives the window — endpointslice-controller rebuilds
// it — and the destination pod still gets its bounce.
func TestLinkerdEndpointSyncDeletesSliceMissingReadyIP(t *testing.T) {
	base := time.Now()
	slice := managedEndpointSlice("desyncapp", "desync-svc") // empty — misses the Ready pod IP
	dest := linkerdDestinationPod(linkerdDestinationName+"-aaa-111", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		headlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := driveEndpointDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("stale EndpointSlice missing a Ready pod IP not deleted")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
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
	dest := linkerdDestinationPod(linkerdDestinationName+"-bbb-222", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		headlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := driveEndpointDesync(t, p, base); res.pass {
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
		headlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice,
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := mustCheck[*linkerdEndpointSyncCheck](t, p).run(ctx); !res.pass {
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
	dest := linkerdDestinationPod(linkerdDestinationName+"-ccc-333", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		headlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
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
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := driveEndpointDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("slice deleted for a pod still inside the Ready fuse")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced")
	}
}

// Only endpointslice-controller-owned slices are delete candidates —
// a stale slice without the managed-by label (mirror/third-party)
// survives; the destination bounce still runs.
func TestLinkerdEndpointSyncKeepsNonManagedSlice(t *testing.T) {
	base := time.Now()
	slice := endpointSliceForService("desyncapp", "desync-svc", "10.244.0.9") // stale, no managed-by
	dest := linkerdDestinationPod(linkerdDestinationName+"-ddd-444", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		linkerdInjectedNamespace("desyncapp"),
		headlessService("desyncapp", "desync-svc", map[string]string{"desyncapp": "x"}),
		readyPodIPSince("desyncapp", "pod-0", "10.244.0.5",
			map[string]string{"desyncapp": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		readyWorkerNode("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := driveEndpointDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("desyncapp").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-managed EndpointSlice deleted — not ours to reap")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced")
	}
}
