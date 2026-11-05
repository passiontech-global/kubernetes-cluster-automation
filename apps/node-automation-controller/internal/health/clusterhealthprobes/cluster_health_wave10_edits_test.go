// cluster_health_wave10_edits_test.go — coverage for the Wave-10
// edits in cluster_health_wave8.go: W10-FIX7 stale-EndpointSlice
// deletion in linkerd-endpoint-sync and the W10-KR6 nodeHangConds
// expansion (KubeletRuntimeStall/KubeletWatchWedge/PodTeardownWedged/
// InodePressure join the pre-cordon latch set).
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// Builders (wave10-prefixed)
// ---------------------------------------------------------------------------

// wave10ReadyPodIPAt builds a Running+Ready pod whose PodReady
// LastTransitionTime is the explicit `readySince` — the EndpointSlice
// heal's missing-IP fuse (linkerdSliceHealMinAge) reads that clock,
// and tests need Ready ages both inside and outside it.
func wave10ReadyPodIPAt(ns, name, ip string, lbls map[string]string,
	readySince time.Time) *corev1.Pod {
	p := w9ReadyPodIP(ns, name, ip, lbls)
	p.Status.Conditions[0].LastTransitionTime = metav1.NewTime(readySince)
	return p
}

// wave10ManagedSlice builds an EndpointSlice carrying the
// managed-by=endpointslice-controller.k8s.io label — the only slice
// kind the desync heal deletes (KCM recreates those; mirror and
// third-party slices are left alone).
func wave10ManagedSlice(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := w9EndpointSlice(ns, svc, addrs...)
	s.Labels[discoveryv1.LabelManagedBy] = linkerdSliceManagedByESC
	return s
}

// wave10DestPod builds a linkerd-destination pod — the bounce target
// the heal picks (oldest match wins; one per test suffices).
func wave10DestPod(name string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace:         linkerdNS,
		Name:              name,
		UID:               types.UID("uid-" + name),
		CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}}
}

// wave10DriveDesync runs the check at base, inside the window, and
// past it — the same three-sweep shape as
// TestCheckLinkerdEndpointSyncDesyncHeal — returning the final
// probeResult.
func wave10DriveDesync(t *testing.T, p *clusterHealthProber, base time.Time) probeResult {
	t.Helper()
	p.now = func() time.Time { return base }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(5 * time.Minute) }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	return p.checkLinkerdEndpointSync(ctx)
}

// ---------------------------------------------------------------------------
// staleLinkerdSlices — pure selection logic
// ---------------------------------------------------------------------------

func TestWave10StaleLinkerdSlices(t *testing.T) {
	live := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	// .1 Ready past the fuse; .2 Ready but inside it (not in aged).
	aged := map[string]bool{"10.0.0.1": true}
	s1 := linkerdSliceRef{ns: "w10app", name: "svc-a",
		addrs: map[string]bool{"10.0.0.1": true}}
	s2 := linkerdSliceRef{ns: "w10app", name: "svc-b",
		addrs: map[string]bool{"10.0.0.9": true}} // dead IP — no live pod owns it
	s3 := linkerdSliceRef{ns: "w10app", name: "svc-c",
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
func TestWave10LinkerdEndpointSyncDeletesSliceMissingReadyIP(t *testing.T) {
	base := time.Now()
	slice := wave10ManagedSlice("w10app", "w10-svc") // empty — misses the Ready pod IP
	dest := wave10DestPod(linkerdDestinationName+"-aaa-111", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("w10app"),
		w9HeadlessSvc("w10app", "w10-svc", map[string]string{"w10app": "x"}),
		wave10ReadyPodIPAt("w10app", "pod-0", "10.244.0.5",
			map[string]string{"w10app": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := wave10DriveDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("w10app").
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
func TestWave10LinkerdEndpointSyncDeletesSliceWithDeadIP(t *testing.T) {
	base := time.Now()
	slice := wave10ManagedSlice("w10app", "w10-svc",
		"10.244.0.5", "10.244.0.9") // .9 belongs to a pod that no longer exists
	dest := wave10DestPod(linkerdDestinationName+"-bbb-222", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("w10app"),
		w9HeadlessSvc("w10app", "w10-svc", map[string]string{"w10app": "x"}),
		wave10ReadyPodIPAt("w10app", "pod-0", "10.244.0.5",
			map[string]string{"w10app": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := wave10DriveDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("w10app").
		Get(ctx, slice.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("EndpointSlice retaining a dead IP not deleted")
	}
}

// A synced headless service passes and its managed slice is left
// untouched — the delete path only fires on proven staleness.
func TestWave10LinkerdEndpointSyncKeepsHealthySlice(t *testing.T) {
	base := time.Now()
	slice := wave10ManagedSlice("w10app", "w10-svc", "10.244.0.5")
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("w10app"),
		w9HeadlessSvc("w10app", "w10-svc", map[string]string{"w10app": "x"}),
		wave10ReadyPodIPAt("w10app", "pod-0", "10.244.0.5",
			map[string]string{"w10app": "x"}, base.Add(-10*time.Minute)),
		slice,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("synced endpoints must pass: %+v", res)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("w10app").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("healthy EndpointSlice deleted")
	}
}

// A pod IP missing from the slices inside linkerdSliceHealMinAge is
// propagation lag, not staleness — the slice survives while the
// destination pod still bounces (the desync itself is real).
func TestWave10LinkerdEndpointSyncKeepsSliceInsideReadyFuse(t *testing.T) {
	base := time.Now()
	slice := wave10ManagedSlice("w10app", "w10-svc", "10.244.0.5")
	dest := wave10DestPod(linkerdDestinationName+"-ccc-333", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("w10app"),
		w9HeadlessSvc("w10app", "w10-svc", map[string]string{"w10app": "x"}),
		// pod-old: Ready well past the fuse, IP present in the slice.
		wave10ReadyPodIPAt("w10app", "pod-old", "10.244.0.5",
			map[string]string{"w10app": "x"}, base.Add(-time.Hour)),
		// pod-new: Ready=True but its LastTransitionTime lands 9m
		// after base — at heal time (base+11m) it is only ~2m Ready,
		// inside linkerdSliceHealMinAge, so its absence from the
		// slice must NOT mark the slice stale.
		wave10ReadyPodIPAt("w10app", "pod-new", "10.244.0.6",
			map[string]string{"w10app": "x"}, base.Add(9*time.Minute)),
		slice, dest,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := wave10DriveDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("w10app").
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
func TestWave10LinkerdEndpointSyncKeepsNonManagedSlice(t *testing.T) {
	base := time.Now()
	slice := w9EndpointSlice("w10app", "w10-svc", "10.244.0.9") // stale, no managed-by
	dest := wave10DestPod(linkerdDestinationName+"-ddd-444", 2*time.Hour)
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("w10app"),
		w9HeadlessSvc("w10app", "w10-svc", map[string]string{"w10app": "x"}),
		wave10ReadyPodIPAt("w10app", "pod-0", "10.244.0.5",
			map[string]string{"w10app": "x"}, base.Add(-10*time.Minute)),
		slice, dest,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := wave10DriveDesync(t, p, base); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("w10app").
		Get(ctx, slice.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-managed EndpointSlice deleted — not ours to reap")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, dest.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("linkerd-destination pod not bounced")
	}
}

// ---------------------------------------------------------------------------
// W10-KR6 — nodeHangConds expansion
// ---------------------------------------------------------------------------

// Every Wave-10 latch in nodeHangConds cordons a worker once True for
// >= nodeHangCondMinAge — same fuse as the original two.
func TestWave10NodeHangPreCordonNewLatches(t *testing.T) {
	for i, cond := range []corev1.NodeConditionType{
		"KubeletRuntimeStall", "KubeletWatchWedge",
		"PodTeardownWedged", "InodePressure",
	} {
		name := "w-" + string(rune('a'+i))
		cs := fake.NewSimpleClientset(
			w8Worker(name, cond, 5*time.Minute, false),
			w8Worker("w-ok-"+string(rune('a'+i)), "", 0, false))
		p := testProberDyn(cs, shOpDyn())
		if res := p.checkNodeHangPreCordon(ctx); res.pass {
			t.Fatalf("%s latch did not fail the check", cond)
		}
		n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !n.Spec.Unschedulable {
			t.Fatalf("%s node not cordoned", cond)
		}
		if got := n.Annotations[nodeHangPreCordonAnno]; got != nodeHangPreCordonValue {
			t.Fatalf("%s cordon missing pre-cordon stamp: %q", cond, got)
		}
	}
}
