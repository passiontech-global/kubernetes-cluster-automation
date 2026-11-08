// cilium_internal_test.go — package-internal coverage for the
// unexported cilium helpers the external cilium_test suites can only
// reach through full Cycles: the WireGuard peer-count parser, the
// Ready-node fallback count, the BPF service-map desync detector and
// its EndpointSlice readiness source, plus the envoy xDS reject
// parser (exported, kept beside its package peers).
package cilium

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// cDeps builds a minimal *wdeps.Deps over the shared fixture — the
// same construction workerhygiene.New does, minus the parent
// package (importing it here would cycle).
func cDeps(t *testing.T, objs ...runtime.Object) (*wdeps.Deps, *wdepstest.Fixture) {
	t.Helper()
	f := wdepstest.New(t, objs...)
	cfg := f.Cfg
	cfg.ApplyDefaults()
	d := &wdeps.Deps{
		Cfg:  cfg,
		Proc: procfs.New(cfg.ProcRoot),
		State: subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
			cfg.Seams.Host.Clock,
			func() *slog.Logger {
				return slog.New(slog.NewTextHandler(io.Discard, nil))
			}),
	}
	d.Cycles, d.Actions = subframe.Counters("cilium-test",
		"test cycles", "test actions")
	f.Bind(d)
	return d, f
}

func readyNode(name string, labels map[string]string, ready bool) *corev1.Node {
	cond := corev1.NodeCondition{
		Type:   corev1.NodeReady,
		Status: corev1.ConditionFalse,
	}
	if ready {
		cond.Status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{cond}},
	}
}

func TestParseCiliumEncryptPeers(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want int
		ok   bool
	}{
		"json nested":     {out: `{"status":{"encryption":{"num-peers":5}}}`, want: 5, ok: true},
		"json snake":      {out: `{"num_peers":3}`, want: 3, ok: true},
		"json largest":    {out: `{"interfaces":[{"num-peers":2},{"num-peers":7}]}`, want: 7, ok: true},
		"json no field":   {out: `{"mode":"disabled"}`, want: 0, ok: false},
		"text numPeers":   {out: "Decryption: 1\nNumPeers: 4\n", want: 4, ok: true},
		"text num_peers=": {out: "num_peers=2\n", want: 2, ok: true},
		"text absent":     {out: "encryption: disabled\n", want: 0, ok: false},
		"garbage":         {out: "", want: 0, ok: false},
	} {
		got, ok := ParseCiliumEncryptPeers(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%s: ParseCiliumEncryptPeers=%d,%v want %d,%v",
				name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestReadyNodeCountFiltersVirtualAndControlPlane(t *testing.T) {
	d, _ := cDeps(t,
		readyNode("w1", nil, true),
		readyNode("w2", nil, false),
		readyNode("cp", map[string]string{
			"node-role.kubernetes.io/control-plane": "true"}, true),
		readyNode("liqo", map[string]string{"liqo.io/type": "virtual-node"}, true),
		readyNode("vk", map[string]string{"virtual-kubelet.io/provider": "azure"}, true),
		readyNode("vk2", map[string]string{"type": "virtual-kubelet"}, true),
	)
	if got := readyNodeCount(d, context.Background()); got != 1 {
		t.Fatalf("readyNodeCount=%d want 1 (only w1)", got)
	}
}

func TestServiceReadyEndpoints(t *testing.T) {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns-abc",
			Namespace: "kube-system",
			Labels:    map[string]string{endpointSliceServiceLabel: "kube-dns"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
			{Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}},
			{}, // nil Ready defaults ready
		},
	}
	d, _ := cDeps(t, slice)
	ctx := context.Background()
	c := &CiliumLRPCheck{d: d}
	ready, ok := c.serviceReadyEndpoints(ctx, "kube-system", "kube-dns")
	if !ok || ready != 2 {
		t.Fatalf("slice path ready=%d ok=%v want 2,true", ready, ok)
	}

	// Fallback: no slices → the legacy corev1.Endpoints object.
	d2, _ := cDeps(t, sliceFallbackEndpoints())
	c2 := &CiliumLRPCheck{d: d2}
	ready, ok = c2.serviceReadyEndpoints(ctx, "default", "kubernetes")
	if !ok || ready != 3 {
		t.Fatalf("endpoints fallback ready=%d ok=%v want 3,true", ready, ok)
	}

	// Unreadable: neither slices nor Endpoints exist.
	d3, _ := cDeps(t)
	c3 := &CiliumLRPCheck{d: d3}
	if ready, ok = c3.serviceReadyEndpoints(ctx, "x", "gone"); ok || ready != 0 {
		t.Fatalf("unreadable ready=%d ok=%v want 0,false", ready, ok)
	}
}

func sliceFallbackEndpoints() *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
		Subsets: []corev1.EndpointSubset{
			{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}, {IP: "10.0.0.2"}}},
			{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.3"}}},
		},
	}
}

func TestServiceDesyncStreakAndReset(t *testing.T) {
	ctx := context.Background()
	// Both services synced: ready endpoints in the apiserver AND
	// backends in the BPF map.
	d, f := cDeps(t, dnsReadySlice())
	f.SvcBackends = map[string]int{
		"kube-system/kube-dns": 2,
		"default/kubernetes":   1,
	}
	c := NewCiliumLRP(d)
	e := &wdeps.CycleEnv{APIOK: true}

	if c.serviceDesync(ctx, e, nil) {
		t.Fatal("no desync evidence must return false")
	}
	// Flip kube-dns to 0 backends — first desync cycle is still
	// inside the streak-pending window (no agent kill attempted).
	f.SvcBackends = map[string]int{"default/kubernetes": 1, "kube-system/kube-dns": 0}
	if !c.serviceDesync(ctx, e, nil) {
		t.Fatal("desynced map must report true (caller skips nld section)")
	}
	// Reset: backends appear → streak cleared.
	f.SvcBackends = map[string]int{"kube-system/kube-dns": 2}
	if c.serviceDesync(ctx, e, nil) {
		t.Fatal("synced map must return false")
	}

	// Unreadable agent map — inconclusive, false.
	f.SvcErr = context.DeadlineExceeded
	if c.serviceDesync(ctx, e, nil) {
		t.Fatal("unreadable map must be inconclusive (false)")
	}
}

func dnsReadySlice() *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns-abc",
			Namespace: "kube-system",
			Labels:    map[string]string{endpointSliceServiceLabel: "kube-dns"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
		},
	}
}

func TestParseEnvoyXDSRejected(t *testing.T) {
	body := []byte(strings.Join([]string{
		"cluster.upstream_cx_total: 5",
		"cluster.cds.update_rejected: 3",
		"listener_manager.lds.update_rejected: 2",
		"cluster_manager.rds.update_rejected: 1",
		"cluster.update_rejected: 9", // no cds/lds/rds segment — excluded
		"cds.update_attempted: 100",  // not a rejected counter
		"listener_manager.lds.update_rejected: 4",
	}, "\n"))
	if got := ParseEnvoyXDSRejected(body); got != 10 {
		t.Fatalf("ParseEnvoyXDSRejected=%d want 10", got)
	}
	if got := ParseEnvoyXDSRejected(nil); got != 0 {
		t.Fatalf("empty body=%d want 0", got)
	}
}
