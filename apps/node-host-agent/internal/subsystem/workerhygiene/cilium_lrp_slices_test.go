// cilium_lrp_slices_test.go — W12/P0-5: the cilium-lrp serviceDesync
// ready-endpoint count now reads discovery.k8s.io/v1 EndpointSlices
// (the source cilium-agent programs the BPF map from), falling back
// to the deprecated corev1.Endpoints object only when the slice LIST
// errors or returns nothing.

package workerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// lrpSliceFixture prepares the desync-test environment on an
// existing fixture: the cilium datapath present, a live
// cilium-agent task, and a BPF service map claiming 0 backends for
// kube-dns while kubernetes has 1.
func lrpSliceFixture(t *testing.T, f *env) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(f.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.MkProc(t, 4343, "S", "", "")
	f.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	f.SvcBackends = map[string]int{
		"kube-system/kube-dns": 0, // desynced if apiserver says ready
		"default/kubernetes":   1,
	}
}

func kubeDNSSlice(ready *bool) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-dns-x7k2",
			Namespace: "kube-system",
			Labels: map[string]string{
				"kubernetes.io/service-name": "kube-dns",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.244.1.7"},
			Conditions: discoveryv1.EndpointConditions{Ready: ready},
		}},
	}
}

func agentKilled(e *env, pid int) bool {
	for _, k := range e.Kills {
		if k.PID == pid && k.Sig == syscall.SIGKILL {
			return true
		}
	}
	return false
}

// EndpointSlice is the PRIMARY source: a ready endpoint in the
// slice plus a 0-backend BPF entry desyncs exactly like the old
// Endpoints read did.
func TestCheckCiliumLRPDesyncViaEndpointSlices(t *testing.T) {
	e := fixture(t, kubeDNSSlice(ptr.To(true)))
	lrpSliceFixture(t, e)
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if agentKilled(e, 4343) {
		t.Fatal("agent killed before ConsecNeeded desync cycles")
	}
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if !agentKilled(e, 4343) {
		t.Fatal("agent not killed on slice-confirmed desync")
	}
}

// A slice that EXISTS but carries only not-ready endpoints is a
// real "0 ready" verdict — the check must NOT fall back to the
// possibly-stale Endpoints object (which still lists addresses here
// to prove the slice wins).
func TestCheckCiliumLRPSliceNotReadyNoDesync(t *testing.T) {
	e := fixture(t,
		kubeDNSSlice(ptr.To(false)), // slice says NOT ready
		&corev1.Endpoints{ // stale object claims a ready address
			ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
			Subsets: []corev1.EndpointSubset{{
				Addresses: []corev1.EndpointAddress{{IP: "10.244.1.7"}},
			}},
		})
	lrpSliceFixture(t, e)
	for i := 0; i < 3; i++ {
		wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
			APIOK: true, WorkerActive: true})
	}
	if agentKilled(e, 4343) {
		t.Fatal("agent killed though the slice reported 0 ready endpoints")
	}
}

// Nil Ready defaults to ready — an endpoint without the condition
// still counts (k8s semantics).
func TestCheckCiliumLRPSliceNilReadyCounts(t *testing.T) {
	e := fixture(t, kubeDNSSlice(nil))
	lrpSliceFixture(t, e)
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if !agentKilled(e, 4343) {
		t.Fatal("nil-Ready endpoint not counted as ready")
	}
}

// No slices at all → the deprecated Endpoints object is the
// fallback source (the pre-migration path, kept for clusters that
// still terminate it).
func TestCheckCiliumLRPDesyncEndpointsFallback(t *testing.T) {
	e := fixture(t, &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: "10.244.1.7"}},
		}},
	})
	lrpSliceFixture(t, e)
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if !agentKilled(e, 4343) {
		t.Fatal("endpoints fallback not honoured — no desync kill")
	}
}
