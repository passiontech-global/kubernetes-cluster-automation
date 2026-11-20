package cilium_test

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCiliumLRPAllDiscoveryAPIErrorsPreserveSvcFails(t *testing.T) {
	e := lrpFixture(t, kubeDNSSlice(true))
	e.SvcBackends = map[string]int{"kube-system/kube-dns": 0}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return true }
	e.H.Cfg.Seams.Probe.DNSProbeTCP = func(context.Context, string, string, time.Duration) bool { return true }

	var failDiscovery atomic.Bool
	e.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failDiscovery.Load() {
			return true, nil, errors.New("apiserver timeout")
		}
		return false, nil, nil
	})
	e.CS.PrependReactor("get", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failDiscovery.Load() {
			return true, nil, errors.New("apiserver timeout")
		}
		return false, nil, nil
	})

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*nldPod("node-local-dns-abc12", wdepstest.UIDA)},
	}

	// Cycle 1: kube-dns desync -> svcFails = 1 (no kill yet).
	lrpRun(t, e, ce)
	if len(e.Kills) != 0 {
		t.Fatalf("killed agent on cycle 1: %+v", e.Kills)
	}

	// Cycle 2: all EndpointSlices/Endpoints calls fail while e.APIOK=true -> svcFails preserved at 1.
	failDiscovery.Store(true)
	lrpRun(t, e, ce)
	if len(e.Kills) != 0 {
		t.Fatalf("unexpected kill during discovery outage: %+v", e.Kills)
	}

	// Cycle 3: discovery recovers with 0 backends -> svcFails reaches 2 and kills cilium-agent.
	failDiscovery.Store(false)
	lrpRun(t, e, ce)
	if len(e.Kills) != 1 || e.Kills[0].PID != 4343 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("kills=%+v want SIGKILL pid 4343 on preserved streak=2", e.Kills)
	}
}

func TestCiliumLRPNilClientDoesNotPanic(t *testing.T) {
	e := lrpFixture(t)
	e.H.Cfg.Client = nil
	e.SvcBackends = map[string]int{"kube-system/kube-dns": 0}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return true }
	e.H.Cfg.Seams.Probe.DNSProbeTCP = func(context.Context, string, string, time.Duration) bool { return true }
	lrpRun(t, e, &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*nldPod("node-local-dns-abc12", wdepstest.UIDA)},
	})
}

func TestCiliumIPAMEmptyIPV4ObjectAbortsPreservesLatch(t *testing.T) {
	used, avail, ok := cilium.ParseCiliumIPAM([]byte(`{"ipam":{"ipv4":{}}}`))
	if ok || used != 0 || avail != -1 {
		t.Fatalf("ParseCiliumIPAM(empty ipv4) = (%d,%d,%v), want (0,-1,false)", used, avail, ok)
	}

	e := fixture(t)
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchCiliumIPAMExhausted) {
		t.Fatal("setup: LatchCiliumIPAMExhausted not armed")
	}

	// Empty ipv4 object must abort and preserve Fails, gauges, and latch.
	e.UnixBody = []byte(`{"ipam":{"ipv4":{}}}`)
	chk := wdepstest.Check[*cilium.CiliumIPAMCheck](e.H, wdeps.CheckCiliumIPAM)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumIPAM, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumIPAMExhausted) {
		t.Fatal("LatchCiliumIPAMExhausted falsely exited on empty ipam.ipv4 object")
	}
	if got := testutil.ToFloat64(e.H.CiliumAllocated); got != 40 {
		t.Fatalf("CiliumAllocated=%v want preserved 40", got)
	}
	if got := testutil.ToFloat64(e.H.CiliumLeaked); got != 40 {
		t.Fatalf("CiliumLeaked=%v want preserved 40", got)
	}

	// Valid healthy payload exits latch cleanly.
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":1,"available":100}}}`)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if e.H.State.Exists(latchdefs.LatchCiliumIPAMExhausted) {
		t.Fatal("LatchCiliumIPAMExhausted did not exit on healthy payload")
	}
}
