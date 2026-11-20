package cilium_test

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10CiliumLRPPartialServiceDiscoveryErrorPreservesSvcFails(t *testing.T) {
	k8sSvcSlice := func() *discoveryv1.EndpointSlice {
		ready := true
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kubernetes",
				Namespace: "default",
				Labels:    map[string]string{"kubernetes.io/service-name": "kubernetes"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			}},
		}
	}

	e := lrpFixture(t, kubeDNSSlice(true), k8sSvcSlice())
	e.SvcBackends = map[string]int{
		"kube-system/kube-dns": 0,
		"default/kubernetes":   1,
	}
	e.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return true }
	e.H.Cfg.Seams.Probe.DNSProbeTCP = func(context.Context, string, string, time.Duration) bool { return true }

	var failKubeSystem atomic.Bool
	e.CS.PrependReactor("list", "endpointslices", func(act k8stesting.Action) (bool, runtime.Object, error) {
		if failKubeSystem.Load() && act.GetNamespace() == "kube-system" {
			return true, nil, errors.New("kube-system endpointslices timeout")
		}
		return false, nil, nil
	})
	e.CS.PrependReactor("get", "endpoints", func(act k8stesting.Action) (bool, runtime.Object, error) {
		if failKubeSystem.Load() && act.GetNamespace() == "kube-system" {
			return true, nil, errors.New("kube-system endpoints timeout")
		}
		return false, nil, nil
	})

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*nldPod("node-local-dns-abc12", wdepstest.UIDA)},
	}

	// Cycle 1: kube-dns desync -> svcFails = 1.
	lrpRun(t, e, ce)
	if len(e.Kills) != 0 {
		t.Fatalf("killed agent on cycle 1: %+v", e.Kills)
	}

	// Cycle 2: partial discovery failure (kube-system fails, default/kubernetes succeeds healthy).
	// Must preserve svcFails=1!
	failKubeSystem.Store(true)
	lrpRun(t, e, ce)
	if len(e.Kills) != 0 {
		t.Fatalf("unexpected kill during partial discovery outage: %+v", e.Kills)
	}

	// Cycle 3: kube-system recovers still desynced -> svcFails reaches 2 and kills cilium-agent.
	failKubeSystem.Store(false)
	lrpRun(t, e, ce)
	if len(e.Kills) != 1 || e.Kills[0].PID != 4343 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("kills=%+v want SIGKILL pid 4343 after preserved svcFails=1", e.Kills)
	}

	// Healthy recovery when ALL desyncServices are readable and synced resets streak cleanly.
	e.SvcBackends["kube-system/kube-dns"] = 1
	e.Kills = nil
	e.SvcBackends["kube-system/kube-dns"] = 0
	e.H.State.RateSpend("last-cilium-restart") // suppress kill on 2nd cycle if needed
	e.H.Cfg.MinRestartInterval = 0
	// Reset to verify: 1 desync cycle -> 1 all-healthy cycle -> 1 desync cycle does NOT reach 2.
	e2 := lrpFixture(t, kubeDNSSlice(true), k8sSvcSlice())
	e2.SvcBackends = map[string]int{"kube-system/kube-dns": 0, "default/kubernetes": 1}
	e2.H.Cfg.Seams.Probe.DNSProbe = func(context.Context, string, string, time.Duration) bool { return true }
	e2.H.Cfg.Seams.Probe.DNSProbeTCP = func(context.Context, string, string, time.Duration) bool { return true }
	lrpRun(t, e2, ce) // svcFails = 1
	e2.SvcBackends["kube-system/kube-dns"] = 1
	lrpRun(t, e2, ce) // all desyncServices readable & healthy -> svcFails = 0
	e2.SvcBackends["kube-system/kube-dns"] = 0
	lrpRun(t, e2, ce) // svcFails = 1 (not 2)
	if len(e2.Kills) != 0 {
		t.Fatalf("unexpected kill=%+v; expected svcFails reset when all services healthy", e2.Kills)
	}
}
