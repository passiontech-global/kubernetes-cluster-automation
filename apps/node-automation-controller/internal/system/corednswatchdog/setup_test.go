// setup_test.go — registration coverage for the coredns-stale-watchdog module's
// Setup function.
package corednswatchdog

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

type stubMgrWithClient struct {
	manager.Manager
	c client.Client
}

func (s stubMgrWithClient) GetClient() client.Client { return s.c }

type spyPodClient struct {
	client.Client
	podLists int
}

func (s *spyPodClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok {
		s.podLists++
	}
	return nil
}

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names.
func TestSetupRegistersPeriodic(t *testing.T) {
	testutil.PeriodicContract(t, Setup, shared.Deps{
		Name: "coredns-stale-watchdog",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}, "coredns-stale-watchdog", time.Minute)
}

func TestSetupKubeSystemPodInformerGate(t *testing.T) {
	defer kube.SetKubeSystemPodInformerEnabled(true)

	t.Run("disabled sets podReader nil while keeping nodeReader and uses direct cs", func(t *testing.T) {
		kube.SetKubeSystemPodInformerEnabled(false)
		sc := &spyPodClient{}
		m := &stubMgrWithClient{Manager: testutil.NewStubManager(), c: sc}
		cs := fake.NewSimpleClientset()
		var directPodLists int
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			directPodLists++
			return true, nil, errors.New("abort after direct pod list")
		})
		d := shared.Deps{Name: "coredns-stale-watchdog", Mgr: m, CS: cs, Dyn: testutil.StubDyn()}
		w := newCoreDNSWatchdog(d)
		if w.nodeReader == nil {
			t.Fatal("expected nodeReader to remain wired")
		}
		if w.podReader != nil {
			t.Fatalf("expected podReader == nil when kube-system pod informer disabled, got %v", w.podReader)
		}

		sm := testutil.NewStubManager()
		m2 := &stubMgrWithClient{Manager: sm, c: sc}
		if err := Setup(shared.Deps{Name: "coredns-stale-watchdog", Mgr: m2, CS: cs, Dyn: testutil.StubDyn()}); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		p := sm.Added[0].(*shared.Periodic)
		if err := p.Fn(t.Context()); err != nil {
			t.Fatalf("Periodic.Fn: %v", err)
		}
		if sc.podLists != 0 {
			t.Fatalf("cached client Pod List called %d times, want 0", sc.podLists)
		}
		if directPodLists != 1 {
			t.Fatalf("direct cs Pod List called %d times, want 1", directPodLists)
		}
	})

	t.Run("enabled wires podReader to cached client", func(t *testing.T) {
		kube.SetKubeSystemPodInformerEnabled(true)
		sc := &spyPodClient{}
		m := &stubMgrWithClient{Manager: testutil.NewStubManager(), c: sc}
		d := shared.Deps{Name: "coredns-stale-watchdog", Mgr: m, CS: fake.NewSimpleClientset(), Dyn: testutil.StubDyn()}
		w := newCoreDNSWatchdog(d)
		if w.nodeReader == nil || w.podReader == nil {
			t.Fatalf("expected both nodeReader and podReader wired, got node=%v pod=%v", w.nodeReader, w.podReader)
		}
	})
}
