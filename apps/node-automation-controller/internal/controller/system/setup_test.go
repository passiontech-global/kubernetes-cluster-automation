// setup_test.go — registration coverage for the system-component
// patcher/watchdog modules' Setup* functions.
package system

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
)

// Every AddPeriodic-based module must register its shell-operator
// queue name with the crontab-equivalent interval — the pairing is
// what keeps metrics/alerts compatible with the old hook names.
func TestSetupPeriodicModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name     string
		interval time.Duration
		setup    func(manager.Manager) error
	}{
		{"coredns-stale-watchdog", time.Minute,
			func(m manager.Manager) error { return SetupCoreDNSWatchdog(m, cs) }},
		{"cf-tunnel-proxy-watchdog", 5 * time.Minute,
			func(m manager.Manager) error {
				return SetupCFTunnelProxyWatchdog(m, cs, true,
					"cloudflare-tunnel-system", 5*time.Minute)
			}},
		{"statefulset-ondelete-roller", 10 * time.Minute,
			func(m manager.Manager) error {
				return SetupStatefulSetOnDeleteRoller(m, cs, true)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			testutil.ExpectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}

// The ported patcher/watchdog modules skip mgr.Add entirely when
// disabled — no informer, no RequeueAfter loop.
func TestSetupFeatureFlagVariants(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
	}{
		{"coredns-patcher", func(m manager.Manager) error {
			return SetupCoreDNSPatcher(m, cs, false, "DoNotSchedule", 2, 4, 1)
		}},
		{"metrics-server-patcher", func(m manager.Manager) error {
			return SetupMetricsServerPatcher(m, cs, false, 3, 1)
		}},
		{"cf-tunnel-proxy-watchdog", func(m manager.Manager) error {
			return SetupCFTunnelProxyWatchdog(m, cs, false,
				"cloudflare-tunnel-system", 5*time.Minute)
		}},
		{"fluent-bit-config-roller", func(m manager.Manager) error {
			return SetupFluentBitRoller(m, cs, false)
		}},
		{"statefulset-ondelete-roller", func(m manager.Manager) error {
			return SetupStatefulSetOnDeleteRoller(m, cs, false)
		}},
	} {
		t.Run(tc.name+"-disabled", func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("disabled setup must return nil, got %v", err)
			}
			if len(m.Added) != 0 {
				t.Fatalf("disabled module registered %d runnables, want 0",
					len(m.Added))
			}
		})
	}
}

// Builder-based modules: .Complete() resolves the For() GVK via the
// real scheme, builds a controller through controller.New and lands it
// in mgr.Add — assert exactly one runnable per Setup.
func TestSetupBuilderModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
	}{
		{"konnectivity-patcher", func(m manager.Manager) error {
			return SetupKonnectivityPatcher(m, cs)
		}},
		{"coredns-patcher", func(m manager.Manager) error {
			return SetupCoreDNSPatcher(m, cs, true, "DoNotSchedule", 2, 4, 1)
		}},
		{"metrics-server-patcher", func(m manager.Manager) error {
			return SetupMetricsServerPatcher(m, cs, true, 3, 1)
		}},
		{"fluent-bit-config-roller", func(m manager.Manager) error {
			return SetupFluentBitRoller(m, cs, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if len(m.Added) != 1 {
				t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
			}
		})
	}
}

// The konnectivity-patcher predicate pins ns/name on top of the
// field-selected informer — belt-and-suspenders against cache misses.
func TestSetupKonnectivityPatcherPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return SetupKonnectivityPatcher(m, fake.NewSimpleClientset())
	})
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "konnectivity-agent"}}
	if !p.Create(event.CreateEvent{Object: ds}) {
		t.Fatal("konnectivity-agent DS did not pass the predicate")
	}
	other := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "kube-proxy"}}
	if p.Create(event.CreateEvent{Object: other}) {
		t.Fatal("unrelated DS passed the predicate")
	}
	wrongNS := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "konnectivity-agent"}}
	if p.Create(event.CreateEvent{Object: wrongNS}) {
		t.Fatal("wrong-namespace DS passed the predicate")
	}
}

// The fluent-bit roller predicate pins the pipeline secret.
func TestSetupFluentBitRollerPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return SetupFluentBitRoller(m, fake.NewSimpleClientset(), true)
	})
	pipeline := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "fluent-system", Name: "passiontech-pipeline"}}
	if !p.Create(event.CreateEvent{Object: pipeline}) {
		t.Fatal("pipeline secret did not pass the predicate")
	}
	other := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "fluent-system", Name: "other"}}
	if p.Create(event.CreateEvent{Object: other}) {
		t.Fatal("unrelated secret passed the predicate")
	}
}
