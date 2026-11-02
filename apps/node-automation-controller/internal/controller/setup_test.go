// setup_test.go — registration coverage for every Setup* function.
//
// Modules register in two shapes:
//   - addPeriodic: a *periodic runnable carrying the legacy
//     shell-operator queue name + crontab interval (metrics contract).
//   - ctrl.NewControllerManagedBy: a builder that resolves the For()
//     GVK against mgr.GetScheme() and lands a real controller in
//     mgr.Add via controller.New.
//
// stubManager captures what both shapes Add without needing envtest:
// source.TypedKind only stores the cache until Start (never invoked),
// so nil cache/client/mapper are safe, but the scheme MUST be real —
// apiutil.GVKForObject is resolved at build time.
package controller

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

var _ manager.Manager = (*stubManager)(nil)

// stubManager is the minimal manager.Manager for Setup coverage: Add
// appends to `added` (addErr injects a registration failure), and only
// GetScheme/GetControllerOptions/GetLogger return anything meaningful
// because those are the only getters the builder and addPeriodic call.
type stubManager struct {
	added  []manager.Runnable
	addErr error
	scheme *runtime.Scheme
}

func newStubManager() *stubManager {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return &stubManager{scheme: scheme}
}

func (m *stubManager) Add(r manager.Runnable) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.added = append(m.added, r)
	return nil
}

// GetControllerOptions disables the process-global controller-name
// uniqueness check — enabled/disabled variants of the same module are
// built in one test binary, which would otherwise collide.
func (m *stubManager) GetControllerOptions() config.Controller {
	return config.Controller{SkipNameValidation: ptr.To(true)}
}

func (m *stubManager) GetScheme() *runtime.Scheme                      { return m.scheme }
func (m *stubManager) GetLogger() logr.Logger                          { return logr.Discard() }
func (m *stubManager) GetCache() cache.Cache                           { return nil }
func (m *stubManager) GetClient() client.Client                        { return nil }
func (m *stubManager) GetFieldIndexer() client.FieldIndexer            { return nil }
func (m *stubManager) GetRESTMapper() meta.RESTMapper                  { return nil }
func (m *stubManager) GetAPIReader() client.Reader                     { return nil }
func (m *stubManager) GetHTTPClient() *http.Client                     { return nil }
func (m *stubManager) GetConfig() *rest.Config                         { return nil }
func (m *stubManager) GetEventRecorderFor(string) record.EventRecorder { return nil }
func (m *stubManager) GetEventRecorder(string) recorder.EventRecorder  { return nil }
func (m *stubManager) GetWebhookServer() webhook.Server                { return nil }
func (m *stubManager) GetConverterRegistry() conversion.Registry       { return nil }
func (m *stubManager) Start(context.Context) error                     { return nil }
func (m *stubManager) Elected() <-chan struct{}                        { return nil }
func (m *stubManager) AddHealthzCheck(string, healthz.Checker) error   { return nil }
func (m *stubManager) AddReadyzCheck(string, healthz.Checker) error    { return nil }

func (m *stubManager) AddMetricsServerExtraHandler(string, http.Handler) error {
	return nil
}

// stubDyn is an empty dynamic fake — Setup only stores dyn on the
// reconciler struct, it never issues calls.
func stubDyn() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
}

// expectPeriodic asserts exactly one runnable was registered and that
// it is the *periodic carrying the legacy queue name + interval.
func expectPeriodic(t *testing.T, m *stubManager, name string, interval time.Duration) {
	t.Helper()
	if len(m.added) != 1 {
		t.Fatalf("expected exactly 1 registered runnable, got %d", len(m.added))
	}
	p, ok := m.added[0].(*periodic)
	if !ok {
		t.Fatalf("registered runnable is %T, want *periodic", m.added[0])
	}
	if p.name != name {
		t.Fatalf("periodic name = %q, want %q", p.name, name)
	}
	if p.interval != interval {
		t.Fatalf("periodic interval = %s, want %s", p.interval, interval)
	}
	if p.fn == nil {
		t.Fatal("periodic registered with nil fn")
	}
}

// Every addPeriodic-based module must register its shell-operator
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
		{"kubelet-liveness-reaper", 2 * time.Minute,
			func(m manager.Manager) error { return SetupKubeletReaper(m, cs) }},
		{"admission-webhook-guard", 5 * time.Minute,
			func(m manager.Manager) error { return SetupWebhookGuard(m, cs) }},
		{"partition-pod-evictor", 5 * time.Minute,
			func(m manager.Manager) error { return SetupPartitionEvictor(m, cs) }},
		{"failed-jobs-janitor", 60 * time.Minute,
			func(m manager.Manager) error { return SetupFailedJobsJanitor(m, cs) }},
		{"dead-node-sweeper", 5 * time.Minute,
			func(m manager.Manager) error { return SetupDeadNodeSweeper(m, cs, stubDyn()) }},
		{"helmrelease-unlocker", 10 * time.Minute,
			func(m manager.Manager) error { return SetupHelmReleaseUnlocker(m, cs, stubDyn()) }},
		{"evicted-pod-janitor", 10 * time.Minute,
			func(m manager.Manager) error { return SetupEvictedPodJanitor(m, cs) }},
		{"cronjob-catchup", 15 * time.Minute,
			func(m manager.Manager) error { return SetupCronJobCatchup(m, cs) }},
		{"externalsecret-nudge", 10 * time.Minute,
			func(m manager.Manager) error {
				return SetupExternalSecretNudge(m, cs, stubDyn(), true)
			}},
		{"csr-watcher", 10 * time.Minute,
			func(m manager.Manager) error { return SetupCSRWatcher(m, cs, true) }},
		{"certmanager-reaper", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupCertManagerReaper(m, cs, stubDyn(), true)
			}},
		{"cilium-identity-auditor", 15 * time.Minute,
			func(m manager.Manager) error {
				return SetupCiliumIdentityAuditor(m, cs, stubDyn(), true)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			expectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}

// Feature flags split in two: externalsecret-nudge and csr-watcher
// register unconditionally (the flag only gates the tick body, like
// the bash exit-early at the top of the hook), while certmanager-reaper
// and cilium-identity-auditor skip mgr.Add entirely when disabled.
func TestSetupFeatureFlagVariants(t *testing.T) {
	cs := fake.NewSimpleClientset()

	m := newStubManager()
	if err := SetupExternalSecretNudge(m, cs, stubDyn(), false); err != nil {
		t.Fatalf("disabled nudge setup: %v", err)
	}
	expectPeriodic(t, m, "externalsecret-nudge", 10*time.Minute)

	m = newStubManager()
	if err := SetupCSRWatcher(m, cs, false); err != nil {
		t.Fatalf("detect-only csr setup: %v", err)
	}
	expectPeriodic(t, m, "csr-watcher", 10*time.Minute)

	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
	}{
		{"certmanager-reaper", func(m manager.Manager) error {
			return SetupCertManagerReaper(m, cs, stubDyn(), false)
		}},
		{"cilium-identity-auditor", func(m manager.Manager) error {
			return SetupCiliumIdentityAuditor(m, cs, stubDyn(), false)
		}},
	} {
		t.Run(tc.name+"-disabled", func(t *testing.T) {
			m := newStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("disabled setup must return nil, got %v", err)
			}
			if len(m.added) != 0 {
				t.Fatalf("disabled module registered %d runnables, want 0",
					len(m.added))
			}
		})
	}
}

// The endpoint guard is a plain Runnable (not addPeriodic) — assert
// its constructor wiring survived: probe seam, backends streak map.
func TestSetupAPIServerEndpointGuard(t *testing.T) {
	cs := fake.NewSimpleClientset()
	m := newStubManager()
	if err := SetupAPIServerEndpointGuard(m, cs); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.added) != 1 {
		t.Fatalf("expected 1 runnable, got %d", len(m.added))
	}
	g, ok := m.added[0].(*apiServerEndpointGuard)
	if !ok {
		t.Fatalf("runnable is %T, want *apiServerEndpointGuard", m.added[0])
	}
	if g.backends == nil {
		t.Fatal("backends streak map not initialized")
	}
	if g.probeFn == nil {
		t.Fatal("probeFn seam not wired to g.probe")
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
		{"descheduler-storm-gate", func(m manager.Manager) error {
			return SetupDeschedulerStormGate(m, cs)
		}},
		{"node-labeler", func(m manager.Manager) error {
			return SetupNodeLabeler(m, cs, "labels.txt")
		}},
		{"fluent-bit-config-roller", func(m manager.Manager) error {
			return SetupFluentBitRoller(m, cs, true)
		}},
		{"fluent-bit-config-roller-disabled", func(m manager.Manager) error {
			return SetupFluentBitRoller(m, cs, false)
		}},
		{"converge-trigger", func(m manager.Manager) error {
			return SetupConvergeTrigger(m, cs)
		}},
		// enabled adds a second source (.Watches on cilium Pods) —
		// still one controller runnable.
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, cs, true)
		}},
		{"cilium-taint-reaper-disabled", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, cs, false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if len(m.added) != 1 {
				t.Fatalf("builder registered %d runnables, want 1", len(m.added))
			}
		})
	}
}

// A manager.Add failure must propagate through addPeriodic so cmd/
// can abort boot instead of silently losing a module.
func TestSetupAddErrorPropagates(t *testing.T) {
	want := errors.New("manager rejected runnable")
	m := newStubManager()
	m.addErr = want
	if err := SetupKubeletReaper(m, fake.NewSimpleClientset()); !errors.Is(err, want) {
		t.Fatalf("Add error = %v, want %v", err, want)
	}
}
