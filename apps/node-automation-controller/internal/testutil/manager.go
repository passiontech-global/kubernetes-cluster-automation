// Package testutil holds the shared fakes and assertion helpers the
// internal/<domain>/ module tests use: a stub manager.Manager that
// captures runnable registrations (Setup coverage without envtest)
// plus small event constructors. Watch predicates and mapfuncs are
// package-level vars in each module, installed verbatim by the
// builder wiring, so tests exercise the exact units the controller
// runs instead of introspecting controller-runtime internals.
package testutil

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

var _ manager.Manager = (*StubManager)(nil)

// StubManager is the minimal manager.Manager for Setup coverage: Add
// appends to Added (AddErr injects a registration failure), and only
// GetScheme/GetControllerOptions/GetLogger return anything meaningful
// because those are the only getters the builder and AddPeriodic call.
// source.TypedKind only stores the cache until Start (never invoked),
// so nil cache/client/mapper are safe, but the scheme MUST be real —
// apiutil.GVKForObject is resolved at build time.
type StubManager struct {
	Added  []manager.Runnable
	AddErr error
	scheme *runtime.Scheme
}

func NewStubManager() *StubManager {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return &StubManager{scheme: scheme}
}

func (m *StubManager) Add(r manager.Runnable) error {
	if m.AddErr != nil {
		return m.AddErr
	}
	m.Added = append(m.Added, r)
	return nil
}

// GetControllerOptions disables the process-global controller-name
// uniqueness check — enabled/disabled variants of the same module are
// built in one test binary, which would otherwise collide.
func (m *StubManager) GetControllerOptions() config.Controller {
	return config.Controller{SkipNameValidation: ptr.To(true)}
}

func (m *StubManager) GetScheme() *runtime.Scheme                      { return m.scheme }
func (m *StubManager) GetLogger() logr.Logger                          { return logr.Discard() }
func (m *StubManager) GetCache() cache.Cache                           { return nil }
func (m *StubManager) GetClient() client.Client                        { return nil }
func (m *StubManager) GetFieldIndexer() client.FieldIndexer            { return nil }
func (m *StubManager) GetRESTMapper() meta.RESTMapper                  { return nil }
func (m *StubManager) GetAPIReader() client.Reader                     { return nil }
func (m *StubManager) GetHTTPClient() *http.Client                     { return nil }
func (m *StubManager) GetConfig() *rest.Config                         { return nil }
func (m *StubManager) GetEventRecorderFor(string) record.EventRecorder { return nil }
func (m *StubManager) GetEventRecorder(string) recorder.EventRecorder  { return nil }
func (m *StubManager) GetWebhookServer() webhook.Server                { return nil }
func (m *StubManager) GetConverterRegistry() conversion.Registry       { return nil }
func (m *StubManager) Start(context.Context) error                     { return nil }
func (m *StubManager) Elected() <-chan struct{}                        { return nil }
func (m *StubManager) AddHealthzCheck(string, healthz.Checker) error   { return nil }
func (m *StubManager) AddReadyzCheck(string, healthz.Checker) error    { return nil }

func (m *StubManager) AddMetricsServerExtraHandler(string, http.Handler) error {
	return nil
}

// StubDyn is an empty dynamic fake — Setup only stores dyn on the
// reconciler struct, it never issues calls.
func StubDyn() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
}

// ExpectPeriodic asserts exactly one runnable was registered and that
// it is the *shared.Periodic carrying the legacy queue name +
// interval.
func ExpectPeriodic(t *testing.T, m *StubManager, name string, interval time.Duration) {
	t.Helper()
	if len(m.Added) != 1 {
		t.Fatalf("expected exactly 1 registered runnable, got %d", len(m.Added))
	}
	p, ok := m.Added[0].(*shared.Periodic)
	if !ok {
		t.Fatalf("registered runnable is %T, want *shared.Periodic", m.Added[0])
	}
	if p.Name != name {
		t.Fatalf("periodic name = %q, want %q", p.Name, name)
	}
	if p.Interval != interval {
		t.Fatalf("periodic interval = %s, want %s", p.Interval, interval)
	}
	if p.Fn == nil {
		t.Fatal("periodic registered with nil fn")
	}
}

// ---------------------------------------------------------------------------
// Watch-unit convention — the predicates and mapfuncs a builder-based
// Setup installs are package-level vars/funcs in the module (e.g.
// `var nodeLabelChanges = predicate.Funcs{...}`), referenced by name
// in the Watches()/For() call. Tests exercise those vars directly
// (drive predicate.Funcs with event.* fixtures, or wrap the mapfunc
// in handler.EnqueueRequestsFromMapFunc and feed it a workqueue) —
// no reflection into the built controller, which pins test coverage
// to exactly what production runs. What is NOT covered this way: the
// count/order of registered watch sources (previously read via unsafe
// field access on the controller struct).
// ---------------------------------------------------------------------------

// UpdateEvent builds an event.UpdateEvent fixture — the predicate
// tests' one-liner for the old/new object pair.
func UpdateEvent(old, new client.Object) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: old, ObjectNew: new}
}
