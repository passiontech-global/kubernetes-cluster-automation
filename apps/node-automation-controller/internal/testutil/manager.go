// Package testutil holds the shared fakes and assertion helpers the
// internal/<domain>/ module tests use: a stub manager.Manager that
// captures runnable registrations (Setup coverage without envtest),
// plus the reflection-based watch-source introspection the
// builder-based Setup functions need for predicate/mapfunc tests.
package testutil

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
	"unsafe"

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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
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

// RunPeriodic fires the Fn of the single *shared.Periodic m captured,
// exactly once, with ctx — "run the sweep now" for tests that
// exercise the real Setup wiring end-to-end (Setup(m, cs, dyn, true)
// then RunPeriodic(t, m, ctx) runs the module's actual sweep closure
// against the fake clients it was built with). Periodic.Start cannot
// serve here: it phase-delays the first tick by up to Interval
// (de-phasing jitter) and then loops forever.
//
// The returned error is fn's raw return value — Start would
// metrics.IncError it, a direct Fn call does not, so
// shell_operator_hook_run_errors_total assertions observe exactly
// what the sweep produced. Callers asserting an EXPECTED error get it
// back for inspection instead of a t.Fatal.
func RunPeriodic(t *testing.T, m *StubManager, ctx context.Context) error {
	t.Helper()
	if len(m.Added) != 1 {
		t.Fatalf("expected exactly 1 registered runnable, got %d", len(m.Added))
	}
	p, ok := m.Added[0].(*shared.Periodic)
	if !ok {
		t.Fatalf("registered runnable is %T, want *shared.Periodic", m.Added[0])
	}
	if p.Fn == nil {
		t.Fatal("periodic registered with nil fn")
	}
	return p.Fn(ctx)
}

// ---------------------------------------------------------------------------
// Watch-source introspection — exercises the predicate/mapfunc closures
// the builder-based Setup functions install. The controller's .Watch()
// calls land in the unexported `startWatches` field and are only
// consumed by Start (never run against StubManager), so reflection +
// unsafe is the only way to reach them without envtest. The
// *internal.Kind source exposes Predicates/Handler as EXPORTED fields —
// only the slice itself needs the unsafe read.
// ---------------------------------------------------------------------------

// ControllerWatches returns the watch sources a builder-built
// controller registered, in registration order.
func ControllerWatches(t *testing.T, r manager.Runnable) []source.TypedSource[reconcile.Request] {
	t.Helper()
	v := reflect.ValueOf(r)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		t.Fatalf("registered runnable is %T, want a controller pointer", r)
	}
	f := v.Elem().FieldByName("startWatches")
	if !f.IsValid() {
		t.Fatalf("%T has no startWatches field — controller-runtime internals changed?", r)
	}
	srcs, ok := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).
		Elem().Interface().([]source.TypedSource[reconcile.Request])
	if !ok {
		t.Fatalf("startWatches type = %s, want []source.TypedSource[reconcile.Request]", f.Type())
	}
	if len(srcs) == 0 {
		t.Fatal("controller registered no watch sources")
	}
	return srcs
}

// KindSource unwraps the *internal Kind source For()/Watches() produce
// and returns its exported Predicates + Handler fields.
func KindSource(t *testing.T, src source.TypedSource[reconcile.Request]) ([]predicate.Predicate, handler.EventHandler) {
	t.Helper()
	v := reflect.ValueOf(src)
	if v.Kind() != reflect.Pointer {
		t.Fatalf("watch source is %T, want *internal Kind", src)
	}
	pf := v.Elem().FieldByName("Predicates")
	hf := v.Elem().FieldByName("Handler")
	if !pf.IsValid() || !hf.IsValid() {
		t.Fatalf("watch source %T lacks Predicates/Handler fields", src)
	}
	preds, _ := pf.Interface().([]predicate.Predicate)
	h, _ := hf.Interface().(handler.EventHandler)
	return preds, h
}

// ForPredicate returns the first predicate installed on the only
// watch source of a single-watch builder module.
func ForPredicate(t *testing.T, setup func(manager.Manager) error) predicate.Predicate {
	t.Helper()
	m := NewStubManager()
	if err := setup(m); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
	preds, _ := KindSource(t, ControllerWatches(t, m.Added[0])[0])
	if len(preds) != 1 {
		t.Fatalf("For watch carries %d predicates, want 1", len(preds))
	}
	return preds[0]
}

func UpdateEvent(old, new client.Object) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: old, ObjectNew: new}
}
