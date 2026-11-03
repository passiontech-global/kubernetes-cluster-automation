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
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
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
		{"cf-tunnel-proxy-watchdog", 5 * time.Minute,
			func(m manager.Manager) error {
				return SetupCFTunnelProxyWatchdog(m, cs, true,
					"cloudflare-tunnel-system", 5*time.Minute)
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
// the bash exit-early at the top of the hook), while certmanager-reaper,
// cilium-identity-auditor, cilium-taint-reaper and
// fluent-bit-config-roller skip mgr.Add entirely when disabled (no
// informer, no RequeueAfter loop).
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
		{"coredns-patcher", func(m manager.Manager) error {
			return SetupCoreDNSPatcher(m, cs, false, "DoNotSchedule", 2)
		}},
		{"metrics-server-patcher", func(m manager.Manager) error {
			return SetupMetricsServerPatcher(m, cs, false)
		}},
		{"cf-tunnel-proxy-watchdog", func(m manager.Manager) error {
			return SetupCFTunnelProxyWatchdog(m, cs, false,
				"cloudflare-tunnel-system", 5*time.Minute)
		}},
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, cs, false)
		}},
		{"fluent-bit-config-roller", func(m manager.Manager) error {
			return SetupFluentBitRoller(m, cs, false)
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
		{"coredns-patcher", func(m manager.Manager) error {
			return SetupCoreDNSPatcher(m, cs, true, "DoNotSchedule", 2)
		}},
		{"metrics-server-patcher", func(m manager.Manager) error {
			return SetupMetricsServerPatcher(m, cs, true)
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
		{"converge-trigger", func(m manager.Manager) error {
			return SetupConvergeTrigger(m, cs)
		}},
		// enabled registers two sources (.Watches on Nodes + cilium
		// Pods) — still one controller runnable.
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, cs, true)
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

// ---------------------------------------------------------------------------
// Watch-source introspection — exercises the predicate/mapfunc closures
// the builder-based Setup functions install. The controller's .Watch()
// calls land in the unexported `startWatches` field and are only
// consumed by Start (never run against stubManager), so reflection +
// unsafe is the only way to reach them without envtest. The
// *internal.Kind source exposes Predicates/Handler as EXPORTED fields —
// only the slice itself needs the unsafe read.
// ---------------------------------------------------------------------------

// controllerWatches returns the watch sources a builder-built
// controller registered, in registration order.
func controllerWatches(t *testing.T, r manager.Runnable) []source.TypedSource[reconcile.Request] {
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

// kindSource unwraps the *internal Kind source For()/Watches() produce
// and returns its exported Predicates + Handler fields.
func kindSource(t *testing.T, src source.TypedSource[reconcile.Request]) ([]predicate.Predicate, handler.EventHandler) {
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

// forPredicate returns the first predicate installed on the only
// watch source of a single-watch builder module.
func forPredicate(t *testing.T, setup func(manager.Manager) error) predicate.Predicate {
	t.Helper()
	m := newStubManager()
	if err := setup(m); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.added))
	}
	preds, _ := kindSource(t, controllerWatches(t, m.added[0])[0])
	if len(preds) != 1 {
		t.Fatalf("For watch carries %d predicates, want 1", len(preds))
	}
	return preds[0]
}

func updateEvent(old, new client.Object) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: old, ObjectNew: new}
}

// The storm-gate For(Node) predicate must fire on node add/remove and
// on changes to the verdict inputs (condition statuses, taint keys) —
// but not on kubelet heartbeat churn.
func TestSetupStormGatePredicate(t *testing.T) {
	p := forPredicate(t, func(m manager.Manager) error {
		return SetupDeschedulerStormGate(m, fake.NewSimpleClientset())
	})

	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Unexpected types fall back to firing (conservative).
	if !p.Update(updateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}

	old := node("n1", corev1.ConditionTrue, nil)
	same := node("n1", corev1.ConditionTrue, nil)
	same.ResourceVersion = "2" // RV churn alone must not fire
	same.Status.Conditions[0].LastHeartbeatTime = metav1.Now()
	if p.Update(updateEvent(old, same)) {
		t.Fatal("heartbeat/RV churn fired the predicate")
	}

	condChanged := node("n1", corev1.ConditionFalse, nil)
	if !p.Update(updateEvent(old, condChanged)) {
		t.Fatal("condition status flip did not fire")
	}

	taintChanged := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "node.ops/kubelet-unresponsive", Effect: corev1.TaintEffectNoSchedule})
	if !p.Update(updateEvent(old, taintChanged)) {
		t.Fatal("taint change did not fire")
	}
}

// The node-labeler predicate is the bash jqFilter='.metadata.labels':
// only label drift fires, everything else is dropped.
func TestSetupNodeLabelerPredicate(t *testing.T) {
	p := forPredicate(t, func(m manager.Manager) error {
		return SetupNodeLabeler(m, fake.NewSimpleClientset(), "labels.txt")
	})

	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Missing objects never fire.
	if p.Update(updateEvent(nil, node("n1", corev1.ConditionTrue, nil))) {
		t.Fatal("nil ObjectOld fired")
	}
	if p.Update(updateEvent(node("n1", corev1.ConditionTrue, nil), nil)) {
		t.Fatal("nil ObjectNew fired")
	}

	labeled := node("n1", corev1.ConditionTrue,
		map[string]string{"passiontech.dev/workload": "app"})
	if !p.Update(updateEvent(node("n1", corev1.ConditionTrue, nil), labeled)) {
		t.Fatal("label drift did not fire")
	}
	if p.Update(updateEvent(labeled, labeled)) {
		t.Fatal("identical labels fired")
	}
}

// The cilium-taint-reaper Node predicate only fires on changes to the
// agent-not-ready taint projection; the enabled variant additionally
// watches kube-system cilium Pods and collapses them onto the same
// fixed sweep key.
func TestSetupCiliumTaintReaperWatches(t *testing.T) {
	m := newStubManager()
	if err := SetupCiliumTaintReaper(m, fake.NewSimpleClientset(), true); err != nil {
		t.Fatalf("setup: %v", err)
	}
	srcs := controllerWatches(t, m.added[0])
	if len(srcs) != 2 {
		t.Fatalf("enabled reaper registered %d watches, want 2", len(srcs))
	}

	preds, _ := kindSource(t, srcs[0])
	if len(preds) != 1 {
		t.Fatalf("Node watch carries %d predicates, want 1", len(preds))
	}
	p := preds[0]
	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}
	if !p.Update(updateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}
	old := node("n1", corev1.ConditionTrue, nil)
	if p.Update(updateEvent(old, node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("unrelated status change fired — heartbeat storms would sweep every 20s")
	}
	if !p.Update(updateEvent(old,
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))) {
		t.Fatal("agent-not-ready taint change did not fire")
	}

	// The Node watch itself enqueues the fixed sweep key — identical
	// NamespacedNames are what the workqueue set collapses, so it must
	// be the SAME key the pod watch below produces.
	_, nodeH := kindSource(t, srcs[0])
	if nodeH == nil {
		t.Fatal("node watch has no event handler")
	}
	nq := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer nq.ShutDown()
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: node("n1", corev1.ConditionTrue, nil)}, nq)
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: node("n2", corev1.ConditionFalse, nil)}, nq)
	if nq.Len() != 1 {
		t.Fatalf("2-node burst enqueued %d requests, want 1 (set-collapse)", nq.Len())
	}
	nitem, _ := nq.Get()
	if nitem.Name != "cilium-taint-reaper-sweep" || nitem.Namespace != "" {
		t.Fatalf("node event enqueued %+v, want fixed sweep key", nitem)
	}
	nq.Done(nitem)

	// The pod watch maps a scheduled cilium pod onto the same fixed
	// sweep key (it used to enqueue the pod's spec.nodeName).
	_, h := kindSource(t, srcs[1])
	if h == nil {
		t.Fatal("pod watch has no event handler")
	}
	q := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	// The pod watch enqueues the same fixed sweep key as the Node
	// watch — the reconcile ignores the request name, so collapsing
	// pod events onto it keeps one queued item per trigger burst.
	h.Create(context.Background(), event.CreateEvent{
		Object: ciliumPod("n7", corev1.PodRunning, true)}, q)
	if q.Len() != 1 {
		t.Fatalf("pod event enqueued %d requests, want 1", q.Len())
	}
	item, _ := q.Get()
	if item.Name != "cilium-taint-reaper-sweep" || item.Namespace != "" {
		t.Fatalf("enqueued request = %+v, want fixed sweep key", item)
	}
	q.Done(item)

	// An unscheduled pod (no spec.nodeName) enqueues nothing.
	h.Create(context.Background(), event.CreateEvent{Object: &corev1.Pod{}}, q)
	if q.Len() != 0 {
		t.Fatalf("nodeless pod enqueued %d requests, want 0", q.Len())
	}

	// Disabled variant: nothing registers at all — no controller,
	// no Node/Pod watch (covered in TestSetupFeatureFlagVariants).
	m = newStubManager()
	if err := SetupCiliumTaintReaper(m, fake.NewSimpleClientset(), false); err != nil {
		t.Fatalf("disabled setup: %v", err)
	}
	if len(m.added) != 0 {
		t.Fatalf("disabled reaper registered %d runnables, want 0", len(m.added))
	}
}

// Each sweep module's Node watch maps every node event onto its own
// fixed key — a multi-node burst must set-collapse to a single queued
// request, and the keys must stay stable (the reconcile ignores the
// request name; only the dedup contract matters).
func TestSetupSweepModulesFixedKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
		key   string
	}{
		{"node-labeler", func(m manager.Manager) error {
			return SetupNodeLabeler(m, fake.NewSimpleClientset(), "labels.txt")
		}, "node-labeler-sweep"},
		{"descheduler-storm-gate", func(m manager.Manager) error {
			return SetupDeschedulerStormGate(m, fake.NewSimpleClientset())
		}, "descheduler-storm-gate-sweep"},
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, fake.NewSimpleClientset(), true)
		}, "cilium-taint-reaper-sweep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			_, h := kindSource(t, controllerWatches(t, m.added[0])[0])
			if h == nil {
				t.Fatal("node watch has no event handler")
			}
			q := workqueue.NewTypedRateLimitingQueue(
				workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
			defer q.ShutDown()
			for _, name := range []string{"n1", "n2", "n3"} {
				h.Create(context.Background(), event.CreateEvent{
					Object: node(name, corev1.ConditionTrue, nil)}, q)
			}
			if q.Len() != 1 {
				t.Fatalf("3-node burst enqueued %d requests, want 1 (set-collapse)", q.Len())
			}
			item, _ := q.Get()
			if item.Name != tc.key || item.Namespace != "" {
				t.Fatalf("enqueued request = %+v, want fixed key %q", item, tc.key)
			}
			q.Done(item)
		})
	}
}

// The konnectivity-patcher predicate pins ns/name on top of the
// field-selected informer — belt-and-suspenders against cache misses.
func TestSetupKonnectivityPatcherPredicate(t *testing.T) {
	p := forPredicate(t, func(m manager.Manager) error {
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
	p := forPredicate(t, func(m manager.Manager) error {
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
