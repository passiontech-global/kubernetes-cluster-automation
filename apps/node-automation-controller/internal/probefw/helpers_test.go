// helpers_test.go — unit coverage for probefw's shared helpers: the
// "selfheal/<check>/<target>" key format, the RequireDyn preamble's
// byte-stable messages, the pod readiness/lookup helpers, the linkerd
// component matcher, PromEndpoint's override/fallback resolution and
// PromQuery's wire shape, and the DeletePodHeal
// preamble→delete→stamp sequence (incl. the fail-closed paths).
package probefw

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func TestSelfHealKey(t *testing.T) {
	got := SelfHealKey("mesh-watchdog", "linkerd/linkerd-destination-abc")
	if got != "selfheal/mesh-watchdog/linkerd/linkerd-destination-abc" {
		t.Fatalf("SelfHealKey = %q", got)
	}
}

func TestRequireDyn(t *testing.T) {
	d := &Deps{}

	r := d.RequireDyn("")
	if r == nil || r.Infra == nil ||
		r.Infra.Error() != "no dynamic client" {
		t.Fatalf("RequireDyn(\"\") = %+v, want bare Infra result", r)
	}

	r = d.RequireDyn("scylla health check")
	if r == nil || r.Infra == nil || r.Infra.Error() !=
		"no dynamic client — scylla health check unverifiable" {
		t.Fatalf("RequireDyn = %+v, want descriptive Infra result", r)
	}

	d.Dyn = testhelp.NewDynamicClient()
	if r := d.RequireDyn("anything"); r != nil {
		t.Fatalf("RequireDyn with Dyn set = %+v, want nil", r)
	}
}

func TestPodUnreadySince(t *testing.T) {
	created := time.Now().Add(-time.Hour).Truncate(time.Second)
	transition := created.Add(30 * time.Minute)
	mk := func(conds ...corev1.PodCondition) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				CreationTimestamp: metav1.NewTime(created)},
			Status: corev1.PodStatus{Conditions: conds},
		}
	}
	cases := []struct {
		name    string
		pod     *corev1.Pod
		want    time.Time
		unready bool
	}{
		{"ready true reports not-unready", mk(corev1.PodCondition{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(transition)}),
			time.Time{}, false},
		{"ready false uses transition time", mk(corev1.PodCondition{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(transition)}),
			transition, true},
		{"ready false without transition falls back to creation", mk(
			corev1.PodCondition{
				Type:   corev1.PodReady,
				Status: corev1.ConditionFalse}),
			created, true},
		{"no ready condition is unready since creation", mk(
			corev1.PodCondition{
				Type:   corev1.PodScheduled,
				Status: corev1.ConditionTrue}),
			created, true},
		{"no conditions at all", mk(), created, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, unready := PodUnreadySince(tc.pod)
			if unready != tc.unready || !got.Equal(tc.want) {
				t.Fatalf("PodUnreadySince = (%v,%v), want (%v,%v)",
					got, unready, tc.want, tc.unready)
			}
		})
	}
}

func TestPodFromList(t *testing.T) {
	items := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "p1"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "p2"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "b", Name: "p1"}},
	}
	if p := PodFromList(items, "a", "p2"); p == nil || p.Name != "p2" {
		t.Fatalf("PodFromList hit = %v", p)
	}
	if p := PodFromList(items, "b", "p2"); p != nil {
		t.Fatalf("PodFromList ns miss = %v, want nil", p)
	}
	if p := PodFromList(items, "a", "gone"); p != nil {
		t.Fatalf("PodFromList name miss = %v, want nil", p)
	}
	if p := PodFromList(nil, "a", "p1"); p != nil {
		t.Fatalf("PodFromList empty = %v, want nil", p)
	}
}

func TestLinkerdPodMatchesComponent(t *testing.T) {
	mk := func(name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "linkerd", Name: name, Labels: labels}}
	}
	cases := []struct {
		name      string
		pod       *corev1.Pod
		component string
		want      bool
	}{
		{"exact deployment name",
			mk("linkerd-destination", nil), "linkerd-destination", true},
		{"replicaset pod prefix",
			mk("linkerd-destination-7d8f9b-x2abc", nil),
			"linkerd-destination", true},
		{"prefix without dash does not match",
			mk("linkerd-destinationextra", nil),
			"linkerd-destination", false},
		{"other component pod",
			mk("linkerd-identity-abc12", nil),
			"linkerd-destination", false},
		{"control-plane-component label short name",
			mk("pod-1", map[string]string{
				"linkerd.io/control-plane-component": "destination"}),
			"linkerd-destination", true},
		{"label for a different component",
			mk("pod-2", map[string]string{
				"linkerd.io/control-plane-component": "identity"}),
			"linkerd-destination", false},
		{"identity by label",
			mk("pod-3", map[string]string{
				"linkerd.io/control-plane-component": "identity"}),
			"linkerd-identity", true},
		{"unrelated pod",
			mk("web-1", map[string]string{"app": "web"}),
			"linkerd-destination", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LinkerdPodMatchesComponent(tc.pod, tc.component); got != tc.want {
				t.Fatalf("LinkerdPodMatchesComponent(%s,%s) = %v, want %v",
					tc.pod.Name, tc.component, got, tc.want)
			}
		})
	}
}

func TestPromEndpoint(t *testing.T) {
	t.Run("env override wins verbatim", func(t *testing.T) {
		t.Setenv("HEALTH_PROMETHEUS_QUERY_URL",
			"http://prom.internal:9090/api/v1/query")
		// The override is captured at NewDeps — the env freeze the
		// construction-time resolution exists to guarantee.
		d := NewDeps("", nil, nil, nil, Config{HTTPContent: HTTPContentConfig{
			URL: "http://ignored/path"}})
		got, err := d.PromEndpoint()
		if err != nil || got != "http://prom.internal:9090/api/v1/query" {
			t.Fatalf("PromEndpoint = (%q,%v)", got, err)
		}
	})
	t.Run("derives scheme://host from http-content target", func(t *testing.T) {
		t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "")
		d := &Deps{Cfg: Config{HTTPContent: HTTPContentConfig{
			URL: "http://prom:9090/-/healthy"}}}
		got, err := d.PromEndpoint()
		if err != nil || got != "http://prom:9090/api/v1/query" {
			t.Fatalf("PromEndpoint = (%q,%v)", got, err)
		}
	})
	t.Run("keeps a reverse-proxy subpath mount", func(t *testing.T) {
		// VictoriaMetrics/Thanos behind an ingress subpath: the
		// mount prefix survives into the derived query endpoint.
		t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "")
		d := &Deps{Cfg: Config{HTTPContent: HTTPContentConfig{
			URL: "https://mon.example.com/prometheus/-/healthy"}}}
		got, err := d.PromEndpoint()
		if err != nil ||
			got != "https://mon.example.com/prometheus/api/v1/query" {
			t.Fatalf("PromEndpoint = (%q,%v)", got, err)
		}
	})
	t.Run("unresolvable fallback errors", func(t *testing.T) {
		t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "")
		d := &Deps{Cfg: Config{HTTPContent: HTTPContentConfig{
			URL: "no-scheme"}}}
		if got, err := d.PromEndpoint(); err == nil {
			t.Fatalf("PromEndpoint = (%q,nil), want error", got)
		}
	})
}

func TestPromQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		if q := r.FormValue("query"); q != `up{job="x"}` {
			t.Errorf("query = %q", q)
		}
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"p1"},"value":[1700000000,"3.5"]}]}}`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", srv.URL+"/api/v1/query")

	// Built through NewDeps so the env override lands in the frozen
	// field; the HTTPClient seam swaps post-construction as in prod.
	d := NewDeps("", nil, nil, nil, Config{})
	d.HTTPClient = srv.Client()
	d.Prom.HTTP = d.HTTPClient
	samples, err := d.PromQuery(t.Context(), `up{job="x"}`)
	if err != nil {
		t.Fatalf("PromQuery: %v", err)
	}
	if len(samples) != 1 || samples[0].Metric["pod"] != "p1" ||
		samples[0].Value != 3.5 {
		t.Fatalf("PromQuery samples = %+v", samples)
	}
}

func TestPromQueryUnresolvableEndpoint(t *testing.T) {
	t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "")
	d := &Deps{HTTPClient: &http.Client{}, Cfg: Config{
		HTTPContent: HTTPContentConfig{URL: "no-scheme"}}}
	if _, err := d.PromQuery(t.Context(), "up"); err == nil {
		t.Fatal("PromQuery with unresolvable endpoint = nil error")
	}
}

// NewDeps resolves the HEALTH_PROMETHEUS_QUERY_URL override ONCE at
// construction — env churn mid-run (what per-call re-reads allowed)
// can no longer flip the endpoint under a running sweep. The
// Cfg.HTTPContent.URL fallback stays live (config, not env), so
// tests re-pointing Cfg keep working. Literally-constructed Deps
// carry no override and fall through to the derivation
// (TestPromEndpoint covers that fold).
func TestPromEndpointResolvedOnceAtConstruction(t *testing.T) {
	t.Setenv("HEALTH_PROMETHEUS_QUERY_URL",
		"http://prom.internal:9090/api/v1/query")
	d := NewDeps("", nil, nil, nil, Config{HTTPContent: HTTPContentConfig{
		URL: "http://ignored/path"}})

	if got, err := d.PromEndpoint(); err != nil ||
		got != "http://prom.internal:9090/api/v1/query" {
		t.Fatalf("NewDeps PromEndpoint = (%q,%v)", got, err)
	}
	t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "http://other:9090/api/v1/query")
	if got, err := d.PromEndpoint(); err != nil ||
		got != "http://prom.internal:9090/api/v1/query" {
		t.Fatalf("endpoint re-resolved after construction = (%q,%v)", got, err)
	}
}

// healPod is the pod DeletePodHeal bounces in these tests — seeded in
// the fake clientset so the UID-preconditioned delete lands.
func healPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "linkerd", Name: "linkerd-destination-abc", UID: "u1"}}
}

func TestDeletePodHealDeletesAndStamps(t *testing.T) {
	pod := healPod()
	cs := fake.NewSimpleClientset(pod)
	// The maintenance mutex evaluates clear: no cordoned nodes, no
	// kured lock, empty autopilot Plan list.
	d := &Deps{Name: "test-queue", CS: cs, Dyn: testhelp.NewDynamicClient()}
	now := time.Now()

	d.DeletePodHeal(t.Context(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(t.Context(), pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod not deleted (get err = %v)", err)
	}
	if _, ok := d.Heals.Last(
		SelfHealKey("mesh-watchdog", "linkerd/linkerd-destination-abc")); !ok {
		t.Fatal("heal ledger not stamped after delete")
	}
}

func TestDeletePodHealHonorsCooldown(t *testing.T) {
	pod := healPod()
	cs := fake.NewSimpleClientset(pod)
	d := &Deps{Name: "test-queue", CS: cs, Dyn: testhelp.NewDynamicClient()}
	now := time.Now()
	// A stamp inside the window must suppress the heal entirely —
	// the delete never reaches the apiserver.
	d.Heals.Stamp(SelfHealKey("mesh-watchdog", "linkerd/linkerd-destination-abc"),
		now.Add(-time.Minute))

	d.DeletePodHeal(t.Context(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(t.Context(), pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted inside cooldown (get err = %v)", err)
	}
}

func TestDeletePodHealFailsClosedWhenUnverifiable(t *testing.T) {
	pod := healPod()
	cs := fake.NewSimpleClientset(pod)
	// Dyn=nil makes the autopilot-Plan mutex signal unverifiable —
	// the heal must defer rather than delete blind.
	d := &Deps{Name: "test-queue", CS: cs}

	d.DeletePodHeal(t.Context(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, time.Now())

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(t.Context(), pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted while mutex unverifiable (get err = %v)", err)
	}
}

func TestDeletePodHealFailedDeleteLeavesNoStamp(t *testing.T) {
	pod := healPod()
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("delete", "pods",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("delete boom")
		})
	d := &Deps{Name: "test-queue", CS: cs, Dyn: testhelp.NewDynamicClient()}
	now := time.Now()

	d.DeletePodHeal(t.Context(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	// A failed delete must NOT stamp the ledger — stamping would let
	// one transient error suppress the heal for the whole window.
	if _, ok := d.Heals.Last(
		SelfHealKey("mesh-watchdog", "linkerd/linkerd-destination-abc")); ok {
		t.Fatal("heal ledger stamped after a failed delete")
	}
}

func TestMergeAnnoPatchLocally(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "p1",
		Annotations: map[string]string{
			"keep": "1", "del": "x", "over": "old"}}}

	// A merge-patch doc: set two keys, delete one — applied to the
	// listed copy exactly like the apiserver merge would.
	MergeAnnoPatchLocally(t.Context(), pod, []byte(
		`{"metadata":{"annotations":{"new":"v","over":"new","del":null}}}`))

	want := map[string]string{"keep": "1", "new": "v", "over": "new"}
	got := pod.GetAnnotations()
	if !maps.Equal(got, want) {
		t.Fatalf("annotations = %v, want %v (all: %v)", got, want, got)
	}

	// A nil annotation map materializes on first write.
	bare := &corev1.Pod{}
	MergeAnnoPatchLocally(t.Context(), bare, []byte(
		`{"metadata":{"annotations":{"k":"v"}}}`))
	if bare.GetAnnotations()["k"] != "v" {
		t.Fatalf("nil-map annotations = %v", bare.GetAnnotations())
	}

	// Malformed payloads are ignored — the input is always
	// kube.MergePatchAnnos output, but a bad read must never corrupt
	// the listed copy.
	MergeAnnoPatchLocally(t.Context(), pod, []byte(`{not json`))
	if pod.GetAnnotations()["new"] != "v" {
		t.Fatal("malformed patch mutated the object")
	}
}

func TestSection(t *testing.T) {
	if got := Section("found: %s", nil); got != "" {
		t.Fatalf("Section with no findings = %q, want empty", got)
	}
	got := Section("stuck %d: %s", []string{"b", "a"}, 2)
	if got != "stuck 2: b, a" {
		t.Fatalf("Section = %q", got)
	}
}

func TestWhyFold(t *testing.T) {
	if res := WhyFold(); !res.Pass || res.Why != "" {
		t.Fatalf("WhyFold() = %+v, want pass", res)
	}
	if res := WhyFold("", "  ", "x"); res.Pass || res.Why != "   | x" {
		t.Fatalf(`WhyFold("", "  ", "x") = %+v — only empty strings drop`, res)
	}
	res := WhyFold("a", "", "b")
	if res.Pass || res.Why != "a | b" {
		t.Fatalf("WhyFold = %+v, want Why 'a | b'", res)
	}
}

// HealAllowedPersisted is the wider-of cooldown gate: the in-RAM
// ledger stamp OR the object's persisted annotation inside the window
// defers; a clear cooldown falls through to the maintenance mutex
// (clear here) and proceeds. nil obj/empty annoKey collapses to the
// plain ledger+mutex gate.
func TestHealAllowedPersisted(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	log := logr.Discard()
	newDeps := func(cs *fake.Clientset) *Deps {
		return &Deps{Name: "test-queue", CS: cs,
			Dyn: testhelp.NewDynamicClient()}
	}
	objWith := func(stamp time.Time) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "target",
			Annotations: map[string]string{
				"passiontech.dev/last-heal": stamp.UTC().Format(time.RFC3339)}}}
	}

	t.Run("no stamps proceeds", func(t *testing.T) {
		d := newDeps(fake.NewSimpleClientset())
		proceed, unverifiable := d.HealAllowedPersisted(ctx, log,
			&d.Heals, objWith(now.Add(-time.Hour)),
			"passiontech.dev/last-heal", "selfheal/check/target",
			time.Hour, now)
		if !proceed || unverifiable {
			t.Fatalf("clear cooldown = (%v,%v), want (true,false)", proceed, unverifiable)
		}
	})

	t.Run("fresh persisted stamp defers", func(t *testing.T) {
		d := newDeps(fake.NewSimpleClientset())
		proceed, unverifiable := d.HealAllowedPersisted(ctx, log,
			&d.Heals, objWith(now.Add(-time.Minute)),
			"passiontech.dev/last-heal", "selfheal/check/target",
			time.Hour, now)
		if proceed || unverifiable {
			t.Fatalf("persisted stamp inside window = (%v,%v), want (false,false)",
				proceed, unverifiable)
		}
	})

	t.Run("ledger stamp defers with stale annotation", func(t *testing.T) {
		d := newDeps(fake.NewSimpleClientset())
		d.Heals.Stamp("selfheal/check/target", now.Add(-time.Minute))
		proceed, _ := d.HealAllowedPersisted(ctx, log,
			&d.Heals, objWith(now.Add(-2*time.Hour)),
			"passiontech.dev/last-heal", "selfheal/check/target",
			time.Hour, now)
		if proceed {
			t.Fatal("in-RAM stamp inside window did not defer")
		}
	})

	t.Run("nil object collapses to ledger+mutex", func(t *testing.T) {
		d := newDeps(fake.NewSimpleClientset())
		d.Heals.Stamp("selfheal/check/target", now.Add(-time.Minute))
		proceed, unverifiable := d.HealAllowedPersisted(ctx, log,
			&d.Heals, nil, "", "selfheal/check/target",
			time.Hour, now)
		if proceed || unverifiable {
			t.Fatalf("nil obj + ledger stamp = (%v,%v), want (false,false)",
				proceed, unverifiable)
		}
	})

	t.Run("unverifiable mutex fails closed", func(t *testing.T) {
		// Dyn=nil makes the autopilot-Plan signal unverifiable — the
		// gate must report it, never read "cannot verify" as clear.
		d := &Deps{Name: "test-queue",
			CS: fake.NewSimpleClientset()}
		proceed, unverifiable := d.HealAllowedPersisted(ctx, log,
			&d.Heals, objWith(now.Add(-time.Hour)),
			"passiontech.dev/last-heal", "selfheal/check/target",
			time.Hour, now)
		if proceed || !unverifiable {
			t.Fatalf("unverifiable mutex = (%v,%v), want (false,true)",
				proceed, unverifiable)
		}
	})
}
