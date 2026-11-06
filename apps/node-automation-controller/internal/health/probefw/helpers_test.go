// helpers_test.go — unit coverage for probefw's shared helpers: the
// "selfheal/<check>/<target>" key format, the RequireDyn preamble's
// byte-stable messages, the pod readiness/lookup helpers, the linkerd
// component matcher, PromEndpoint's override/fallback resolution and
// PromQuery's wire shape, and the DeletePodHeal
// preamble→delete→stamp sequence (incl. the fail-closed paths).
package probefw

import (
	"context"
	"errors"
	"fmt"
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
			Namespace: LinkerdNS, Name: name, Labels: labels}}
	}
	cases := []struct {
		name      string
		pod       *corev1.Pod
		component string
		want      bool
	}{
		{"exact deployment name",
			mk("linkerd-destination", nil), LinkerdDestinationName, true},
		{"replicaset pod prefix",
			mk("linkerd-destination-7d8f9b-x2abc", nil),
			LinkerdDestinationName, true},
		{"prefix without dash does not match",
			mk("linkerd-destinationextra", nil),
			LinkerdDestinationName, false},
		{"other component pod",
			mk("linkerd-identity-abc12", nil),
			LinkerdDestinationName, false},
		{"control-plane-component label short name",
			mk("pod-1", map[string]string{
				"linkerd.io/control-plane-component": "destination"}),
			LinkerdDestinationName, true},
		{"label for a different component",
			mk("pod-2", map[string]string{
				"linkerd.io/control-plane-component": "identity"}),
			LinkerdDestinationName, false},
		{"identity by label",
			mk("pod-3", map[string]string{
				"linkerd.io/control-plane-component": "identity"}),
			LinkerdIdentityName, true},
		{"unrelated pod",
			mk("web-1", map[string]string{"app": "web"}),
			LinkerdDestinationName, false},
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
		d := &Deps{Cfg: Config{HTTPContent: HTTPContentConfig{
			URL: "http://ignored/path"}}}
		got, err := d.PromEndpoint()
		if err != nil || got != "http://prom.internal:9090/api/v1/query" {
			t.Fatalf("PromEndpoint = (%q,%v)", got, err)
		}
	})
	t.Run("derives scheme://host from http-content target", func(t *testing.T) {
		t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", "")
		d := &Deps{Cfg: Config{HTTPContent: HTTPContentConfig{
			URL: "http://prom:9090/health/content"}}}
		got, err := d.PromEndpoint()
		if err != nil || got != "http://prom:9090/api/v1/query" {
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
		if q := r.URL.Query().Get("query"); q != `up{job="x"}` {
			t.Errorf("query = %q", q)
		}
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"p1"},"value":[1700000000,"3.5"]}]}}`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HEALTH_PROMETHEUS_QUERY_URL", srv.URL+"/api/v1/query")

	d := &Deps{HTTPClient: srv.Client()}
	samples, err := d.PromQuery(context.Background(), `up{job="x"}`)
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
	if _, err := d.PromQuery(context.Background(), "up"); err == nil {
		t.Fatal("PromQuery with unresolvable endpoint = nil error")
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

	d.DeletePodHeal(context.Background(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(context.Background(), pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
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

	d.DeletePodHeal(context.Background(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(context.Background(), pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted inside cooldown (get err = %v)", err)
	}
}

func TestDeletePodHealFailsClosedWhenUnverifiable(t *testing.T) {
	pod := healPod()
	cs := fake.NewSimpleClientset(pod)
	// Dyn=nil makes the autopilot-Plan mutex signal unverifiable —
	// the heal must defer rather than delete blind.
	d := &Deps{Name: "test-queue", CS: cs}

	d.DeletePodHeal(context.Background(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, time.Now())

	if _, err := cs.CoreV1().Pods(pod.Namespace).
		Get(context.Background(), pod.Name, metav1.GetOptions{}); err != nil {
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

	d.DeletePodHeal(context.Background(), logr.Discard(),
		"mesh-watchdog", "linkerd/linkerd-destination-abc",
		pod, time.Hour, now)

	// A failed delete must NOT stamp the ledger — stamping would let
	// one transient error suppress the heal for the whole window.
	if _, ok := d.Heals.Last(
		SelfHealKey("mesh-watchdog", "linkerd/linkerd-destination-abc")); ok {
		t.Fatal("heal ledger stamped after a failed delete")
	}
}
