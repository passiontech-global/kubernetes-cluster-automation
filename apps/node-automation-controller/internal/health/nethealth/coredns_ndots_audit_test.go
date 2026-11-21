// coredns_ndots_audit_test.go — coverage for Wave 4C #12B CoreDNS
// ndots:5 DNS amplification audit: unconditional per-sweep execution,
// NaN/empty/0÷0 handling, ratio>0.40 && QPS>50 thresholds, >=3 replica
// Deployment/StatefulSet audit, 6h Event deduplication, RFC 1123 names,
// and PromQL error propagation.
package nethealth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func ndotsDeps(t *testing.T, rejects float64, ratioSamples, qpsSamples []probetest.PromTestSample, objs ...runtime.Object) *probefw.Deps {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "max_concurrent_rejects"):
			return []probetest.PromTestSample{{Value: rejects}}
		case strings.Contains(query, `rcode="NXDOMAIN"`):
			return ratioSamples
		case strings.Contains(query, "coredns_dns_responses_total"):
			return qpsSamples
		default:
			return nil
		}
	})
	cs := fake.NewSimpleClientset(objs...)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	d.Cfg.HTTPContent.URL = srv.URL
	d.HTTPClient = srv.Client()
	return d
}

func makeNdotsDeploy(ns, name string, replicas int32, hasNdots bool, terminating bool) *appsv1.Deployment {
	var dnsCfg *corev1.PodDNSConfig
	if hasNdots {
		dnsCfg = &corev1.PodDNSConfig{
			Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr.To("2")}},
		}
	}
	var delTime *metav1.Time
	if terminating {
		now := metav1.Now()
		delTime = &now
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID("dep-uid-" + name),
			DeletionTimestamp: delTime,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					DNSConfig: dnsCfg,
				},
			},
		},
	}
}

func makeNdotsSTS(ns, name string, replicas int32, hasNdots bool) *appsv1.StatefulSet {
	var dnsCfg *corev1.PodDNSConfig
	if hasNdots {
		dnsCfg = &corev1.PodDNSConfig{
			Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr.To("2")}},
		}
	}
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID("sts-uid-" + name),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(replicas),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					DNSConfig: dnsCfg,
				},
			},
		},
	}
}

func TestCoreDNSNdotsAudit_BreachAndEventCooldown(t *testing.T) {
	// Zero forward rejects — verifies ndots audit runs even when forward saturation is quiet.
	d := ndotsDeps(t, 0,
		[]probetest.PromTestSample{{Value: 0.55}},
		[]probetest.PromTestSample{{Value: 120}},
		makeNdotsDeploy("prod", "api-gw", 4, false, false),
		makeNdotsDeploy("prod", "api-tuned", 4, true, false),
		makeNdotsDeploy("prod", "api-small", 2, false, false),
		makeNdotsDeploy("prod", "api-terminating", 5, false, true),
		makeNdotsSTS("data", "worker-pool", 3, false),
		makeNdotsSTS("data", "worker-tuned", 3, true),
	)
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
	base := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(d, base)

	res := ch.Run(probetest.SweepCtx(ctx, d))
	if res.Pass {
		t.Fatalf("expected failure on ndots breach, got PASS: %+v", res)
	}
	if !strings.Contains(res.Why, "Deployment/prod/api-gw missing ndots") ||
		!strings.Contains(res.Why, "StatefulSet/data/worker-pool missing ndots") {
		t.Fatalf("unexpected Why: %q", res.Why)
	}
	for _, skip := range []string{"api-tuned", "api-small", "api-terminating", "worker-tuned"} {
		if strings.Contains(res.Why, skip) {
			t.Fatalf("expected %s to be skipped, Why=%q", skip, res.Why)
		}
	}

	v, ok := testutil.GaugeSeriesValue(t, "node_automation_coredns_nxdomain_ratio", nil)
	if !ok || v != 0.55 {
		t.Fatalf("nxdomain ratio gauge = %v, %v want 0.55", v, ok)
	}

	evs, err := d.CS.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("expected 2 Warning events, got %d", len(evs.Items))
	}
	for _, ev := range evs.Items {
		if ev.Reason != coreDNSNdotsEventReason {
			t.Fatalf("unexpected event reason %q", ev.Reason)
		}
		if !strings.Contains(ev.Note, "ndots:2") {
			t.Fatalf("event note missing ndots:2 suggestion: %q", ev.Note)
		}
	}

	// Second sweep within 6h cooldown must NOT emit duplicate events.
	probetest.FreezeNow(d, base.Add(3*time.Hour))
	ch.Run(probetest.SweepCtx(ctx, d))
	evs2, _ := d.CS.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if len(evs2.Items) != 2 {
		t.Fatalf("expected cooldown to dedupe events (still 2), got %d", len(evs2.Items))
	}

	// Sweep after 6h cooldown emits fresh events.
	probetest.FreezeNow(d, base.Add(6*time.Hour+time.Minute))
	ch.Run(probetest.SweepCtx(ctx, d))
	evs3, _ := d.CS.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if len(evs3.Items) != 4 {
		t.Fatalf("expected 4 events after 6h cooldown expiry, got %d", len(evs3.Items))
	}
}

func TestCoreDNSNdotsAudit_ThresholdsAndNaNHandling(t *testing.T) {
	cases := []struct {
		name      string
		ratio     []probetest.PromTestSample
		qps       []probetest.PromTestSample
		wantRatio float64
		wantPass  bool
	}{
		{
			name:      "empty/0-div-0 NaN handled cleanly",
			ratio:     nil,
			qps:       nil,
			wantRatio: 0,
			wantPass:  true,
		},
		{
			name:      "ratio at boundary 0.40 passes",
			ratio:     []probetest.PromTestSample{{Value: 0.40}},
			qps:       []probetest.PromTestSample{{Value: 100}},
			wantRatio: 0.40,
			wantPass:  true,
		},
		{
			name:      "high ratio with low QPS <=50 passes",
			ratio:     []probetest.PromTestSample{{Value: 0.80}},
			qps:       []probetest.PromTestSample{{Value: 50}},
			wantRatio: 0.80,
			wantPass:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ndotsDeps(t, 0, tc.ratio, tc.qps, makeNdotsDeploy("prod", "web", 4, false, false))
			ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
			res := ch.Run(probetest.SweepCtx(ctx, d))
			if res.Pass != tc.wantPass {
				t.Fatalf("Pass = %v, want %v (res=%+v)", res.Pass, tc.wantPass, res)
			}
			v, ok := testutil.GaugeSeriesValue(t, "node_automation_coredns_nxdomain_ratio", nil)
			if !ok || v != tc.wantRatio {
				t.Fatalf("ratio gauge = %v, %v want %v", v, ok, tc.wantRatio)
			}
		})
	}

	t.Run("raw NaN JSON response handled cleanly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1700000000,"NaN"]}]}}`))
		}))
		t.Cleanup(srv.Close)
		d := probetest.NewDeps(fake.NewSimpleClientset(makeNdotsDeploy("prod", "web", 4, false, false)), probetest.OpDyn())
		d.Cfg.HTTPContent.URL = srv.URL
		d.HTTPClient = srv.Client()
		ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
		res := ch.Run(probetest.SweepCtx(ctx, d))
		if !res.Pass || res.Infra != nil {
			t.Fatalf("NaN response must pass cleanly without Infra error: %+v", res)
		}
		v, ok := testutil.GaugeSeriesValue(t, "node_automation_coredns_nxdomain_ratio", nil)
		if !ok || v != 0 {
			t.Fatalf("ratio gauge on NaN = %v, %v want 0", v, ok)
		}
	})
}

func TestCoreDNSNdotsAudit_LongNamesSameSweepNoEventCollision(t *testing.T) {
	ns := strings.Repeat("n", 63)
	sharedPrefix := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "."
	name1 := sharedPrefix + strings.Repeat("d", 52) // 235 chars
	name2 := sharedPrefix + strings.Repeat("e", 52) // 235 chars

	d := ndotsDeps(t, 0,
		[]probetest.PromTestSample{{Value: 0.55}},
		[]probetest.PromTestSample{{Value: 120}},
		makeNdotsDeploy(ns, name1, 3, false, false),
		makeNdotsDeploy(ns, name2, 3, false, false),
	)
	d.Name = CheckNameCoreDNSForwardSaturation
	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(d, now)

	beforeErrs := probetest.CounterSnapshot(t, d.Name)
	res := ch.Run(probetest.SweepCtx(ctx, d))
	if res.Pass {
		t.Fatalf("expected failure on long-named ndots offenders, got PASS")
	}
	probetest.AssertCounterDelta(t, d.Name, beforeErrs, 0)

	evs, err := d.CS.EventsV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("expected 2 distinct Warning events for long-named Deployments, got %d", len(evs.Items))
	}
	seenNames := make(map[string]bool, 2)
	for _, ev := range evs.Items {
		if len(ev.Name) > 253 {
			t.Fatalf("event name len=%d exceeds 253: %q", len(ev.Name), ev.Name)
		}
		if errs := validation.IsDNS1123Subdomain(ev.Name); len(errs) > 0 {
			t.Fatalf("event name %q invalid RFC 1123 subdomain: %v", ev.Name, errs)
		}
		seenNames[ev.Name] = true
	}
	if len(seenNames) != 2 {
		t.Fatalf("expected 2 distinct event names, got %v", seenNames)
	}
}

func TestCoreDNSNdotsEvent403DoesNotIncError(t *testing.T) {
	d := ndotsDeps(t, 0,
		[]probetest.PromTestSample{{Value: 0.55}},
		[]probetest.PromTestSample{{Value: 120}},
		makeNdotsDeploy("app", "web", 4, false, false),
	)
	d.Name = CheckNameCoreDNSForwardSaturation
	cs := d.CS.(*fake.Clientset)
	cs.PrependReactor("create", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "events.k8s.io", Resource: "events"}, "", errors.New("forbidden"))
	})

	ch := &coreDNSForwardSaturationCheck{Deps: d, boostReplicas: 2}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	probetest.FreezeNow(d, now)

	beforeErrs := probetest.CounterSnapshot(t, d.Name)
	res := ch.Run(probetest.SweepCtx(ctx, d))
	if res.Pass || res.Infra != nil {
		t.Fatalf("expected Pass=false with nil Infra on ndots breach + event 403, got %+v", res)
	}
	if !strings.Contains(res.Why, "Deployment/app/web missing ndots") {
		t.Fatalf("expected Deployment/app/web missing ndots in Why, got %q", res.Why)
	}
	probetest.AssertCounterDelta(t, d.Name, beforeErrs, 0)
}
