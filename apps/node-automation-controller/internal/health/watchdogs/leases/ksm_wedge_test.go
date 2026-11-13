// ksm_wedge_test.go — coverage for the kube-state-metrics wedge
// halves the lease-guard tests stub out: the real log-tail probe and
// its signature table (ksmLogProbe was always injected), the
// Prometheus error-counter OR-half, and the inconclusive/resolve
// postures (a broken read must keep tracking — never read as clean —
// and a genuinely clean pod must lose its persisted first-seen
// stamp so a recurrence re-arms the full window).
package leases

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ksmPod builds a Running kube-state-metrics pod — the label the
// kube-prometheus-stack chart ships is the primary isKSMPod match.
func ksmPod(ns, name string) *corev1.Pod {
	return probetest.ReadyPodWithIP(ns, name, "10.0.0.7",
		map[string]string{"app.kubernetes.io/name": "kube-state-metrics"})
}

// ---------------------------------------------------------------------------
// The signature table — through the real ksmLogTailWedge probe
// ---------------------------------------------------------------------------

// The log tail is the primary signal: each wedge marker classifies
// to its reason, and a reflector line whose root cause is the 401
// still reads as the auth wedge (the table is ordered
// most-specific-first — a "failed to watch … 401 Unauthorized" line
// is an auth wedge, not a generic reflector flake). Bare
// "unauthorized" is no longer a marker — the generic word shadowed
// the full-phrase 401 spells — so a bare "Unauthorized" tail now
// classifies reflector, and the full phrases carry the auth verdict.
func TestKSMWedgeLogSignatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  string
		want string
	}{
		{"401 unauthorized", `E0101 reflector.go:1] Failed to watch *v1.Pod: 401 Unauthorized` + "\n",
			leaseReasonKSMUnauthorized},
		{"expired sa token", `the server has asked for the client to provide credentials` + "\n",
			leaseReasonKSMUnauthorized},
		{"token expired marker", `authentication failed: token expired` + "\n",
			leaseReasonKSMUnauthorized},
		{"failed to list", `E0101 listers.go:9] failed to list *v1.ConfigMap: configmaps is forbidden` + "\n",
			leaseReasonKSMReflectorErrors},
		{"failed to watch", `E0101 reflector.go:9] failed to watch *v1.Secret: context deadline` + "\n",
			leaseReasonKSMReflectorErrors},
		{"unable to sync caches", `unable to sync caches for *v1.Pod` + "\n",
			leaseReasonKSMReflectorErrors},
		{"bare unauthorized without phrase is reflector",
			`E0101 reflector.go:1] Failed to watch *v1.Pod: Unauthorized` + "\n",
			leaseReasonKSMReflectorErrors},
		{"reflector line caused by 401 classifies auth",
			`failed to watch *v1.Pod: the server has asked for the client to provide credentials` + "\n",
			leaseReasonKSMUnauthorized},
		{"uppercase marker still matches", `FAILED TO LIST *v1.Pod: 401 UNAUTHORIZED` + "\n",
			leaseReasonKSMUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := ksmPod("monitoring", "kube-state-metrics-sig")
			cs := fake.NewSimpleClientset(pod)
			cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(tc.log, nil))
			_, ch := leaseGuardProber(cs)
			// ksmLogProbe stays nil — the production tail path runs.
			got, err := ch.ksmWedgeReason(ctx, pod)
			if err != nil {
				t.Fatalf("ksmWedgeReason err = %v, want reason %q", err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("ksmWedgeReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// Bare "unauthorized" is no longer a signature: a tail that merely
// carries the word — no 401/token phrase, no reflector marker — must
// read clean (the missing error-counter series confirms it), never
// bounce the pod as an auth wedge on the wrong cause.
func TestKSMWedgeBareUnauthorizedReadsClean(t *testing.T) {
	srv, _ := probetest.PromTestServer(t,
		func(string) []probetest.PromTestSample { return nil })
	pod := ksmPod("monitoring", "kube-state-metrics-bare")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"auth middleware logged 3 unauthorized requests\n", nil))
	p, ch := leaseGuardProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	got, err := ch.ksmWedgeReason(ctx, pod)
	if err != nil {
		t.Fatalf("ksmWedgeReason err = %v, want clean", err)
	}
	if got != "" {
		t.Fatalf(`ksmWedgeReason = %q, want clean — bare "unauthorized" must not match`, got)
	}
}

// A clean tail falls through to the Prometheus counter half: an
// error-counter increase at/above the ksmReflectorErrorMinIncrease
// floor still wedges the pod (the spamming reflector can rotate the
// 401 storm out of the last tail lines), while a sub-floor increase —
// one routine reflector retry per 10m window, self-healing noise —
// and a missing series read clean.
func TestKSMWedgeReflectorErrorCounterHalf(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []probetest.PromTestSample
		want    string
	}{
		{"error increase wedges", []probetest.PromTestSample{{
			Labels: map[string]string{"pod": "kube-state-metrics-m"},
			Value:  42}}, leaseReasonKSMReflectorErrors},
		{"increase at the floor wedges", []probetest.PromTestSample{{
			Labels: map[string]string{"pod": "kube-state-metrics-m"},
			Value:  float64(ksmReflectorErrorMinIncrease)}}, leaseReasonKSMReflectorErrors},
		{"sub-floor increase is noise, not a wedge", []probetest.PromTestSample{{
			Labels: map[string]string{"pod": "kube-state-metrics-m"},
			Value:  float64(ksmReflectorErrorMinIncrease - 1)}}, ""},
		{"missing series is clean", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := probetest.PromTestServer(t,
				func(string) []probetest.PromTestSample { return tc.samples })
			pod := ksmPod("monitoring", "kube-state-metrics-m")
			cs := fake.NewSimpleClientset(pod)
			// Clean tail — the metrics half decides.
			cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
				"all quiet\n", nil))
			p, ch := leaseGuardProber(cs)
			p.Cfg.HTTPContent.URL = srv.URL
			p.HTTPClient = srv.Client()
			got, err := ch.ksmWedgeReason(ctx, pod)
			if err != nil {
				t.Fatalf("ksmWedgeReason err = %v, want %q", err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("ksmWedgeReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// A clean tail plus a FAILED Prometheus query is inconclusive, not
// healthy — the error propagates out of ksmWedgeReason so the sweep
// keeps tracking instead of clearing the wedge window.
func TestKSMWedgeReasonPromErrorInconclusive(t *testing.T) {
	pod := ksmPod("monitoring", "kube-state-metrics-promdown")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"all quiet\n", nil))
	_, ch := leaseGuardProber(cs)
	// Deps default points the query at a dead address — the instant
	// query fails.
	if _, err := ch.ksmWedgeReason(ctx, pod); err == nil {
		t.Fatal("a failed prometheus query must be inconclusive, not clean")
	}
}

// A log fetch failure is inconclusive, not clean.
func TestKSMWedgeLogFetchErrorInconclusive(t *testing.T) {
	pod := ksmPod("monitoring", "kube-state-metrics-logdown")
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"", errors.New("log fetch boom")))
	_, ch := leaseGuardProber(cs)
	if _, err := ch.ksmWedgeReason(ctx, pod); err == nil {
		t.Fatal("a failed log tail must be inconclusive, not clean")
	}
}

// ---------------------------------------------------------------------------
// The sweep postures around the verdict
// ---------------------------------------------------------------------------

// An inconclusive read keeps the pod's wedge tracking AND any held
// gauge series — it must never delete the pod, never clear the
// first-seen, and never prune the series: "could not evaluate" is
// not "resolved".
func TestKSMWedgeInconclusiveKeepsTracking(t *testing.T) {
	base := time.Now()
	pod := ksmPod("monitoring", "kube-state-metrics-inc")
	cs := fake.NewSimpleClientset(pod)
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)

	// Arm the wedge first — the pod is one sweep past first-seen.
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}
	if res := ch.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first wedge sighting must pass: %+v", res)
	}
	key := "monitoring/kube-state-metrics-inc"
	if _, ok := ch.wedgeSeen.Seen(key, base); !ok {
		t.Fatal("wedge key not tracked after the first sighting")
	}

	// The read goes inconclusive past the window — the pod survives
	// AND the tracking is not pruned (a clear would re-arm the
	// window for a signature that was never proven resolved).
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return "", errors.New("log tail unreachable")
	}
	probetest.FreezeNow(p.Deps, base.Add(ksmWedgeMinAge+time.Minute))
	res := ch.Run(probetest.SweepCtx(ctx))
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("inconclusive wedge deleted the pod: %v", err)
	}
	if _, ok := ch.wedgeSeen.Seen(key, base); !ok {
		t.Fatal("inconclusive sweep must keep the wedge first-seen")
	}
	_ = res // inconclusive is not a finding — nothing new is reported
}

// A pod that evaluates healthy loses its persisted first-seen stamp
// (the annotation dies on the pod) — a stale stamp would fast-trip
// the next wedge's window.
func TestKSMWedgeResolveClearsPersistedStamp(t *testing.T) {
	base := time.Now()
	pod := ksmPod("monitoring", "kube-state-metrics-resolve")
	pod.Annotations = map[string]string{
		kube.AnnoFirstSeenKSMWedge: `{"monitoring/kube-state-metrics-resolve":"` +
			base.Add(-(ksmWedgeMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`}
	srv, _ := probetest.PromTestServer(t,
		func(string) []probetest.PromTestSample { return nil })
	cs := fake.NewSimpleClientset(pod)
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return "", nil // clean tail AND a quiet counter — resolved
	}

	res := ch.Run(probetest.SweepCtx(ctx))
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy ksm pod deleted: %v", err)
	}
	got, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if raw := got.Annotations[kube.AnnoFirstSeenKSMWedge]; strings.Contains(raw, "kube-state-metrics-resolve") {
		t.Fatalf("resolved wedge kept its first-seen stamp: %q", raw)
	}
	if _, ok := ch.wedgeSeen.Seen(
		"monitoring/kube-state-metrics-resolve", base); ok {
		t.Fatal("resolved wedge kept its ledger entry")
	}
	_ = res
}

// The pod census is the wedge scan's only input — a list failure is
// Infra, and every held ksm_* series carries forward: "never
// evaluated" must not read as "resolved" (a stale-1 prune on an API
// flap would flap the alert AND re-arm the window).
func TestKSMWedgePodListErrorIsInfraAndCarries(t *testing.T) {
	base := time.Now()
	pod := ksmPod("monitoring", "kube-state-metrics-carry")
	cs := fake.NewSimpleClientset(pod)
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}
	// Seed the window already past minAge so this sweep emits.
	ch.wedgeSeen.Observe("monitoring/kube-state-metrics-carry",
		base.Add(-(ksmWedgeMinAge + time.Minute)))
	if res := ch.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("persisted wedge must fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "monitoring",
			"lease": "kube-state-metrics-carry", "reason": "ksm_unauthorized"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("precondition: ksm_unhealthy series not emitted")
	}
	t.Cleanup(func() {
		controllerLeaseUnhealthyGauge.DeleteLabelValues(
			"monitoring", "kube-state-metrics-carry", "ksm_unauthorized")
	})

	// Next sweep: the pod census is unlistable. The first sweep's
	// bounce already invalidated the census, so this list really
	// reaches the reactor.
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Infra == nil {
		t.Fatal("a pod list failure must mark the check infra-failed")
	}
	m = probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "monitoring",
			"lease": "kube-state-metrics-carry", "reason": "ksm_unauthorized"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("held ksm series was pruned by an API flap — must carry")
	}
}

// The persisted-window path driven by the REAL tail probe end to
// end: a 401 signature on the pod's log tail past the 10m window
// bounces the pod and reports the auth reason — the signature
// table's verdict lands in the gauge, not just the finding string.
func TestKSMWedgeRealTailBouncesAndReports(t *testing.T) {
	base := time.Now()
	pod := ksmPod("monitoring", "kube-state-metrics-e2e")
	pod.OwnerReferences = ksmOwnerRef("kube-state-metrics-e2e")
	pod.Annotations = map[string]string{
		kube.AnnoFirstSeenKSMWedge: `{"monitoring/kube-state-metrics-e2e":"` +
			base.Add(-(ksmWedgeMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		`E0101 reflector.go:1] Failed to watch *v1.Pod: 401 Unauthorized`+"\n", nil))
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)
	t.Cleanup(func() {
		controllerLeaseUnhealthyGauge.DeleteLabelValues(
			"monitoring", "kube-state-metrics-e2e", "ksm_unauthorized")
	})

	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("persisted 401 wedge must fail")
	}
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged ksm pod not bounced: %v", err)
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "monitoring",
			"lease": "kube-state-metrics-e2e", "reason": "ksm_unauthorized"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("ksm_unauthorized series missing after the bounce")
	}
}

// ---------------------------------------------------------------------------
// Marker precision + bounce gates (the 401 phrase fix)
// ---------------------------------------------------------------------------

// The 401 markers are full phrases — a bare "401" elsewhere in a line
// (a retry count, a byte count, a metric value) must NOT classify as
// the auth wedge, while both precise spellings still do.
func TestKSMWedgeMarkerPrecision(t *testing.T) {
	pod := ksmPod("monitoring", "kube-state-metrics-m401")
	quiet := []struct{ name, log string }{
		{"bare 401 number", "sync loop finished after 401 iterations\n"},
		{"4xx that is not 401", "probe wrote 4013 bytes, status 200 OK\n"},
	}
	for _, tc := range quiet {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(pod)
			cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(tc.log, nil))
			reason, err := ksmLogTailWedge(ctx, cs, pod)
			if err != nil {
				t.Fatalf("ksmLogTailWedge err = %v", err)
			}
			if reason != "" {
				t.Fatalf("bare-number line classified as %q — marker not phrase-precise", reason)
			}
		})
	}
	loud := []struct{ name, log string }{
		{"401 unauthorized phrase",
			"E0101 reflector.go:1] Failed to watch *v1.Pod: 401 Unauthorized\n"},
		{"status code 401 phrase",
			"E0101 watch.go:9] watch failed with status code 401\n"},
	}
	for _, tc := range loud {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(pod)
			cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(tc.log, nil))
			reason, err := ksmLogTailWedge(ctx, cs, pod)
			if err != nil {
				t.Fatalf("ksmLogTailWedge err = %v", err)
			}
			if reason != leaseReasonKSMUnauthorized {
				t.Fatalf("ksmLogTailWedge = %q, want %q", reason, leaseReasonKSMUnauthorized)
			}
		})
	}
}

// A wedged KSM pod with NO controller owner is reported (the gauge
// carries the alert) but never bounced — deleting a controller-less
// pod would remove kube-state-metrics permanently.
func TestKSMWedgeUnownedPodNotBounced(t *testing.T) {
	base := time.Now()
	pod := ksmPod("monitoring", "kube-state-metrics-lone")
	pod.Annotations = map[string]string{
		kube.AnnoFirstSeenKSMWedge: `{"monitoring/kube-state-metrics-lone":"` +
			base.Add(-(ksmWedgeMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(pod)
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}
	t.Cleanup(func() {
		controllerLeaseUnhealthyGauge.DeleteLabelValues(
			"monitoring", "kube-state-metrics-lone", "ksm_unauthorized")
	})

	res := ch.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("wedged controller-less ksm pod must still fail the check")
	}
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("controller-less wedged pod deleted: %v", err)
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "monitoring",
			"lease": "kube-state-metrics-lone", "reason": "ksm_unauthorized"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("ksm_unauthorized series missing for the un-bouncable pod")
	}
}

// The heal cooldown keys on the pod's CONTROLLER (kube.PodControllerKey):
// the replacement pod a bounce spawns inherits the 30m window — a
// fresh pod name cannot re-arm a new heal every sweep (the pod-bounce
// churn loop the old pod-scoped key allowed).
func TestKSMWedgeCooldownFollowsController(t *testing.T) {
	base := time.Now()
	pastWindow := func(name string) map[string]string {
		return map[string]string{
			kube.AnnoFirstSeenKSMWedge: `{"monitoring/` + name + `":"` +
				base.Add(-(ksmWedgeMinAge + time.Minute)).
					UTC().Format(time.RFC3339) + `"}`}
	}
	podA := ksmPod("monitoring", "kube-state-metrics-6cc5c9d9b4-x1")
	podA.OwnerReferences = ksmOwnerRef("kube-state-metrics-6cc5c9d9b4")
	podA.Annotations = pastWindow(podA.Name)
	cs := fake.NewSimpleClientset(podA)
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}
	t.Cleanup(func() {
		controllerLeaseUnhealthyGauge.DeleteLabelValues(
			"monitoring", "kube-state-metrics-6cc5c9d9b4-x1", "ksm_unauthorized")
		controllerLeaseUnhealthyGauge.DeleteLabelValues(
			"monitoring", "kube-state-metrics-6cc5c9d9b4-x2", "ksm_unauthorized")
	})

	if res := ch.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("precondition: first wedge must fail")
	}
	if _, err := cs.CoreV1().Pods("monitoring").Get(ctx, podA.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("first wedged pod not bounced: %v", err)
	}

	// The ReplicaSet respawns the pod under a NEW name inside the
	// cooldown window, wedged again with a persisted stamp past the
	// window.
	podB := ksmPod("monitoring", "kube-state-metrics-6cc5c9d9b4-x2")
	podB.OwnerReferences = ksmOwnerRef("kube-state-metrics-6cc5c9d9b4")
	podB.Annotations = pastWindow(podB.Name)
	if _, err := cs.CoreV1().Pods("monitoring").Create(ctx, podB, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(time.Minute))
	if res := ch.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("respawned wedge must keep failing the check")
	}
	if _, err := cs.CoreV1().Pods("monitoring").Get(ctx, podB.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("cooldown keyed on the pod name re-bounced the replacement: %v", err)
	}
}
