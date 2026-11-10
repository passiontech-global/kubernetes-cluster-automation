// nats_jetstream_health_test.go — coverage for the
// nats-jetstream-health check (nats-jetstream-health): the Prometheus wedge
// signals (jetstream disabled, meta leaderless, consumer ack-floor),
// the log-marker persistence window, the quorum-safe bounce, and the
// no-NATS / no-Prometheus postures.
package datastore

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// natsSTS builds a StatefulSet carrying the canonical helm label the
// discovery step matches on.
func natsSTS(ns, name string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name,
		Labels: map[string]string{"app.kubernetes.io/name": "nats"}}}
}

// natsMemberPod builds a member pod of the named StatefulSet — the
// canonical label plus a controller owner ref, so the per-cluster
// quorum census groups it correctly.
func natsMemberPod(ns, stsName, name string, ready bool) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{"app.kubernetes.io/name": "nats"}
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "StatefulSet", Name: stsName,
		UID: types.UID("sts-" + stsName), Controller: ptr.To(true)}}
	return pod
}

// natsProber wires the prom endpoint + client into the test prober.
func natsProber(cs *fake.Clientset, srv *httptest.Server) *probetest.Prober {
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	return p
}

// natsFixture is the standard 3-member cluster every wedge test
// starts from.
func natsFixture() []runtime.Object {
	return []runtime.Object{
		natsSTS("mq", "nats"),
		natsMemberPod("mq", "nats", "nats-0", true),
		natsMemberPod("mq", "nats", "nats-1", true),
		natsMemberPod("mq", "nats", "nats-2", true),
	}
}

// No NATS StatefulSets on the cluster — absence is tolerated, the
// check passes and never pays the pods List.
func TestNatsJetstreamNoNatsPasses(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	if res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("no nats statefulsets must pass: %+v", res)
	}
}

// Healthy cluster, Prometheus quiet — clean pass.
func TestNatsJetstreamHealthyPasses(t *testing.T) {
	srv, _ := probetest.PromTestServer(t,
		func(string) []probetest.PromTestSample { return nil })
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)
	if res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("healthy jetstream must pass: %+v", res)
	}
}

// A member running with JetStream disabled emits immediately (the
// metric IS the state), but the bounce waits out the 10m
// persistence window — then fires with 2 other Ready members.
func TestNatsJetstreamDisabledEmitsThenHeals(t *testing.T) {
	base := time.Now()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "jetstream_disabled") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "nats-0"},
				Value:  1}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	res := check.Run(ctx)
	if res.Pass {
		t.Fatal("jetstream_disabled member must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "jetstream_disabled"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("jetstream_disabled gauge must emit immediately")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err != nil {
		t.Fatal("the bounce must wait out the persistence window")
	}

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res = check.Run(ctx)
	if res.Pass {
		t.Fatal("persisted jetstream_disabled must keep failing")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err == nil {
		t.Fatal("wedged member must be deleted with quorum intact")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy members must survive: %v", err)
	}
}

// The heal cooldown keys on the pod's CONTROLLER (kube.PodControllerKey
// — the owning StatefulSet), not the pod name: the STS recreates a
// bounced member and the wedge evidence (the Prom series and the seen
// ledger) outlives the pod, so a fresh pod name must still read as the
// SAME heal target inside the 30m window — a name-keyed stamp never
// matches the replacement and the member bounces again on the very
// next sweep. The >=2 Ready-siblings quorum census is untouched.
func TestNatsJetstreamHealCooldownKeysOnController(t *testing.T) {
	base := time.Now()
	// The wedged member's name follows the pod the sweep actually
	// sees — it changes when the STS recreates the member.
	wedged := "nats-0"
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "jetstream_disabled") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": wedged},
				Value:  1}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)
	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)

	// Arm the 10m window, then sweep past it — nats-0 is bounced.
	probetest.FreezeNow(p.Deps, base)
	if res := check.Run(ctx); res.Pass {
		t.Fatal("jetstream_disabled member must FAIL the check")
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := check.Run(ctx); res.Pass {
		t.Fatal("persisted jetstream_disabled must keep failing")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err == nil {
		t.Fatal("wedged member must be bounced with quorum intact")
	}
	if _, ok := check.Heals.Last(probefw.SelfHealKey(
		CheckNameNatsJetstreamHealth, "mq/nats")); !ok {
		t.Fatal("heal stamp must key on the owning StatefulSet, not the pod name")
	}

	// The STS recreates the member — under a fresh name here — and the
	// wedge signature persists on the replacement.
	wedged = "nats-0-reborn"
	reborn := natsMemberPod("mq", "nats", wedged, true)
	if _, err := cs.CoreV1().Pods("mq").
		Create(ctx, reborn, metav1.CreateOptions{}); err != nil {
		t.Fatalf("recreate member: %v", err)
	}
	// The replacement inherits the wedge evidence: seed its first-seen
	// entry so the 10m window reads as already lapsed — only the heal
	// cooldown can hold the bounce now (the member is Ready and both
	// siblings are up, so the quorum guard would allow it).
	check.seen.Observe("mq/"+wedged+"/jetstream_disabled",
		base.Add(-time.Hour))

	probetest.FreezeNow(p.Deps, base.Add(12*time.Minute))
	if res := check.Run(ctx); res.Pass {
		t.Fatal("wedged replacement must keep the check failing")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, wedged, metav1.GetOptions{}); err != nil {
		t.Fatal("controller-keyed cooldown must hold: the recreated member " +
			"must not be bounced again inside the window")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy members must survive: %v", err)
	}
}

// A namespace whose meta-group lost its leader flags at namespace
// scope (empty pod label — no single culprit) and never heals a pod.
func TestNatsJetstreamMetaLeaderlessEmits(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "count by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 3}}
		case strings.Contains(query, "sum by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)

	res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("leaderless meta-group must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "",
			"reason": "meta_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("meta_leaderless gauge must emit at namespace scope")
	}
	for _, name := range []string{"nats-0", "nats-1", "nats-2"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("leaderless meta-group must not bounce pods: %v", err)
		}
	}
}

// A consumer pinned at its ack-floor stalls every delivery while
// nothing crashes — alert only, no bounce (a restart cannot move a
// consumption stall).
func TestNatsJetstreamAckFloorEmits(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "num_ack_pending"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"namespace": "mq", "pod": "nats-0",
					"stream_name": "events", "consumer_name": "worker"},
				Value: 5000}}
		case strings.Contains(query, "max_ack_pending"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"namespace": "mq", "pod": "nats-0",
					"stream_name": "events", "consumer_name": "worker"},
				Value: 5000}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)

	res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("consumer ack-floor stall must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "consumer_ack_floor"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("consumer_ack_floor gauge must emit")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err != nil {
		t.Fatal("ack-floor is a consumption stall — the pod must not be bounced")
	}
}

// The wedged pod's own Ready status must not count toward its
// sibling census — a cluster at 2/3 Ready drops to 1/3 (Raft quorum
// loss) if the gray-failed member is deleted.
func TestNatsJetstreamQuorumGuardSkipsHeal(t *testing.T) {
	base := time.Now()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "jetstream_disabled") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "nats-0"},
				Value:  1}}
		}
		return nil
	})
	objs := natsFixture()
	objs[3] = natsMemberPod("mq", "nats", "nats-2", false) // 2/3 Ready
	cs := fake.NewSimpleClientset(objs...)
	p := natsProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	_ = check.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(ctx)
	if res.Pass {
		t.Fatal("persisted wedge must still FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err != nil {
		t.Fatal("otherReady=1 — the delete would break Raft quorum")
	}
}

// A wedged member's log marker carries no timestamp — the 10m
// first-seen window IS its persistence clock, so the finding (and
// the bounce) only fire once it lapses. The reactor serves the same
// marker tail to every member, so all three flag: the gauge + the
// first bounced member prove the path.
func TestNatsJetstreamLogMarkerAfterWindow(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(natsFixture()...)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"INFO server started\nERR raft: lost leadership\n", nil))
	p := testProber(cs) // no prometheus — the log path stands alone
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	if res := check.Run(ctx); !res.Pass {
		t.Fatal("a fresh log marker must wait out its window")
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(ctx)
	if res.Pass {
		t.Fatal("a persisted log marker must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "raft_lost_leadership"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("raft_lost_leadership gauge must emit past the window")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err == nil {
		t.Fatal("persisted wedge with quorum intact must bounce members")
	}
}

// natsLogReason — the marker table is pure, so the match itself is
// testable without a log stream.
func TestNatsLogReason(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{"[WRN] JetStream not enabled, cannot start", "jetstream_disabled"},
		{"raft: lost leadership for '$G > _meta_' group", "raft_lost_leadership"},
		{"[WRN] RAFT [abc] - no meta leader", "no_meta_leader"},
		{"server is ready", ""},
	} {
		if got := natsLogReason(tc.line); got != tc.want {
			t.Fatalf("natsLogReason(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// stream-leaderless — stream leaderless
// ---------------------------------------------------------------------------

// The stream-leaderless stream markers map to stream_leaderless — pure table,
// no log stream needed.
func TestNatsLogReasonStreamLeaderless(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"[WRN] stream has no leader: events > A", "stream_leaderless"},
		{"[ERR] group has no leader", "stream_leaderless"},
		{"[INF] stream events has leader nats-0", ""},
	} {
		if got := natsLogReason(tc.line); got != tc.want {
			t.Fatalf("natsLogReason(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// Prometheus stream-leader loss resolves to member pods: the gauge
// emits immediately (the metric IS the state), and once the window
// lapses the wedged member bounces under the >=2-Ready-siblings
// quorum guard.
func TestNatsJetstreamStreamLeaderlessEmitsThenHeals(t *testing.T) {
	base := time.Now()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "min by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		case strings.Contains(query, "stream_leader"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "nats-0"},
				Value:  0}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	res := check.Run(ctx)
	if res.Pass {
		t.Fatal("stream_leaderless member must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "stream_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stream_leaderless gauge must emit immediately")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err != nil {
		t.Fatal("the bounce must wait out the persistence window")
	}

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res = check.Run(ctx)
	if res.Pass {
		t.Fatal("persisted stream_leaderless must still FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err == nil {
		t.Fatal("persisted wedge with quorum intact must bounce the member")
	}
	for _, name := range []string{"nats-1", "nats-2"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("healthy members must survive: %v", err)
		}
	}
}

// The quorum guard holds for the stream-leaderless reason too: at
// 2/3 Ready the wedge holder's own Ready status is discounted, so
// only ONE other member is Ready and the delete would break Raft
// quorum — skipped.
func TestNatsJetstreamStreamLeaderlessQuorumGuard(t *testing.T) {
	base := time.Now()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "min by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		case strings.Contains(query, "stream_leader"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "nats-0"},
				Value:  0}}
		}
		return nil
	})
	objs := natsFixture()
	objs[3] = natsMemberPod("mq", "nats", "nats-2", false) // 2/3 Ready
	cs := fake.NewSimpleClientset(objs...)
	p := natsProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	_ = check.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := check.Run(ctx); res.Pass {
		t.Fatal("persisted wedge must still FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err != nil {
		t.Fatal("otherReady=1 — the delete would break Raft quorum")
	}
}

// Series without pod labels (aggregate exporters) emit at namespace
// scope — no single culprit pod, so no bounce ever fires.
func TestNatsJetstreamStreamLeaderlessNamespaceScope(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "min by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		case strings.Contains(query, "stream_leader"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)

	res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("namespace-scope stream leader loss must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "",
			"reason": "stream_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stream_leaderless gauge must emit at namespace scope")
	}
	for _, name := range []string{"nats-0", "nats-1", "nats-2"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("namespace-scope verdict must not bounce pods: %v", err)
		}
	}
}

// Multi-stream partial leader loss: namespace "mq" runs two streams —
// events keeps its leader (series value 1) while orders lost hers
// (0). `sum by` would read 1 and miss the loss entirely; `min by`
// reads 0 and flags the namespace. The stub answers `sum by` with 1
// so a regression back to sum fails this test loudly.
func TestNatsJetstreamStreamLeaderlessPartialLoss(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "min by"):
			// min(events=1, orders=0) = 0 — the leaderless stream wins.
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		case strings.Contains(query, "sum by"):
			// Only reachable if the check regresses to `sum by` —
			// the summed value stays positive and the check passes.
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 1}}
		case strings.Contains(query, "stream_leader"):
			return []probetest.PromTestSample{
				{Labels: map[string]string{"namespace": "mq", "pod": "nats-0",
					"stream_name": "events"}, Value: 1},
				{Labels: map[string]string{"namespace": "mq", "pod": "nats-0",
					"stream_name": "orders"}, Value: 0},
			}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)

	res := probetest.MustCheck[*natsJetstreamHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("partial stream leader loss must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "stream_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stream_leaderless gauge must emit on partial leader loss")
	}
}

// Per-pod attribution: a namespace whose min series is 0 because ONE
// member lost a stream leader must not stamp the members whose own
// series are all positive — those still hold their leadership, and
// bouncing the leadership holder cascades leader loss (one bounce
// per 30m loop). Only the member whose OWN per-stream minimum is 0
// joins the healable pod-local path.
func TestNatsJetstreamStreamLeaderlessSparesLeadershipHolder(t *testing.T) {
	base := time.Now()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "min by"):
			// The namespace minimum reads 0 — nats-0 lost the orders
			// stream leader — but the OTHER members' series are all
			// positive: they still hold their streams.
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq"}, Value: 0}}
		case strings.Contains(query, "stream_leader"):
			return []probetest.PromTestSample{
				{Labels: map[string]string{"namespace": "mq", "pod": "nats-0",
					"stream_name": "orders"}, Value: 0},
				{Labels: map[string]string{"namespace": "mq", "pod": "nats-1",
					"stream_name": "events"}, Value: 1},
				{Labels: map[string]string{"namespace": "mq", "pod": "nats-2",
					"stream_name": "events"}, Value: 1},
			}
		}
		return nil
	})
	cs := fake.NewSimpleClientset(natsFixture()...)
	p := natsProber(cs, srv)
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*natsJetstreamHealthCheck](t, p)
	res := check.Run(ctx)
	if res.Pass {
		t.Fatal("stream_leaderless member must FAIL the check")
	}
	m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
		map[string]string{"namespace": "mq", "pod": "nats-0",
			"reason": "stream_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("the per-pod culprit member must stamp")
	}
	for _, holder := range []string{"nats-1", "nats-2"} {
		if m := probetest.FindMetric(t, "node_automation_nats_jetstream_unhealthy",
			map[string]string{"namespace": "mq", "pod": holder,
				"reason": "stream_leaderless"}); m != nil {
			t.Fatalf("leadership holder %s must not stamp — bouncing it would cascade leader loss", holder)
		}
	}

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := check.Run(ctx); res.Pass {
		t.Fatal("persisted stream_leaderless must still FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "nats-0", metav1.GetOptions{}); err == nil {
		t.Fatal("the culprit member must bounce past the window")
	}
	for _, holder := range []string{"nats-1", "nats-2"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, holder, metav1.GetOptions{}); err != nil {
			t.Fatalf("leadership holder %s must survive the sweep", holder)
		}
	}
}

// natsSTSKey resolves the StatefulSet owning a member pod — the
// per-cluster quorum-census grouping key. The controller owner ref
// wins; the "<sts>-<ordinal>" name shape is the fallback for a pod
// whose owner ref was stripped, and a dash-less name groups under
// itself so two clusters can never pool members.
func TestNatsSTSKey(t *testing.T) {
	stsOwned := func() *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "mq", Name: "nats-1",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "StatefulSet", Name: "nats-cluster-a",
				Controller: ptr.To(true)}}}}
	}
	if got := natsSTSKey(stsOwned()); got != "mq/nats-cluster-a" {
		t.Fatalf("owner-ref key = %q, want mq/nats-cluster-a", got)
	}
	// A non-StatefulSet controller (or a non-controller ref) falls
	// through to the name shape.
	rsOwned := stsOwned()
	rsOwned.OwnerReferences[0].Kind = "ReplicaSet"
	if got := natsSTSKey(rsOwned); got != "mq/nats" {
		t.Fatalf("replicaset-owned key = %q, want mq/nats", got)
	}
	bare := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "mq", Name: "nats-2"}}
	if got := natsSTSKey(bare); got != "mq/nats" {
		t.Fatalf("name-shape key = %q, want mq/nats", got)
	}
	// Dash-less and trailing-dash names still resolve to a stable
	// group key — never an empty or truncated one.
	for name, want := range map[string]string{
		"nats":    "mq/nats",
		"nats-":   "mq/nats",
		"a-b-c-0": "mq/a-b-c",
	} {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "mq", Name: name}}
		if got := natsSTSKey(p); got != want {
			t.Errorf("natsSTSKey(%q)=%q, want %q", name, got, want)
		}
	}
}
