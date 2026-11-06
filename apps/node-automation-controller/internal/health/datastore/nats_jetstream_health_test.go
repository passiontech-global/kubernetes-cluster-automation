// nats_jetstream_health_test.go — coverage for the
// nats-jetstream-health check (W12-ST1): the Prometheus wedge
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
