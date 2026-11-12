// rabbitmq_quorum_health_test.go — coverage for the
// rabbitmq-quorum-health check (rabbitmq-quorum-health): alarm FAIL, stuck-
// unready heal with quorum, healthy pass.
package rabbitmq

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func TestRabbitMQQuorumAlarmFails(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, rabbitMQMemberPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("fd-limit alarm must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "rabbitmq-server-0") ||
		!strings.Contains(res.Why, "fd_limit_alarm") {
		t.Fatalf("why missing diagnostics: %q", res.Why)
	}
}

// Restart resume: a member pod still carrying the persisted
// first-seen stamp for its alarm signal heals on the FIRST
// post-restart sweep — the in-RAM ledger is empty but the
// annotation proves the signal held past the 10m window.
func TestRabbitMQQuorumPromResumeHeals(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	flagged := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	flagged.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-0":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(flagged, r1, r2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("persisted quorum window past 10m must FAIL on the first sweep")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("resumed window must heal on the first sweep, err=%v", err)
	}
}

func TestRabbitMQQuorumStuckUnreadyHeal(t *testing.T) {
	// Prometheus dead -> pod signature still heals: unready >10m
	// with >=2 Ready siblings.
	bad := rabbitMQMemberPod("mq", "rabbitmq-server-0", false)
	bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-15 * time.Minute))
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(bad, r1, r2)
	p := testProber(cs)

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("stuck-unready quorum member must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unready pod should be deleted with quorum intact, err=%v", err)
	}
}

// The Ready census is decremented only for a pod it actually counted
// (PodRunningReady): the pass-1 stuck-unready delete below must not
// shrink the tally the pass-2 partitioned-Ready candidate's quorum
// gate reads — and the one-heal-per-cluster guard still caps the
// sweep at a single delete.
func TestRabbitMQQuorumUnreadyDeleteKeepsReadyCensus(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "dist_node_state") {
			// Partitioned-but-Ready member: node_state != 3.
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-3"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	unready := rabbitMQMemberPod("mq", "rabbitmq-server-2", false)
	unready.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		base.Add(-15 * time.Minute))
	partitioned := rabbitMQMemberPod("mq", "rabbitmq-server-3", true)
	partitioned.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-3":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(r1, r2, unready, partitioned)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("stuck-unready + mnesia partition must FAIL")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-server-2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stuck-unready member must be healed first, err=%v", err)
	}
	// The partitioned-Ready member survives: its quorum gate reads
	// the census the unready delete did not decrement, and the
	// one-per-cluster guard blocks the second same-sweep heal.
	for _, name := range []string{
		"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-3"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("ready census member %s must survive: %v", name, err)
		}
	}
}

// A RabbitmqCluster parked at spec.replicas:0 by the
// go-kube-downscaler — lingering alarm series and a still-present
// unready member are sleep, not quorum evidence: nothing flags,
// nothing heals.
func TestRabbitMQQuorumDownscaledClusterSkipped(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	cr := probetest.UnstructuredObj("rabbitmq.com/v1beta1", "RabbitmqCluster",
		"mq", "rabbitmq", 1, 0)
	cr.SetAnnotations(map[string]string{"downscaler/force-downtime": "true"})
	cr.Object["spec"] = map[string]any{"replicas": int64(0)}
	bad := rabbitMQMemberPod("mq", "rabbitmq-server-0", false)
	bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-15 * time.Minute))
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	cs := fake.NewSimpleClientset(bad, r1)
	p := testProberDyn(cs, probetest.OpDyn(cr))
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if !res.Pass {
		t.Fatalf("downscaled cluster must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("downscaled member pod must not be healed: %v", err)
	}
}

func TestRabbitMQQuorumHealthyPasses(t *testing.T) {
	pods := []runtime.Object{
		rabbitMQMemberPod("mq", "rabbitmq-server-0", true),
		rabbitMQMemberPod("mq", "rabbitmq-server-1", true),
		rabbitMQMemberPod("mq", "rabbitmq-server-2", true),
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("healthy quorum must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// rabbitmq-quorum-heal — the quorum-breaking delete fixes.
// ---------------------------------------------------------------------------

// Sub-bug (a): the Ready census is per RabbitmqCluster, not per
// namespace — rmq-a's unready member must NOT be healed on the
// strength of rmq-b's Ready pods sharing the namespace.
func TestRabbitMQQuorumPerClusterCensus(t *testing.T) {
	bad := rabbitMQClusterPod("mq", "rmq-a", "rmq-a-server-0", false)
	bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		time.Now().Add(-15 * time.Minute))
	a1 := rabbitMQClusterPod("mq", "rmq-a", "rmq-a-server-1", true)
	// rmq-a's third member is unready but only 5m — inside the
	// persistence window so it flags nothing; it still keeps rmq-a
	// at a single Ready member.
	a2 := rabbitMQClusterPod("mq", "rmq-a", "rmq-a-server-2", false)
	a2.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		time.Now().Add(-5 * time.Minute))
	b0 := rabbitMQClusterPod("mq", "rmq-b", "rmq-b-server-0", true)
	b1 := rabbitMQClusterPod("mq", "rmq-b", "rmq-b-server-1", true)
	b2 := rabbitMQClusterPod("mq", "rmq-b", "rmq-b-server-2", true)
	cs := fake.NewSimpleClientset(bad, a1, a2, b0, b1, b2)
	p := testProber(cs)

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("stuck-unready member must still FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rmq-a-server-0",
		metav1.GetOptions{}); err != nil {
		t.Fatal("rmq-a has only 1 other Ready member — the delete must " +
			"not borrow rmq-b's census (per-cluster grouping)")
	}
}

// Sub-bug (a) fallback: member pods missing the
// app.kubernetes.io/name label group by controller owner UID — a
// different StatefulSet's Ready members must not lend quorum, and a
// same-owner unready member DOES heal with 2 Ready siblings.
func TestRabbitMQQuorumOwnerFallbackCensus(t *testing.T) {
	t.Run("other owner's members do not count", func(t *testing.T) {
		bad := rabbitMQOwnedPod("mq", "x-server-0", false, "sts-a")
		bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
			time.Now().Add(-15 * time.Minute))
		a1 := rabbitMQOwnedPod("mq", "x-server-1", true, "sts-a")
		b0 := rabbitMQOwnedPod("mq", "y-server-0", true, "sts-b")
		b1 := rabbitMQOwnedPod("mq", "y-server-1", true, "sts-b")
		b2 := rabbitMQOwnedPod("mq", "y-server-2", true, "sts-b")
		cs := fake.NewSimpleClientset(bad, a1, b0, b1, b2)
		p := testProber(cs)

		if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
			t.Fatal("stuck-unready member must still FAIL the check")
		}
		if _, err := cs.CoreV1().Pods("mq").Get(ctx, "x-server-0",
			metav1.GetOptions{}); err != nil {
			t.Fatal("owner fallback pooled another controller's Ready members")
		}
	})

	t.Run("same owner with 2 ready siblings heals", func(t *testing.T) {
		bad := rabbitMQOwnedPod("mq", "x-server-0", false, "sts-a")
		bad.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
			time.Now().Add(-15 * time.Minute))
		a1 := rabbitMQOwnedPod("mq", "x-server-1", true, "sts-a")
		a2 := rabbitMQOwnedPod("mq", "x-server-2", true, "sts-a")
		cs := fake.NewSimpleClientset(bad, a1, a2)
		p := testProber(cs)

		if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
			t.Fatal("stuck-unready member must FAIL the check")
		}
		if _, err := cs.CoreV1().Pods("mq").Get(ctx, "x-server-0",
			metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("owner-grouped pod with quorum intact should be deleted, err=%v", err)
		}
	})
}

// Sub-bug (b): a Ready-but-alarmed member must not count toward its
// own sibling census — a 3-node cluster already at 2/3 Ready drops
// to 1/3 (Raft quorum loss) if the alarmed pod is deleted.
func TestRabbitMQQuorumReadyAlarmDoesNotSelfCount(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "memory_used_watermark") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	flagged := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	flagged.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-0":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	// Third member down but only 5m — inside the persistence
	// window, flags nothing, keeps the cluster at 2/3 Ready.
	down := rabbitMQMemberPod("mq", "rabbitmq-server-2", false)
	down.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		base.Add(-5 * time.Minute))
	cs := fake.NewSimpleClientset(flagged, r1, down)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("persisted alarm must FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0",
		metav1.GetOptions{}); err != nil {
		t.Fatal("alarmed pod deleted — 2/3 Ready drops to 1/3 (Raft " +
			"quorum loss); the target must not count toward its own census")
	}
}

// Sub-bug (c): disk_watermark_alarm NEVER deletes the pod — a
// delete cannot free the PVC and the restart replays the
// quorum-queue WAL onto a still-full disk. The check still FAILs
// and emits the alarm gauge.
func TestRabbitMQQuorumDiskWatermarkNeverHeals(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "free_disk_space_watermark") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	flagged := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	flagged.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-0":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(flagged, r1, r2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("disk_watermark_alarm must FAIL the check")
	}
	if !strings.Contains(res.Why, "disk_watermark_alarm") {
		t.Fatalf("why missing the alarm reason: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0",
		metav1.GetOptions{}); err != nil {
		t.Fatal("disk_watermark_alarm must never delete — the pod " +
			"cannot free its own PVC")
	}
	m := probetest.FindMetric(t, "node_automation_rabbitmq_quorum_unhealthy",
		map[string]string{
			"namespace": "mq", "pod": "rabbitmq-server-0",
			"reason": "disk_watermark_alarm"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("disk_watermark_alarm gauge must still emit")
	}
}

// Sub-bug (c) boundary: a disk_watermark_alarm stacked WITH a
// healable reason does heal — the guard excludes the disk-only
// shape, not every finding set that mentions the disk.
func TestRabbitMQQuorumDiskPlusHealableHeals(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "free_disk_space_watermark") ||
			strings.Contains(query, "memory_used_watermark") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	flagged := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	flagged.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-0":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	r1 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-2", true)
	cs := fake.NewSimpleClientset(flagged, r1, r2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("stacked alarms must FAIL the check")
	}
	if _, err := cs.CoreV1().Pods("mq").Get(ctx, "rabbitmq-server-0",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("disk+memory alarm with quorum intact should heal, err=%v", err)
	}
}

// rabbitMQMemberPod builds a member pod of the "rabbitmq"
// RabbitmqCluster.
func rabbitMQMemberPod(ns, name string, ready bool) *corev1.Pod {
	return rabbitMQClusterPod(ns, "rabbitmq", name, ready)
}

// rabbitMQClusterPod builds a member pod of the named
// RabbitmqCluster — the operator stamps app.kubernetes.io/name with
// the owning CR's name next to the part-of/component labels
// isRabbitMQPod matches on; the per-cluster census keys on it
// (rabbitmq-quorum-heal).
func rabbitMQClusterPod(ns, cluster, name string, ready bool) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/name":      cluster,
		"app.kubernetes.io/part-of":   "rabbitmq",
		"app.kubernetes.io/component": "rabbitmq",
	}
	return pod
}

// rabbitMQOwnedPod builds a member pod WITHOUT the
// app.kubernetes.io/name label — the census falls back to
// controller-owner grouping by StatefulSet UID (rabbitmq-quorum-heal).
func rabbitMQOwnedPod(ns, name string, ready bool, ownerUID string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Labels = map[string]string{
		"app.kubernetes.io/component": "rabbitmq",
	}
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "StatefulSet", Name: name + "-sts",
		UID: types.UID(ownerUID), Controller: ptr.To(true)}}
	return pod
}

// quorum-raft-health — a member whose rabbitmq_raft_role series exist but sum
// to 0 has lost leadership on every replicated quorum queue: the
// quorum_leaderless reason FAILs the check, flags the gauge, and —
// deliberately NOT healable — never deletes the pod (deleting a
// member of a degraded queue membership can drop the queue under
// its own Raft quorum).
func TestRabbitMQQuorumLeaderlessFlagged(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "sum by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  0}}
		case strings.Contains(query, "count by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  3}}
		case strings.Contains(query, "raft_term"):
			return nil
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, rabbitMQMemberPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("quorum_leaderless must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "rabbitmq-server-0") ||
		!strings.Contains(res.Why, "quorum_leaderless") {
		t.Fatalf("why missing quorum_leaderless diagnostics: %q", res.Why)
	}
	m := probetest.FindMetric(t, "node_automation_rabbitmq_quorum_unhealthy",
		map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0",
			"reason": "quorum_leaderless"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("quorum_leaderless gauge must flag the leaderless member")
	}
	// Alert-only: the leaderless member must survive the sweep even
	// with quorum intact.
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-server-0", metav1.GetOptions{}); err != nil {
		t.Fatal("quorum_leaderless is alert-only — the pod must not be deleted")
	}
}

// A member holding at least one raft role (sum > 0) is healthy — no
// quorum_leaderless flag even when its peers' series exist.
func TestRabbitMQQuorumLeaderWithRolesPasses(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		switch {
		case strings.Contains(query, "sum by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  2}}
		case strings.Contains(query, "count by"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  3}}
		case strings.Contains(query, "raft_term"):
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  7}}
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, rabbitMQMemberPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("a member holding raft roles must pass: %+v", res)
	}
}

// quorum-raft-health — quorum_skew pools raft terms per RabbitmqCLUSTER, never
// per namespace: a second cluster sharing the namespace must not
// judge the first cluster's terms (rabbitmq-quorum-heal hazard), and a member
// genuinely lagging its OWN cluster's max term by >= 2 flags.
func TestRabbitMQQuorumSkewClusterScoped(t *testing.T) {
	// Cluster alpha (term 10 across members) and cluster beta
	// (term 5) share namespace mq — beta must NOT flag even though
	// 10-5 >= 2 crosses namespaces.
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "raft_term") {
			terms := []probetest.PromTestSample{
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-alpha-0"}, Value: 10},
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-alpha-1"}, Value: 10},
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-beta-0"}, Value: 5},
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-beta-1"}, Value: 5},
			}
			for i := range terms {
				terms[i].Labels["pod_name"] = terms[i].Labels["pod"]
			}
			return terms
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-alpha-0", "rabbitmq-alpha-1"} {
		pods = append(pods, rabbitMQClusterPod("mq", "alpha", n, true))
	}
	for _, n := range []string{"rabbitmq-beta-0", "rabbitmq-beta-1"} {
		pods = append(pods, rabbitMQClusterPod("mq", "beta", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	if res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).
		Run(ctx); !res.Pass {
		t.Fatalf("cross-cluster term gap must not flag skew: %+v", res)
	}
	for _, pod := range []string{"rabbitmq-alpha-0", "rabbitmq-beta-1"} {
		if m := probetest.FindMetric(t, "node_automation_rabbitmq_quorum_unhealthy",
			map[string]string{"namespace": "mq", "pod": pod, "reason": "quorum_skew"}); m != nil {
			t.Fatalf("cross-cluster term gap must not flag %s", pod)
		}
	}
}

// A member lagging its OWN cluster's max term by >= 2 elections
// flags quorum_skew (alert-only — the pod survives the sweep).
func TestRabbitMQQuorumSkewFlagsLaggingMember(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "raft_term") {
			terms := []probetest.PromTestSample{
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0", "pod_name": "rabbitmq-server-0"}, Value: 10},
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-1", "pod_name": "rabbitmq-server-1"}, Value: 10},
				{Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-2", "pod_name": "rabbitmq-server-2"}, Value: 7},
			}
			return terms
		}
		return nil
	})
	pods := []runtime.Object{}
	for _, n := range []string{"rabbitmq-server-0", "rabbitmq-server-1", "rabbitmq-server-2"} {
		pods = append(pods, rabbitMQMemberPod("mq", n, true))
	}
	cs := fake.NewSimpleClientset(pods...)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("an in-cluster term laggard must fail: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_rabbitmq_quorum_unhealthy",
		map[string]string{"namespace": "mq", "pod": "rabbitmq-server-2",
			"reason": "quorum_skew"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("quorum_skew gauge must flag the lagging member")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-server-2", metav1.GetOptions{}); err != nil {
		t.Fatal("quorum_skew is alert-only — the pod must not be deleted")
	}
}

// ---------------------------------------------------------------------------
// heal-budget — the per-cluster heal budget.
// ---------------------------------------------------------------------------

// At most ONE member pod per RabbitmqCluster is deleted per sweep,
// even when several qualify: the first delivered delete decrements
// the Ready census AND sets the per-cluster break, so a sweep can
// never halve a cluster. Here the stuck-unready pod heals first
// (2 Ready siblings), the census drops to 1 — and the persisted
// alarm on the still-Ready member plus the second unready member
// both stay untouched this sweep.
func TestRabbitMQQuorumOnePodPerClusterPerSweep(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "file_descriptor_limit") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"namespace": "mq", "pod": "rabbitmq-server-0"},
				Value:  1,
			}}
		}
		return nil
	})
	base := time.Now()
	alarmedReady := rabbitMQMemberPod("mq", "rabbitmq-server-0", true)
	alarmedReady.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitQuorum: `{"prom/mq/rabbitmq-server-0":"` +
			base.Add(-15*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	r2 := rabbitMQMemberPod("mq", "rabbitmq-server-1", true)
	unready1 := rabbitMQMemberPod("mq", "rabbitmq-server-2", false)
	unready1.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		base.Add(-15 * time.Minute))
	unready2 := rabbitMQMemberPod("mq", "rabbitmq-server-3", false)
	unready2.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		base.Add(-15 * time.Minute))
	cs := fake.NewSimpleClientset(alarmedReady, r2, unready1, unready2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*rabbitMQQuorumHealthCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("the sweep must still FAIL on the findings")
	}
	deleted, alive := 0, 0
	for _, name := range []string{
		"rabbitmq-server-0", "rabbitmq-server-2", "rabbitmq-server-3"} {
		if _, err := cs.CoreV1().Pods("mq").
			Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			deleted++
			continue
		}
		alive++
	}
	if deleted != 1 || alive != 2 {
		t.Fatalf("exactly one pod per cluster per sweep may heal: "+
			"deleted=%d alive=%d", deleted, alive)
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-server-2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("the first stuck-unready candidate must be the one healed, err=%v", err)
	}
}
