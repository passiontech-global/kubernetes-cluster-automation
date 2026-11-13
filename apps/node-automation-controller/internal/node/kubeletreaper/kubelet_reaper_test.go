// kubelet_reaper_test.go — the taint action's per-target
// non-convergent circuit breaker: an open breaker defers the taint
// (sweep stays a nil-error defer), a fresh circuit taints as before,
// and a healthy probe clears the node's history.
package kubeletreaper

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// krStaleNode builds a dead-kubelet worker: its Ready heartbeat is
// minutes old AND it posts no kube-node-lease Lease — no renewal
// evidence, the taint decision's precondition.
func krStaleNode(name string) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Status.Conditions[0].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-10 * time.Minute))
	return n
}

// krLease stamps the kube-node-lease heartbeat Lease for node with a
// renewal `age` old (negative = dated in the future — clock skew).
func krLease(node string, age time.Duration) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kubeletLeaseNamespace,
			Name:      node,
		},
		Spec: coordinationv1.LeaseSpec{
			RenewTime: &metav1.MicroTime{Time: time.Now().Add(-age)},
		},
	}
}

// krReaper builds the sweep fixture: direct clientset, pinned clock,
// the registry ops name as the breaker's module label.
func krReaper(cs *fake.Clientset, now time.Time) *kubeletReaper {
	return &kubeletReaper{
		cs:    cs,
		queue: "kubelet-liveness-reaper",
		now:   shared.NewClock(func() time.Time { return now }),
	}
}

// krConfigureBreaker arms the package-global breaker with a tight
// window and pre-charges (module,node) to its limit — the circuit is
// open before the sweep runs. Cleaning up drops the global state so
// no sibling test inherits it.
func krConfigureBreaker(t *testing.T, module, node string, now time.Time) {
	t.Helper()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	for range 3 {
		heal.TryAcquireTarget(module, node, now)
	}
}

// A node the breaker already opened for defers its taint: nothing
// lands on the node, and the sweep absorbs the defer without an
// error (no IncError loop over the queue).
func TestKubeletReaperDefersTaintUnderOpenCircuit(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	krConfigureBreaker(t, "kubelet-liveness-reaper", "w1", now)
	r := krReaper(cs, now)
	if err := r.sweep(t.Context(), n, false); err != nil {
		t.Fatalf("open circuit must defer, not error: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("taint applied while the target circuit is open")
	}
}

// The same decision on a fresh circuit taints as before — the
// breaker never blocks first-line remediation of a node it has not
// already acted on.
func TestKubeletReaperFreshCircuitTaints(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, now)
	if err := r.sweep(t.Context(), n, false); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("fresh circuit did not taint the stale-kubelet node")
	}
}

// A healthy probe clears the node's breaker history: after three
// taints and a recovery, the breaker grants again — a kubelet
// restart ends the episode instead of banking against the next one.
func TestKubeletReaperHealthyProbeClearsHistory(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	krConfigureBreaker(t, "kubelet-liveness-reaper", "w1", now)
	r := krReaper(cs, now)
	if err := r.sweep(t.Context(), n, true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := heal.TryAcquireTarget("kubelet-liveness-reaper", "w1",
		now.Add(time.Minute)); !ok {
		t.Fatal("healthy probe did not clear the node's breaker history")
	}
}

// ---------------------------------------------------------------------------
// run() — the sweep driver: parallel probes, the zero-success abort,
// control-plane skip, and per-node error absorption.
// ---------------------------------------------------------------------------

// krRunReaper builds the reaper with a stubbed probeFn — the apiserver
// REST path the fake clientset cannot serve.
func krRunReaper(cs *fake.Clientset, now time.Time,
	probe func(ctx context.Context, node string) bool) *kubeletReaper {

	r := krReaper(cs, now)
	r.probeFn = probe
	return r
}

// A node census failure is the run's only hard error — the periodic
// meters it through the returned error.
func TestKubeletReaperRunListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
	r := krRunReaper(cs, time.Now(), func(context.Context, string) bool { return true })
	if err := r.run(t.Context()); err == nil {
		t.Fatal("node list failure must return an error")
	}
}

// Zero successful probes across MULTIPLE nodes means the probe PATH
// is broken (apiserver or konnectivity), not that every kubelet
// died — the run aborts before any taint decision rather than
// mass-tainting the fleet. (A single failing node is NOT abort
// evidence: on a one-worker cluster it is exactly the fake-ready
// case the reaper exists for — the per-node lease/persistence
// gates decide.)
func TestKubeletReaperRunAbortsWhenNoProbeSucceeds(t *testing.T) {
	cp := testutil.Node("cp1", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})
	w1 := krStaleNode("w1")
	w2 := krStaleNode("w2")
	cs := fake.NewSimpleClientset(cp, w1, w2)
	var probed []string
	var mu sync.Mutex
	r := krRunReaper(cs, time.Now(),
		func(_ context.Context, node string) bool {
			mu.Lock()
			probed = append(probed, node)
			mu.Unlock()
			return false
		})
	if err := r.run(t.Context()); err != nil {
		t.Fatalf("all-fail run must absorb, not error: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("tainted on a dead probe path — the mass-taint guard failed")
	}
	for _, n := range probed {
		if n == "cp1" {
			t.Fatal("control-plane node was probed — k0s CPs run no kubelet")
		}
	}
	if len(probed) != 2 {
		t.Fatalf("probed = %v, want both workers", probed)
	}
	for _, w := range []string{"w1", "w2"} {
		if kube.HasTaint(testutil.GetNode(t, cs, w).Spec.Taints, kubeletReaperTaint) {
			t.Fatalf("%s tainted on a dead probe path — the mass-taint guard failed", w)
		}
	}
}

// The healthy/dead split: a serving kubelet clears its marks, a dead
// one with no lease renewal gets the NoSchedule taint — and the
// control-plane node is never probed nor swept.
func TestKubeletReaperRunTaintsOnlyTheDeadWorker(t *testing.T) {
	cp := testutil.Node("cp1", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})
	wOK := testutil.Node("w-ok", corev1.ConditionTrue, nil)
	wDead := krStaleNode("w-dead")
	wDead.Spec.Taints = []corev1.Taint{{
		Key: kubeletReaperTaint, Effect: corev1.TaintEffectNoSchedule}}
	// w-alive: probe fails but the kubelet renews its heartbeat
	// Lease — inside the persistence grace, no taint.
	wAlive := krStaleNode("w-alive") // stale heartbeat does NOT mean dead
	cs := fake.NewSimpleClientset(cp, wOK, wDead, wAlive)
	for _, lease := range []*coordinationv1.Lease{
		krLease("w-ok", 5*time.Second), krLease("w-alive", 5*time.Second),
	} {
		if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Create(ctx, lease, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	r := krRunReaper(cs, now,
		func(_ context.Context, node string) bool { return node == "w-ok" })
	if err := r.run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// w-dead already carried the taint -> kept (no lease renewal).
	if !kube.HasTaint(testutil.GetNode(t, cs, "w-dead").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("dead worker (stale lease) lost its taint")
	}
	// w-alive: probe failed but the lease proves life -> no taint.
	if kube.HasTaint(testutil.GetNode(t, cs, "w-alive").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("lease-renewing worker tainted — broken proxy path punished")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w-ok").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("healthy worker tainted")
	}
}

// A per-node sweep failure is absorbed — logged, IncError'd, and the
// remaining nodes still get their decision (the bash loop's
// best-effort contract).
func TestKubeletReaperRunAbsorbsSweepErrors(t *testing.T) {
	wBad := krStaleNode("w-bad")
	wDead := krStaleNode("w-dead")
	cs := fake.NewSimpleClientset(wBad, wDead)
	// The re-Get inside sweep fails for w-bad — but only the FIRST
	// one, so the test's own verification Get below still reads the
	// node back.
	badGets := 0
	cs.PrependReactor("get", "nodes",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.GetAction).GetName() == "w-bad" {
				badGets++
				if badGets == 1 {
					return true, nil, errors.New("get boom")
				}
			}
			return false, nil, nil
		})
	// One healthy node keeps anyOK true so the sweep runs at all —
	// zero successes would abort before any per-node decision.
	wOK := testutil.Node("w-ok", corev1.ConditionTrue, nil)
	if _, err := cs.CoreV1().Nodes().Create(t.Context(), wOK, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	r := krRunReaper(cs, time.Now(),
		func(_ context.Context, node string) bool { return node == "w-ok" })
	if err := r.run(t.Context()); err != nil {
		t.Fatalf("sweep error must be absorbed into a nil return: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w-dead").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("w-dead not tainted — the w-bad failure blocked the sweep")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w-bad").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("w-bad tainted despite its get failing")
	}
}

// ---------------------------------------------------------------------------
// sweep() — the liveness gate: the kube-node-lease Lease renewal
// stamp is the proof of life, not the Ready heartbeat.
// ---------------------------------------------------------------------------

// THE REGRESSION: a kubelet refreshes Ready's lastHeartbeatTime only
// when it patches its Node status (5m cadence + jitter, skipped when
// nothing changed), so a HEALTHY kubelet routinely reads minutes
// stale. A probe failure on a broken proxy path must not taint it
// while its Lease renewal (every ~10s) proves life.
func TestKubeletReaperFreshLeaseSkipsTaintDespiteStaleHeartbeat(t *testing.T) {
	n := krStaleNode("w1") // heartbeat 10m old — "stale" under the old gate
	cs := fake.NewSimpleClientset(n)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := krReaper(cs, now)
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("lease-renewing kubelet tainted on a stale heartbeat stamp")
	}
}

// The mirror direction pins the swap: a fresh heartbeat does NOT mask
// a dead kubelet. The stamp is a leftover from the last status patch
// before the kubelet died; the untouched Lease renewal is the verdict.
func TestKubeletReaperStaleLeaseTaintsDespiteFreshHeartbeat(t *testing.T) {
	n := testutil.Node("w1", corev1.ConditionTrue, nil)
	// Fresh Ready heartbeat — the exact signal the pre-lease gate
	// trusted. The stale lease below must still taint.
	n.Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(time.Now())
	cs := fake.NewSimpleClientset(n)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Minute), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, now)
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("kubelet with a dead lease renewal not tainted")
	}
}

// A renewal dated in the FUTURE is clock skew, not staleness — proof
// of life (the same clamp the Ready gate carried).
func TestKubeletReaperFutureLeaseRenewalSkipsTaint(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", -30*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := krReaper(cs, now)
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("future-dated renewal (clock skew) read as staleness")
	}
}

// An unreadable Lease is not evidence of death — the sweep fails
// closed (returns an error, taints nothing) instead of tainting on
// its own read failure.
func TestKubeletReaperLeaseGetErrorFailsClosed(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	cs.PrependReactor("get", "leases",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("lease get boom")
		})
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, now)
	if err := r.sweep(ctx, n, false); err == nil {
		t.Fatal("lease read failure must fail the node's sweep, not taint")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("node tainted while its lease was unreadable")
	}
}

// THE P0-11 REGRESSION: the fake-ready wedge — kubelet renews its
// Lease (node stays Ready) while :10250 hangs — must NOT be
// suppressed by the fresh lease. First observation skips (a proxy
// flap gets the grace window); once the probe-fail persists past
// kubeletReaperLeaseFreshGrace with the lease still fresh, the
// node taints.
func TestKubeletReaperFreshLeaseFakeReadyTaintsAfterGrace(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := &kubeletReaper{
		cs:    cs,
		queue: "kubelet-liveness-reaper",
		now:   shared.NewClock(func() time.Time { return now }),
	}
	// renewLease keeps the heartbeat fresh as the fake clock
	// advances — a live kubelet renews every ~10s, so each sweep
	// sees a renewal stamped at "now".
	renewLease := func() {
		t.Helper()
		l, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Get(ctx, "w1", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		l.Spec.RenewTime = &metav1.MicroTime{Time: now}
		if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Update(ctx, l, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// First observation — inside the grace window, no taint.
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("tainted inside the fresh-lease grace window")
	}
	// Still inside grace — second sweep must not taint either.
	now = now.Add(kubeletReaperLeaseFreshGrace / 2)
	renewLease()
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("tainted before the grace window elapsed")
	}
	// Grace elapsed, lease still fresh — fake-ready confirmed.
	now = now.Add(kubeletReaperLeaseFreshGrace)
	renewLease()
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("persisted fake-ready (fresh lease + dead :10250) not tainted")
	}
}

// A probe that recovers inside the grace window re-arms the
// persistence stamp — a flap must not bank toward a later taint.
func TestKubeletReaperFreshLeaseRecoveryRearms(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := &kubeletReaper{
		cs:    cs,
		queue: "kubelet-liveness-reaper",
		now:   shared.NewClock(func() time.Time { return now }),
	}
	renewLease := func() {
		t.Helper()
		l, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Get(ctx, "w1", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		l.Spec.RenewTime = &metav1.MicroTime{Time: now}
		if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Update(ctx, l, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(kubeletReaperLeaseFreshGrace / 2)
	renewLease()
	if err := r.sweep(ctx, n, true); err != nil { // probe recovers
		t.Fatal(err)
	}
	now = now.Add(kubeletReaperLeaseFreshGrace)
	renewLease()
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("recovered flap tainted — persistence stamp was not re-armed")
	}
}

// ---------------------------------------------------------------------------
// truncateLog — the log-value cap for arbitrary proxy response bodies.
// ---------------------------------------------------------------------------

func TestTruncateLog(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"short body unchanged", "ok", 200, "ok"},
		{"empty body stays empty", "", 200, ""},
		{"surrounding whitespace trimmed", "  ok\n\t", 200, "ok"},
		{"exactly max is unchanged", strings.Repeat("a", 200), 200, strings.Repeat("a", 200)},
		{"longer body truncated to max plus ellipsis",
			strings.Repeat("a", 201), 200, strings.Repeat("a", 200) + "…"},
		{"trim happens before the cap",
			"  " + strings.Repeat("a", 201) + "  ", 200, strings.Repeat("a", 200) + "…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateLog(tc.in, tc.max); got != tc.want {
				t.Fatalf("truncateLog(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}

	// The cap counts BYTES after the trim, and the ellipsis is
	// multibyte: the result of a long multibyte body is exactly max
	// bytes of the trimmed input followed by "…". Slicing mid-rune
	// must never produce invalid UTF-8.
	long := strings.Repeat("é", 300)
	got := truncateLog(long, 200)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("multibyte body missing ellipsis suffix: %q", got[len(got)-4:])
	}
	body := strings.TrimSuffix(got, "…")
	if body != strings.Repeat("é", 100) || !utf8.ValidString(got) {
		t.Fatalf("multibyte body truncated to %d bytes, want the first 200 bytes", len(body))
	}
}

// ---------------------------------------------------------------------------
// sweep() — the L1<->L3 yield: the live signal is the
// LocalRemediationInProgress NodeCondition (the annotation has had no
// writer since the agent's RBAC narrowed to nodes/status patch).
// ---------------------------------------------------------------------------

// krRemediationCond appends a LocalRemediationInProgress condition
// with the given heartbeat age.
func krRemediationCond(n *corev1.Node, hbAge time.Duration) {
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:              corev1.NodeConditionType(nodecond.CondLocalRemediation),
		Status:            corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(time.Now().Add(-hbAge)),
	})
}

// A node mid-L1-self-heal (fresh condition heartbeat) must not get
// taint-raced while node-host-agent restarts k0sworker — the yield
// the dead annotation was meant to provide.
func TestKubeletReaperYieldsToLocalRemediationCondition(t *testing.T) {
	n := krStaleNode("w1")
	krRemediationCond(n, 30*time.Second)
	cs := fake.NewSimpleClientset(n)
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, time.Now())
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("tainted while node-host-agent self-heal in flight")
	}
}

// A FROZEN heartbeat means the episode ended (or the reporter died)
// — the condition stops yielding and the dead-kubelet verdict
// proceeds to the taint.
func TestKubeletReaperStaleRemediationHeartbeatDoesNotYield(t *testing.T) {
	n := krStaleNode("w1")
	krRemediationCond(n, 10*time.Minute)
	cs := fake.NewSimpleClientset(n)
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, time.Now())
	if err := r.sweep(ctx, n, false); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("frozen remediation heartbeat still yielded — dead kubelet not tainted")
	}
}

// ---------------------------------------------------------------------------
// run() — the mesh-dark guard: >=half the probed workers showing
// probe-fail + fresh lease means the shared proxy path is the suspect.
// ---------------------------------------------------------------------------

// With 3 of 5 workers apiserver-dark (fresh lease, probe failing past
// the persistence grace) the fleet guard suppresses their fresh-lease
// taints — while a stale-lease worker (dead kubelet) still taints:
// the guard only covers the ambiguous signature.
func TestKubeletReaperMeshDarkSuppressesFreshLeaseTaints(t *testing.T) {
	now := time.Now()
	w1 := krStaleNode("w1")
	w2 := krStaleNode("w2")
	w3 := krStaleNode("w3")
	w4 := testutil.Node("w4", corev1.ConditionTrue, nil)
	w5 := krStaleNode("w5") // no lease — dead kubelet
	cs := fake.NewSimpleClientset(w1, w2, w3, w4, w5)
	for _, w := range []string{"w1", "w2", "w3"} {
		if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
			Create(ctx, krLease(w, 5*time.Second), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	r := krRunReaper(cs, now,
		func(_ context.Context, node string) bool { return node == "w4" })
	// Age the fresh-lease persistence ledger past the grace window —
	// without it the sweep stops inside the window before the guard.
	for _, w := range []string{"w1", "w2", "w3"} {
		r.freshFail.Observe(w, now.Add(-kubeletReaperLeaseFreshGrace-time.Minute))
	}
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	if err := r.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, w := range []string{"w1", "w2", "w3"} {
		if kube.HasTaint(testutil.GetNode(t, cs, w).Spec.Taints, kubeletReaperTaint) {
			t.Fatalf("%s tainted under the mesh-dark guard — shared-path fault punished as dead kubelets", w)
		}
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w5").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("stale-lease (dead kubelet) worker not tainted — guard over-suppressed")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w4").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("healthy worker tainted")
	}
}

// The guard's complement: below the >=half threshold the same
// persisted fresh-lease failure taints exactly as before — one node's
// dead tunnel is its own incident, not a mesh fault.
func TestKubeletReaperMeshGuardOffTaintsPersistedNode(t *testing.T) {
	now := time.Now()
	w1 := krStaleNode("w1")
	w2 := testutil.Node("w2", corev1.ConditionTrue, nil)
	w3 := testutil.Node("w3", corev1.ConditionTrue, nil)
	w4 := testutil.Node("w4", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(w1, w2, w3, w4)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	r := krRunReaper(cs, now,
		func(_ context.Context, node string) bool { return node != "w1" })
	r.freshFail.Observe("w1", now.Add(-kubeletReaperLeaseFreshGrace-time.Minute))
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	if err := r.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("1-of-4 dark is below the mesh guard — persisted fake-ready must taint")
	}
}

// The guard needs siblings to compare against: on a ONE-worker
// cluster the same probe-fail+fresh-lease signature IS the
// fake-ready case the reaper exists to fence (the dedicated
// konnectivityDegraded check above already covers the tunnel
// suspect) — meshDark must not engage and suppress it forever.
func TestKubeletReaperMeshGuardNeverEngagesOnSingleWorker(t *testing.T) {
	now := time.Now()
	w1 := krStaleNode("w1")
	cs := fake.NewSimpleClientset(w1)
	if _, err := cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Create(ctx, krLease("w1", 5*time.Second), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	r := krRunReaper(cs, now,
		func(_ context.Context, node string) bool { return false })
	r.freshFail.Observe("w1", now.Add(-kubeletReaperLeaseFreshGrace-time.Minute))
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	if err := r.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("single-worker fresh-lease failure suppressed — fake-ready can never fence")
	}
}
