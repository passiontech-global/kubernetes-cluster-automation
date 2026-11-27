// apiserver_node_reachability.go — the apiserver-node-reachability
// check (apiserver-node-reachability): the "apiserver-dark" node
// detector + webhook-backend evacuee.
//
// Incident 2026-11-12 (nonprod): lanit-cloud-worker-nonprod-04 stayed
// Ready with every node-host-agent condition green — its outbound
// paths were fine — while the apiserver's proxied path to it died
// (kubectl logs → dial tcp <node>:10250 i/o timeout, 3/3). Two of
// four linkerd-policy-validator endpoints sat on that node, so ~25%
// of apiserver webhook calls returned EOF and every Flux
// Kustomization dry-run over HTTPRoutes failed for ~10h. Nothing
// detected it: node-side conditions cannot see an inbound failure,
// kubelet-liveness-reaper only acts on dead kubelets, and
// partition-pod-evictor needs a partition CONDITION that never
// fired.
//
// The check probes each Ready worker through the apiserver's own
// proxy path — GET /api/v1/nodes/<n>/proxy/healthz via
// kube.KubeletHealthz, the same konnectivity hop kubectl logs takes.
// A probe failure while the node's kube-node-lease Lease renewTime
// stays fresh (<60s — the kubelet→apiserver direction is a different
// path and proves the kubelet is alive) is the apiserver-dark
// signature: kubelet-reaper owns the dead-kubelet case, this check
// owns the asymmetric one.
//
// A node must hold the signature for darkMinAge (two 5m sweeps)
// before the check acts — mesh flaps shorter than that never reach
// the taint. Persisted-dark nodes get fenced with
// passiontech.dev/apiserver-unreachable:NoSchedule so replacements
// cannot reschedule onto them, and every Ready endpoint pod backing
// a failurePolicy=Fail admission webhook on those nodes is deleted
// (reschedules onto reachable nodes) — capped, cooldowned, and
// UID-preconditioned through DeletePodHeal. The taint ALSO feeds
// webhookguard's unhealthy-node endpoint discount, so a fully-dark
// backend set still trips the circuit breaker as a fallback.
//
// Mesh-wide guard: when >= half the probed workers fail at once the
// fault is apiserver-side or mesh-wide — fencing nodes then is
// churn, so the sweep reports and takes no action (the
// partition-pod-evictor majority-abort posture).
package nethealth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// apiserverNodeReachabilityCheck is the apiserver-node-reachability check —
// probe-fail persistence rides the seen ledger; taint writes confirm
// on the direct clientset; pod deletes ride DeletePodHeal.
type apiserverNodeReachabilityCheck struct {
	*probefw.Deps

	// seen: node name → first sweep its apiserver-proxy probe failed
	// while the kubelet Lease stayed fresh — the darkMinAge window
	// before the node counts as apiserver-dark. In-RAM by contract
	// (state.FirstSeenLedger): a restart re-arms the window, the
	// safe direction.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — tuples that stop being
	// reported get DeleteLabelValues'd (zero value usable; the
	// serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// probeFn is the per-node healthz probe — r.probe in production
	// (kube.KubeletHealthz through the apiserver REST client, which
	// the fake clientset cannot serve); a field so tests stub the
	// outcome per node, the kubeletreaper seam.
	probeFn func(ctx context.Context, node string) bool
	// probeGap overrides probeRetryGap in tests (0 = default probeRetryGap).
	probeGap time.Duration
}

// NewApiserverNodeReachabilityCheck builds the apiserver-node-reachability check.
func NewApiserverNodeReachabilityCheck(d *probefw.Deps) probefw.Check {
	c := &apiserverNodeReachabilityCheck{Deps: d}
	c.probeFn = c.probe
	return c
}

const (
	CheckNameApiserverNodeReachability = "apiserver-node-reachability"

	// apiserver-node-reachability — probe/persistence/heal knobs.
	// darkMinAge is two 5m sweeps: a mesh flap shorter than that
	// never reaches the taint (the partitionMinAge=10m convention).
	darkMinAge = 10 * time.Minute
	// leaseFreshMaxAge mirrors kubeletreaper's kubeletReaperLeaseStale:
	// a live kubelet renews its node-lease every ~10s, so <60s proves
	// liveness with skew headroom.
	leaseFreshMaxAge = 60 * time.Second
	// darkHealCool is the per-workload pod-delete cooldown —
	// DeletePodHeal keys on the pod's controller so a recreated pod
	// cannot re-heal inside the window.
	darkHealCool = 30 * time.Minute
	// darkHealCap bounds webhook-backend deletions per sweep — the
	// partitionEvictCap posture: enough to drain a multi-webhook
	// node without turning one sweep into a delete storm.
	darkHealCap = 4
	// probeWorkers bounds concurrent apiserver-proxied probes — each
	// can sit for the full 8s KubeletHealthz timeout, so an unbounded
	// fan-out on a large fleet is the apiserver's biggest burst.
	probeWorkers = 8
	// probeAttempts retries 2 times (3 total attempts) before marking a
	// node dark so one-shot proxy/network blips do not false-positive.
	probeAttempts = 3
	// probeRetryGap is the short backoff between healthz retry attempts.
	probeRetryGap = 2 * time.Second
)

var (
	// apiserver-node-reachability — 1 while a Ready worker's
	// apiserver-proxy probe has failed for >= darkMinAge with a
	// fresh kubelet lease (apiserver-dark, fenced by
	// passiontech.dev/apiserver-unreachable).
	apiserverNodeDarkGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_apiserver_node_dark",
		Help: "1 while a Ready worker fails the apiserver node-proxy probe with a fresh kubelet lease for >=10m — apiserver-node-reachability.",
	}, []string{"node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(apiserverNodeDarkGauge)
}

// probe reports whether the apiserver can reach the node's kubelet
// through its proxy path — the same hop kubectl logs/exec take.
// KubeletHealthz returns the raw body; healthy kubelets answer "ok"
// (often with a trailing newline). Retries twice (3 attempts total)
// with a short backoff before returning false to absorb one-shot blips.
func (c *apiserverNodeReachabilityCheck) probe(ctx context.Context, node string) bool {
	gapDur := probeRetryGap
	if c.probeGap > 0 {
		gapDur = c.probeGap
	}
	var gap *time.Timer
	defer func() {
		if gap != nil {
			gap.Stop()
		}
	}()
	for i := range probeAttempts {
		if i > 0 {
			if gap == nil {
				gap = time.NewTimer(gapDur)
			} else {
				gap.Reset(gapDur)
			}
			select {
			case <-ctx.Done():
				return false
			case <-gap.C:
			}
		}
		body, err := kube.KubeletHealthz(ctx, c.Deps.CS, node)
		if err == nil && strings.TrimSpace(string(body)) == "ok" {
			return true
		}
	}
	return false
}

// Run executes one reachability sweep: probe every Ready worker (plus any
// non-control-plane node still carrying TaintApiserverUnreachable so
// recovery untaint runs even if Ready is currently False), fence
// persisted-dark nodes, then evacuate their Fail-policy webhook backends.
func (c *apiserverNodeReachabilityCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()

	nodes, err := c.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	var candidates []corev1.Node
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		if !kube.NodeReady(n) && !kube.HasTaint(n.Spec.Taints, kube.TaintApiserverUnreachable) {
			continue
		}
		candidates = append(candidates, *n)
	}
	// Probe and untaint BEFORE any early return. Recovery is
	// bookkeeping against a LIVE probe answer, not a speculative
	// heal — a fenced node whose proxy path answers again must be
	// unfenced even on a mesh-wide blip (the old order stranded it
	// with the taint until the majority cleared) or when the lease
	// census fails. probeAll on an empty candidate set is a cheap
	// no-op, so the no-worker early return below stays honest.
	dark := c.probeAll(ctx, candidates)
	var rep probefw.SweepReport
	c.untaintRecovered(ctx, &rep, nodes, dark)

	if len(candidates) == 0 {
		c.seen.Prune(func(string) bool { return false })
		return rep.Result(&c.emitted,
			apiserverNodeDarkGauge.DeleteLabelValues,
			"apiserver-dark nodes: ", ", ")
	}

	// Lease gate: only a FRESH kube-node-lease proves the kubelet is
	// alive while its proxy path fails — the apiserver-dark signature.
	// A stale/missing lease means the kubelet itself is dead, which
	// kubelet-liveness-reaper owns; probing that case here would
	// double-fence the same node under two taints.
	leases, err := c.AllLeases(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list leases: %w", err)}
	}
	// LeasesFetchedAt, not now: the census was fetched earlier in the
	// sweep and a late-running check would overstate renewTime age —
	// a fresh lease could read stale and the node would be skipped
	// (missed fence). Same convention as controller-lease-guard.
	leaseNow := c.LeasesFetchedAt(ctx)
	leaseFresh := map[string]bool{}
	for i := range leases {
		l := &leases[i]
		if l.Namespace != "kube-node-lease" || l.Spec.RenewTime == nil {
			continue
		}
		leaseFresh[l.Name] = leaseNow.Sub(l.Spec.RenewTime.Time) < leaseFreshMaxAge
	}

	// Partition the probe failures: apiserver-dark candidates (fresh
	// lease) vs dead-kubelet skips. Only dark candidates enter the
	// persistence ledger — a dead kubelet's probe failure is not
	// this check's evidence.
	darkCandidates := map[string]bool{}
	for name := range dark {
		if leaseFresh[name] {
			darkCandidates[name] = true
		}
	}

	// Prune + persistence run BEFORE the mesh-wide guard: a
	// mesh-wide fault must still report truthful gauges for nodes
	// that ARE persisted-dark (the emitted ledger would otherwise
	// delete their series mid-incident), and recovered nodes must
	// re-arm their first-seen window even while the guard holds.
	// The guard only suppresses the fencing ACTION, never the
	// observation.
	c.seen.Prune(func(k string) bool { return darkCandidates[k] })

	persistedDark := map[string]bool{}
	for name := range darkCandidates {
		if !probefw.Persisted(&c.seen, name, now, darkMinAge, log) {
			continue
		}
		persistedDark[name] = true
		rep.Emit(apiserverNodeDarkGauge, name, []string{name},
			name+"(apiserver proxy probe failing, lease fresh)")
	}

	// Mesh-wide guard: >= half the workers apiserver-dark at once
	// means the fault is apiserver-side or mesh-wide — fencing nodes
	// then is churn, so the sweep reports and takes no action (the
	// partition-pod-evictor majority-abort posture). Counts only
	// fresh-lease candidates: a mass dead-kubelet event is the
	// reaper's incident, not a reason to suppress a real dark node
	// sharing the sweep. A SINGLE worker is also exempted from
	// fencing: with nothing to compare against, an apiserver-proxy
	// failure cannot be distinguished from an apiserver/mesh fault,
	// and fencing the only worker would evacuate its webhook
	// backends with no reachable node to reschedule onto. Fail
	// closed — report the finding, take no action.
	//
	// The guard is purely a suppression of FENCING, so it must only
	// fire when there is something to suppress: with zero dark
	// candidates (e.g. a one-worker cluster whose lone worker is
	// healthy) an unconditional `len(candidates) <= 1` branch emits a
	// bogus "apiserver-dark on 0/1 workers" finding and pins the
	// kuberhealthy_check at FAIL=1 forever. No dark candidate means
	// no finding and no action — the sweep passes cleanly.
	if len(darkCandidates) > 0 &&
		(len(candidates) <= 1 || len(darkCandidates)*2 >= len(candidates)) {
		rep.Find(fmt.Sprintf("apiserver-dark on %d/%d workers (fresh lease) — "+
			"mesh-wide fault or single-worker cluster, no fencing",
			len(darkCandidates), len(candidates)))
		return rep.Result(&c.emitted, apiserverNodeDarkGauge.DeleteLabelValues,
			"apiserver-dark nodes: ", ", ")
	}

	// Fencing: taint persisted-dark nodes. Untaint of recovered
	// nodes already ran above, before every early return — a tainted
	// node whose probe answered is gone from the live census view
	// by the time this loop runs, so the `hasTaint && wasDark`
	// branch below is the only fence source that survives here.
	fencedDark := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) || !kube.NodeReady(n) {
			continue
		}
		hasTaint := kube.HasTaint(n.Spec.Taints, kube.TaintApiserverUnreachable)
		_, wasDark := dark[n.Name]
		if hasTaint {
			// Keep the fence state for the evacuation pass. The
			// in-RAM seen ledger is EMPTY after a controller
			// restart, so persistedDark cannot carry a node that
			// was fenced before the restart — the taint plus a
			// still-failing probe is the durable proof. Without
			// this, webhook backends on a still-dark, still-fenced
			// node would stop being evacuated for a full
			// darkMinAge after every restart.
			if wasDark {
				fencedDark[n.Name] = true
			}
			continue
		}
		if !persistedDark[n.Name] {
			continue
		}
		// Taint is a scheduling mutation — same heal contract as
		// the pod deletes below. HealAllowedOnNode runs FIRST
		// (cooldown → node-scoped mutex → fleet budget): a
		// cluster-wide hold or a drain naming THIS node must defer
		// before the per-target circuit is consulted, while a
		// drain scoped to a different node does not — or every
		// held sweep would burn breaker credit on a fence it
		// could never deliver.
		proceed, unverifiable := c.HealAllowedOnNode(ctx, log, &c.Heals,
			CheckNameApiserverNodeReachability+"/fence/"+n.Name,
			n.Name, darkHealCool, now)
		if unverifiable {
			rep.InfraErr(fmt.Errorf(
				"maintenance verdict unverifiable — fence %s deferred", n.Name))
			continue
		}
		if !proceed {
			log.Info("heal gate deferred apiserver-dark fence",
				"node", n.Name)
			continue
		}
		if allowed, reason := heal.TryAcquireTarget(
			CheckNameApiserverNodeReachability, n.Name, now); !allowed {
			// The budget grant HealAllowed spent buys a
			// mutation — the circuit denial means none happens.
			heal.RefundGrant(now)
			log.Info("DEFER: heal target circuit open — fence skipped",
				"node", n.Name, "reason", reason)
			continue
		}
		if err := kube.TaintNode(ctx, c.Deps.CS, n.Name,
			kube.TaintApiserverUnreachable, "true", corev1.TaintEffectNoSchedule); err != nil {
			rep.InfraErr(fmt.Errorf("taint %s: %w", n.Name, err))
			continue
		}
		fencedDark[n.Name] = true
		// The mutation landed — stamp the fence cooldown so a
		// restart (or the next sweep's HealAllowed) honors the
		// window this grant already spent.
		c.Heals.Stamp(CheckNameApiserverNodeReachability+"/fence/"+n.Name, now)
		c.InvalidateNodes(ctx) // taint census is stale — next sweep must see it
		rep.Find("ACTION: fenced apiserver-dark node " + n.Name)
		log.Info("ACTION: fenced apiserver-dark node",
			"node", n.Name, "taint", kube.TaintApiserverUnreachable)
	}

	// Webhook-backend evacuation — only worth the census when at
	// least one node is fenced-dark; a dark node hosting no Fail-
	// policy webhook backend needs no pod churn.
	if len(fencedDark) > 0 {
		c.evictWebhookBackends(ctx, &rep, fencedDark, now, log)
	}

	return rep.Result(&c.emitted, apiserverNodeDarkGauge.DeleteLabelValues,
		"apiserver-dark nodes: ", ", ")
}

// untaintRecovered lifts the apiserver-unreachable taint from every
// fenced worker whose proxy probe answered THIS sweep. It deliberately
// runs before the mesh-wide/single-worker early returns: recovery is
// bookkeeping against live evidence, not a speculative heal, so a
// recovered node must never stay stranded with a NoSchedule taint
// until a fleet-wide blip clears (or a Lease LIST failure resolves).
// It also skips the budget/target circuit — spending either here
// burned breaker credit on healthy nodes, where three recoveries in
// an hour locked the target circuit for 2h with the fence still on.
func (c *apiserverNodeReachabilityCheck) untaintRecovered(ctx context.Context,
	rep *probefw.SweepReport, nodes []corev1.Node, dark map[string]bool) {
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		if !kube.HasTaint(n.Spec.Taints, kube.TaintApiserverUnreachable) ||
			dark[n.Name] {
			continue // no fence, or still dark — fence stands
		}
		if err := kube.UntaintNode(ctx, c.Deps.CS, n.Name,
			kube.TaintApiserverUnreachable); err != nil {
			rep.InfraErr(fmt.Errorf("untaint %s: %w", n.Name, err))
			continue
		}
		heal.RecordTargetHealthy(CheckNameApiserverNodeReachability, n.Name)
		c.InvalidateNodes(ctx) // untaint census is stale too
		// Recovery is NOT an action finding — rep.Find would report
		// the sweep as flagged on the very sweep the node healed.
		// Log only; the gauge cleared via the emitted-ledger reconcile.
		logf.FromContext(ctx).Info("unfenced recovered node",
			"node", n.Name, "taint", kube.TaintApiserverUnreachable)
	}
}

// probeAll runs the per-node healthz probe on a fixed worker pool —
// each probe can sit for the full KubeletHealthz timeout, so the
// fan-out is bounded exactly like kubelet-liveness-reaper's.
// Returns the set of node names whose probe failed.
func (c *apiserverNodeReachabilityCheck) probeAll(ctx context.Context,
	candidates []corev1.Node) map[string]bool {
	type result struct {
		node string
		ok   bool
	}
	workers := probeWorkers
	if workers > len(candidates) {
		workers = len(candidates)
	}
	// Node names, not corev1.Node structs — a Node is ~4KB and the
	// jobs channel would copy every candidate through every worker.
	jobs := make(chan string)
	results := make(chan result, len(candidates))
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for name := range jobs {
				results <- result{node: name, ok: c.probeSafe(ctx, name)}
			}
		})
	}
	go func() {
		for i := range candidates {
			jobs <- candidates[i].Name
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	dark := map[string]bool{}
	for r := range results {
		if !r.ok {
			dark[r.node] = true
		}
	}
	return dark
}

// probeSafe runs probeFn under a panic guard — a panic inside the
// probe path is OUR bug, never dark evidence: the node reports ok
// (inconclusive, feeds nothing into the persistence ledger) and the
// panic is logged. Without the guard one bad probe kills a worker
// goroutine mid-sweep — and an unrecovered panic in ANY spawned
// goroutine takes the whole process down, bypassing Periodic's
// Run-level recover entirely.
func (c *apiserverNodeReachabilityCheck) probeSafe(ctx context.Context,
	node string) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			logf.FromContext(ctx).Error(errors.New("apiserver probe panic"),
				"node", node, "panic", r)
			ok = true
		}
	}()
	if ctx.Err() != nil {
		// The sweep budget is spent — every remaining probe would
		// fail on OUR deadline, not the node's reachability.
		// Inconclusive, never dark evidence.
		return true
	}
	ok = c.probeFn(ctx, node)
	if ctx.Err() != nil {
		// The deadline landed mid-probe — a transport error caused
		// by our own timeout must not read as a dark node.
		return true
	}
	return ok
}
