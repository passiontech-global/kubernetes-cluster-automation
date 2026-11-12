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
// KubeletHealthz returns the raw body; healthy kubelets answer "ok".
func (c *apiserverNodeReachabilityCheck) probe(ctx context.Context, node string) bool {
	body, err := kube.KubeletHealthz(ctx, c.Deps.CS, node)
	return err == nil && strings.HasPrefix(string(body), "ok")
}

// Run executes one reachability sweep: probe every Ready worker,
// fence persisted-dark nodes, then evacuate their Fail-policy
// webhook backends.
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
		if kube.IsControlPlane(n) || !kube.NodeReady(n) {
			continue
		}
		candidates = append(candidates, *n)
	}
	if len(candidates) == 0 {
		c.seen.Prune(func(string) bool { return false })
		var rep probefw.SweepReport
		return rep.Result(&c.emitted,
			apiserverNodeDarkGauge.DeleteLabelValues,
			"apiserver-dark nodes: ", ", ")
	}

	dark := c.probeAll(ctx, candidates)

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

	var rep probefw.SweepReport
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
	// sharing the sweep.
	if len(darkCandidates)*2 >= len(candidates) {
		rep.Find(fmt.Sprintf("apiserver-dark on %d/%d workers (fresh lease) — "+
			"mesh-wide fault, no fencing", len(darkCandidates), len(candidates)))
		return rep.Result(&c.emitted, apiserverNodeDarkGauge.DeleteLabelValues,
			"apiserver-dark nodes: ", ", ")
	}

	// Fencing: taint persisted-dark nodes; untaint fenced nodes whose
	// probe recovered this sweep. Untaint runs off the LIVE probe
	// result, not the ledger — one healthy answer is reachability
	// proof, and holding the fence on a recovered node only extends
	// the outage's scheduling damage.
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) || !kube.NodeReady(n) {
			continue
		}
		hasTaint := kube.HasTaint(n.Spec.Taints, kube.TaintApiserverUnreachable)
		_, wasDark := dark[n.Name]
		if persistedDark[n.Name] && !hasTaint {
			// Taint/untaint are scheduling mutations — same heal
			// contract as the pod deletes below: the per-target
			// circuit first (no grant spent on a denied target),
			// then the shared HealAllowed gate (cooldown → mutex →
			// fleet budget; a proceed consumes one grant, which the
			// mutation below spends — a failed TaintNode is an
			// attempted mutation, never refunded).
			if allowed, reason := heal.TryAcquireTarget(
				CheckNameApiserverNodeReachability, n.Name, now); !allowed {
				log.Info("DEFER: heal target circuit open — fence skipped",
					"node", n.Name, "reason", reason)
				continue
			}
			proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals,
				CheckNameApiserverNodeReachability+"/fence/"+n.Name,
				darkHealCool, now)
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
			if err := kube.TaintNode(ctx, c.Deps.CS, n.Name,
				kube.TaintApiserverUnreachable, "true", corev1.TaintEffectNoSchedule); err != nil {
				rep.InfraErr(fmt.Errorf("taint %s: %w", n.Name, err))
				continue
			}
			c.InvalidateNodes(ctx) // taint census is stale — next sweep must see it
			rep.Find("ACTION: fenced apiserver-dark node " + n.Name)
			log.Info("ACTION: fenced apiserver-dark node",
				"node", n.Name, "taint", kube.TaintApiserverUnreachable)
		} else if hasTaint && !wasDark {
			// Same gate for the restorative untaint — a recovered
			// node's fence release is still a node mutation.
			if allowed, reason := heal.TryAcquireTarget(
				CheckNameApiserverNodeReachability, n.Name, now); !allowed {
				log.Info("DEFER: heal target circuit open — unfence skipped",
					"node", n.Name, "reason", reason)
				continue
			}
			proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals,
				CheckNameApiserverNodeReachability+"/unfence/"+n.Name,
				darkHealCool, now)
			if unverifiable {
				rep.InfraErr(fmt.Errorf(
					"maintenance verdict unverifiable — unfence %s deferred", n.Name))
				continue
			}
			if !proceed {
				log.Info("heal gate deferred apiserver-dark unfence",
					"node", n.Name)
				continue
			}
			if err := kube.UntaintNode(ctx, c.Deps.CS, n.Name,
				kube.TaintApiserverUnreachable); err != nil {
				rep.InfraErr(fmt.Errorf("untaint %s: %w", n.Name, err))
				continue
			}
			c.InvalidateNodes(ctx) // untaint census is stale too
			// Recovery is NOT an action finding — rep.Find would
			// report the sweep as flagged on the very sweep the
			// node healed. Log only; the gauge already cleared via
			// the emitted-ledger reconcile.
			log.Info("unfenced recovered node",
				"node", n.Name, "taint", kube.TaintApiserverUnreachable)
		}
	}

	// Webhook-backend evacuation — only worth the census when at
	// least one node is fenced-dark; a dark node hosting no Fail-
	// policy webhook backend needs no pod churn.
	if len(persistedDark) > 0 {
		c.evictWebhookBackends(ctx, &rep, persistedDark, now, log)
	}

	return rep.Result(&c.emitted, apiserverNodeDarkGauge.DeleteLabelValues,
		"apiserver-dark nodes: ", ", ")
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
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				results <- result{node: name, ok: c.probeSafe(ctx, name)}
			}
		}()
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
	return c.probeFn(ctx, node)
}
