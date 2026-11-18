// kubelet-liveness-reaper — port of hooks/50-kubelet-liveness-reaper.sh.
//
// Taints NoSchedule nodes whose kubelet is "fake Ready" — the lease
// still renews (node Ready=True) but :10250 does not serve: new pods
// never start, exec/logs fail, status goes stale (incident 2026-09-18
// datahub: ~150 pods Pending/PodInitializing because the scheduler
// kept bin-packing a dead node). This layer blocks scheduling; the
// watchdog/systemd/NHC layers do the actual remediation.
//
// Probe = GET /api/v1/nodes/<n>/proxy/healthz via the apiserver
// (through the konnectivity tunnel): healthy kubelets answer "ok",
// dead ones return "error trying to reach service: ...". Four
// consecutive failures (~45s down) are required before tainting, so a
// normal kubelet restart (~10-40s) is not punished.
//
// The probe also fails when the node's konnectivity-agent is dead or
// the inter-DC mesh flaps while kubelet still renews its lease — so
// tainting is gated on the kube-node-lease/<node> Lease's
// spec.renewTime: a live kubelet renews it every ~10s over its own
// kubelet->apiserver connection, which does not traverse the broken
// proxy path, so a fresh renewal means a broken proxy path
// (skip/untaint) and a stale or missing one means the kubelet is
// really dead (taint). The Ready condition's lastHeartbeatTime is
// NOT usable as this gate — an upstream kubelet refreshes it only
// when it actually patches its Node status (nodeStatusHasChanged
// deliberately ignores the stamp; cadence nodeStatusReportFrequency,
// 5m default plus up to 50% jitter), so a healthy kubelet routinely
// reads minutes stale. Without the gate a mesh flap mass-taints and
// the descheduler evicts hundreds of pods (has happened).
//
// This file owns the module wiring + the probe-pool sweep; the
// healthz probe + tunnel-degraded guard live in probe.go and the
// per-node taint decision + lease liveness gate in sweep.go.
package kubeletreaper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	kubeletReaperTaint    = kube.TaintKubeletUnresponsive
	kubeletReaperProbes   = 4                // all probes fail -> really down
	kubeletReaperProbeGap = 10 * time.Second // between probes
	// kubeletProbeWorkers bounds the parallel probe pool — each
	// probe is up to 4 sequential apiserver-proxied kubelet calls,
	// so the cap keeps a large cluster's sweep inside the apiserver
	// budget while still finishing wedged nodes within one period.
	kubeletProbeWorkers = 16
	// per-probe apiserver timeout (8s) lives in kube.KubeletHealthz
	// kubeletLeaseNamespace holds the per-node heartbeat Leases — one
	// Lease named exactly like the Node (upstream node-heartbeat
	// contract; every kubelet heartbeat is an update of that Lease's
	// spec.renewTime).
	kubeletLeaseNamespace = "kube-node-lease"
	// kubeletReaperLeaseStale is the renewal age past which the
	// kubelet reads as dead: a live kubelet renews every ~10s
	// (renewInterval = leaseDuration/4, 40s default), so its stamp is
	// <15s old even with clock skew — 60s gives several missed
	// renewals of headroom without letting a dead kubelet wait more
	// than the next 2m cycle for its taint.
	kubeletReaperLeaseStale = 60 * time.Second
	// kubeletReaperLeaseFreshGrace is how long a probe-fail must
	// PERSIST while the kubelet Lease stays fresh before the node
	// is tainted anyway. The fresh lease proves kubelet↔apiserver
	// liveness, NOT that :10250 serves — the fake-ready incident
	// this module exists for is exactly "lease renews, healthz
	// hangs". What a fresh lease + failed probe CAN also mean is a
	// broken proxy path (konnectivity-agent dead on the node, mesh
	// flap) where kubelet itself is healthy — so the fresh-lease
	// case demands cross-sweep persistence (~2 cycles) instead of
	// the old unconditional skip that suppressed the only scenario
	// the reaper was built to catch.
	kubeletReaperLeaseFreshGrace = 4 * time.Minute
	// kubeletReaperLocalRemediationLease is the L1<->L3 protocol's
	// trust window for the LocalRemediationInProgress heartbeat —
	// the same 3m heal.localRemediationLease and
	// nodecoord.LocalRemediationLease carry (duplicated per module
	// boundary). The agent re-stamps only when it acts, so a frozen
	// heartbeat means the episode ended or the reporter died.
	kubeletReaperLocalRemediationLease = 3 * time.Minute
)

type kubeletReaper struct {
	cs         kubernetes.Interface
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the wall-clock seam so tests can pin the heartbeat-age
	// verdict. nil reads as system time — the standard unarmed-seam
	// convention.
	now shared.Clock
	// Probe seam: r.probe goes through the apiserver REST client,
	// which the fake clientset cannot serve — a field so tests can
	// stub the healthz outcome per node.
	probeFn func(ctx context.Context, node string) bool
	// probeGap overrides kubeletReaperProbeGap in unit tests so retry
	// cadence tests don't sleep 30+ real seconds. 0 = production default.
	probeGap time.Duration
	// freshFail tracks how long each node's probe-fail has persisted
	// while its kubelet Lease stayed fresh — the cross-sweep
	// persistence window that separates a wedged :10250 (fake-ready,
	// taint it) from a transient proxy-path flap (skip it). run() is
	// the only writer and sweeps sequentially, so no lock.
	freshFail state.FirstSeenLedger
	// meshDark is run()'s fleet guard for the sweep: true while
	// >=half the probed workers show the apiserver-dark signature
	// (probe fail + fresh kubelet Lease) — the shared proxy path,
	// not the kubelets, is the suspect, so sweep() suppresses
	// fresh-lease taints for the cycle (the
	// apiserver-node-reachability >=half-dark posture). run() is
	// the only writer and sweeps sequentially — no lock (the
	// freshFail contract).
	meshDark bool
	// probeOutage latches when run() aborts on a broad probe-path
	// failure (!anyOK guards): the next run that gets past them
	// resets freshFail — persistence windows measured across the
	// outage are stale, and a node failing NOW must earn a fresh
	// grace window instead of inheriting the outage's age.
	probeOutage bool
}

func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		r := &kubeletReaper{cs: d.CS, nodeReader: d.CachedClient(), queue: d.Name, now: shared.SystemClock}
		r.probeFn = r.probe
		return shared.AddPeriodic(d.Mgr, r.queue, 2*time.Minute, r.run)
	})
}

func (r *kubeletReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	nodes, err := kube.ListNodesCached(ctx, r.nodeReader, r.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}

	// Probe all workers on a FIXED pool so >=2 wedged nodes still
	// finish inside one ~62s run without spawning a goroutine per
	// node — each probe is up to 4 sequential apiserver-proxied
	// kubelet calls, so unbounded fan-out was the cluster's biggest
	// concurrent-request burst.
	type result struct {
		node string
		ok   bool
	}
	workers := kubeletProbeWorkers
	if workers > len(nodes) {
		workers = len(nodes)
	}
	results := make(chan result, len(nodes))
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for name := range jobs {
				results <- result{name, r.probeSafe(ctx, name)}
			}
		})
	}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			// k0s control planes run no kubelet — the probe would
			// always fail and taint an innocent node.
			log.Info("SKIP-CP", "node", n.Name)
			continue
		}
		jobs <- n.Name
	}
	close(jobs)
	wg.Wait()
	close(results)

	ok := map[string]bool{}
	anyOK := false
	for res := range results {
		ok[res.node] = res.ok
		anyOK = anyOK || res.ok
	}
	// Guard: zero successes across MULTIPLE probed nodes = the probe
	// path itself is broken (apiserver/konnectivity server) — apply
	// no decision. Mass-taint on a broken probe path is worse than
	// one wedged node.
	if !anyOK && len(ok) > 1 {
		log.Info("ABORT: no node probe succeeded — probe path broken?", "results", ok)
		r.probeOutage = true
		return nil
	}
	// One-worker tunnel protection: with a SINGLE probed node a
	// failed probe cannot be cross-checked against sibling
	// successes — and it carries the exact signature a dead
	// konnectivity-agent produces cluster-wide (every node's
	// healthz proxy path dies together). Before letting the sweep
	// taint the cluster's only worker, verify the proxy path
	// itself: degraded konnectivity-agent pods mean the fault is
	// in the tunnel, not the kubelet — fail OPEN (skip the whole
	// sweep; there is only the one node anyway). An unverifiable
	// agent list fails open too: tainting the sole worker on our
	// own read failure is the mass-taint-on-broken-path failure
	// this guard exists to prevent.
	if !anyOK && len(ok) == 1 {
		degraded, err := r.konnectivityDegraded(ctx)
		if err != nil {
			log.Info("one-worker probe failed — konnectivity check errored, failing open",
				"error", err, "results", ok)
			r.probeOutage = true
			return nil
		}
		if degraded {
			log.Info("ABORT: single worker probe failed and konnectivity-agent degraded — tunnel suspect, not tainting",
				"results", ok)
			r.probeOutage = true
			return nil
		}
	}

	// Mesh-wide guard (the apiserver-node-reachability >=half-dark
	// posture): count the apiserver-dark signature — probe failed
	// AND the kubelet Lease still fresh — across the probed workers.
	// At >=half the suspect is the shared apiserver->kubelet path
	// (konnectivity/mesh), not N simultaneous fake-ready kubelets,
	// so sweep() suppresses fresh-lease taints for the cycle. One
	// Lease read per failed node — cheap next to the probe pool's
	// apiserver fan-out — and an unreadable lease simply doesn't
	// count (fail closed, the same posture sweep()'s own
	// lease-read error path takes).
	darkFresh := 0
	leaseAlive := make(map[string]leaseVerdict, len(ok))
	for name, o := range ok {
		if o {
			continue
		}
		// One Lease read per failed node — the sweep's per-node
		// decision below reuses this verdict instead of re-Get'ing
		// the same Lease a second time.
		alive, err := r.kubeletAlive(ctx, name)
		leaseAlive[name] = leaseVerdict{alive: alive, err: err}
		if err == nil && alive {
			darkFresh++
		}
	}
	// len(ok) > 1: a single probed worker has no siblings to
	// cross-check — its probe-fail+fresh-lease signature IS the
	// fake-ready case this module exists to fence (the dedicated
	// konnectivityDegraded guard above already covers the tunnel
	// suspect), so the fleet guard must not engage there.
	//
	// On a TWO-worker cluster one dark worker is NOT a mesh outage:
	// >=half is trivially true at 1-of-2, and suppressing the
	// healthy sibling's evidence would let a genuinely dead worker
	// go unfenced forever. Both workers must be dark. On >=3
	// workers the shared-path >=half posture still applies.
	wasDark := r.meshDark
	switch {
	case len(ok) == 2:
		r.meshDark = darkFresh == 2
	case len(ok) >= 3:
		r.meshDark = darkFresh > 0 && darkFresh*2 >= len(ok)
	default:
		r.meshDark = false
	}
	if r.meshDark {
		log.Info("mesh-dark guard: >=half of probed workers fail with fresh leases — fresh-lease taints suppressed",
			"darkFresh", darkFresh, "probed", len(ok))
	}
	// Broad-outage exit reset: freshFail windows measured while the
	// probe path (or the mesh-dark suppression) was down are stale —
	// restart them so each node earns a fresh persistence window
	// against the recovered path instead of inheriting outage age.
	if r.probeOutage || (wasDark && !r.meshDark) {
		r.freshFail = state.FirstSeenLedger{}
	}
	r.probeOutage = false

	// Fleet-capacity guard: on a MULTI-worker cluster this module
	// must never unnode the fleet. Count both the workers and those
	// that can actually host a replacement — Ready, schedulable, and
	// not already fenced by any remediation actor (our own
	// kubelet-unresponsive taint included). On a 2-worker cluster
	// that has already lost one worker to fencing, the last remaining
	// one is the ONLY capacity left: a failed probe there gets a
	// deferral, never a taint, even with a stale lease and an expired
	// grace window. This guard covers the "the other worker is
	// already fenced" shape the probe cross-checks cannot see.
	//
	// A GENUINE one-worker cluster is excluded: with no sibling ever
	// present, the probe-fail+fresh-lease signature is exactly the
	// fake-ready case this reaper exists to fence (see the one-worker
	// tunnel guard above and the meshDark len(ok)>1 carve-out).
	workerNodes := 0
	schedulable := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		workerNodes++
		if n.Spec.Unschedulable ||
			kube.HasRemediationOrFenceTaint(n) || !kube.NodeReady(n) {
			continue
		}
		schedulable[n.Name] = true
	}
	sweepErrs := 0
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		// Only a NEW taint on a schedulable worker costs capacity;
		// untaints (healthy probe) and keep-taints stay allowed.
		atRisk := !ok[n.Name] && schedulable[n.Name] &&
			!kube.HasTaint(n.Spec.Taints, kubeletReaperTaint)
		if atRisk && workerNodes > 1 && len(schedulable) <= 1 {
			log.Info("DEFER: last schedulable worker — refusing to fence the cluster",
				"node", n.Name)
			continue
		}
		if err := r.sweep(ctx, n, ok[n.Name], leaseAlive); err != nil {
			// Best-effort per node — like the bash loop a failure on
			// one node must not skip the rest of the sweep. The run
			// absorbs it (returns nil), so it IncErrors here —
			// shared.Periodic only meters errors fn RETURNS.
			sweepErrs++
			metrics.IncError(r.queue)
			log.Error(err, "sweep failed — node skipped", "node", n.Name)
		}
		if atRisk {
			// Conservatively spend the capacity slot even if sweep()
			// deferred (lease grace, circuit breaker, L1 yield):
			// under-counting capacity here can only make THIS sweep
			// more conservative — no sibling may be fenced on the
			// same pass.
			delete(schedulable, n.Name)
		}
	}
	// Prune freshFail against the live node list: a deleted (or
	// promoted-to-control-plane) node's persistence stamp would
	// otherwise linger in the ledger forever — and silently
	// re-fire its grace window if the name is ever reused.
	live := make(map[string]bool, len(nodes))
	for i := range nodes {
		if !kube.IsControlPlane(&nodes[i]) {
			live[nodes[i].Name] = true
		}
	}
	r.freshFail.Prune(func(key string) bool { return live[key] })
	healthy := 0
	for _, o := range ok {
		if o {
			healthy++
		}
	}
	log.Info("sweep done", "probed", len(ok), "healthy", healthy,
		"sweepErrors", sweepErrs)
	return nil
}

// probeSafe runs probeFn under a panic guard — a panic in the probe
// path is OUR bug, never evidence the kubelet is dead: the node reads
// ok (inconclusive, feeds no persistence window, earns no taint) and
// the panic is logged. Without this guard one bad probe kills a
// worker goroutine mid-sweep — and an unrecovered panic in ANY
// spawned goroutine takes the whole process down, bypassing
// Periodic's Run-level recover entirely (same posture as
// apiserver-node-reachability's probeSafe). A spent sweep budget is
// inconclusive too: every remaining probe would fail on OUR
// deadline, not the node's.
func (r *kubeletReaper) probeSafe(ctx context.Context, node string) (ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			logf.FromContext(ctx).Error(errors.New("kubelet probe panic"),
				"node", node, "panic", rec)
			ok = true // inconclusive — never taint on our own bug
		}
	}()
	if ctx.Err() != nil {
		return true
	}
	return r.probeFn(ctx, node)
}
