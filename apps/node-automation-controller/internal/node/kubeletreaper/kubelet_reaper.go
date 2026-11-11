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
package kubeletreaper

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
}

func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		r := &kubeletReaper{cs: d.CS, nodeReader: d.Mgr.GetClient(), queue: d.Name, now: shared.SystemClock}
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
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				results <- result{name, r.probeFn(ctx, name)}
			}
		}()
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
	// Guard: zero successes = the probe path itself is broken
	// (apiserver/konnectivity server) — apply no decision. Mass-taint
	// on a broken probe path is worse than one wedged node.
	if !anyOK {
		log.Info("ABORT: no node probe succeeded — probe path broken?", "results", ok)
		return nil
	}

	sweepErrs := 0
	for i := range nodes {
		n := &nodes[i]
		if kube.IsControlPlane(n) {
			continue
		}
		if err := r.sweep(ctx, n, ok[n.Name]); err != nil {
			// Best-effort per node — like the bash loop a failure on
			// one node must not skip the rest of the sweep. The run
			// absorbs it (returns nil), so it IncErrors here —
			// shared.Periodic only meters errors fn RETURNS.
			sweepErrs++
			metrics.IncError(r.queue)
			log.Error(err, "sweep failed — node skipped", "node", n.Name)
		}
	}
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

// probe asks kube.KubeletHealthz up to 4 times (10s apart, 8s per
// attempt) — a body starting with "ok" wins. The REST-path details
// live in the helper; the retry loop and the taint decision it feeds
// are this module's policy.
func (r *kubeletReaper) probe(ctx context.Context, node string) bool {
	// One timer reused across the inter-probe gaps — a fresh
	// time.After per attempt leaves each channel allocated until GC.
	// Armed stopped+drained so Reset never races an earlier fire; each
	// wait below consumes the pending fire, leaving the channel empty
	// for the next Reset.
	gap := time.NewTimer(kubeletReaperProbeGap)
	if !gap.Stop() {
		<-gap.C
	}
	defer gap.Stop()
	for i := 0; i < kubeletReaperProbes; i++ {
		if i > 0 {
			gap.Reset(kubeletReaperProbeGap)
			select {
			case <-ctx.Done():
				return false
			case <-gap.C:
			}
		}
		body, err := kube.KubeletHealthz(ctx, r.cs, node)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(body)), "ok") {
			return true
		}
		// sweep() only sees the bool — log WHY the attempt failed
		// (apiserver-proxy error vs. a 200 whose body isn't "ok",
		// which means the proxy reached the wrong backend).
		log := logf.FromContext(ctx)
		if err != nil {
			log.Info("WARN: kubelet healthz probe failed",
				"node", node, "attempt", i+1, "of", kubeletReaperProbes,
				"error", err)
		} else {
			log.Info("WARN: kubelet healthz probe returned non-ok body",
				"node", node, "attempt", i+1, "of", kubeletReaperProbes,
				"body", truncateLog(string(body), 200))
		}
	}
	return false
}

// truncateLog caps a string spliced into a log value — a proxy
// response can be an arbitrarily large error page.
func truncateLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// sweep applies the taint decision for one node. listed is the object
// from this run's node list — already fresh enough to see our taint.
// The per-node Get (the bash's `kubectl get node`) now only happens
// when the probe FAILED: the liveness gate below needs a fresh read,
// while a healthy probe with no listed taint has literally nothing to
// decide — one fewer apiserver read per worker per cycle.
func (r *kubeletReaper) sweep(ctx context.Context, listed *corev1.Node, ok bool) error {
	log := logf.FromContext(ctx)

	if ok {
		// The kubelet serves :10250 — the node's own convergence
		// evidence: clear its breaker history now so the next real
		// episode starts from zero instead of inheriting a stale
		// count (and so a half-open episode cannot trip on an
		// unrelated later taint).
		heal.RecordTargetHealthy(r.queue, listed.Name)
		if kube.HasTaint(listed.Spec.Taints, kubeletReaperTaint) {
			// kube.UntaintNode re-Gets the node inside before patching,
			// so a stale listed snapshot cannot remove a taint that
			// is already gone — no separate Get needed here either.
			if err := kube.UntaintNode(ctx, r.cs, listed.Name, kubeletReaperTaint); err != nil {
				return fmt.Errorf("remove taint %s on node %s: %w",
					kubeletReaperTaint, listed.Name, err)
			}
			log.Info("UNTAINT: kubelet :10250 ok -> taint removed", "node", listed.Name)
		} else {
			log.Info("OK", "node", listed.Name)
		}
		return nil
	}

	// Probe failed — re-Get like the bash per-node kubectl get: the
	// heartbeat gate decides on freshness, so the listed snapshot
	// must not stand in for it.
	node, err := r.cs.CoreV1().Nodes().Get(ctx, listed.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", listed.Name, err)
	}
	has := kube.HasTaint(node.Spec.Taints, kubeletReaperTaint)
	name := listed.Name

	// Probe failed — liveness gate: a fresh Lease renewal = broken
	// proxy path, not a dead kubelet. The signal is the
	// kube-node-lease/<node> Lease's spec.renewTime, NOT the Ready
	// condition's lastHeartbeatTime: an upstream kubelet refreshes
	// that stamp only when it actually patches its Node status
	// (nodeStatusHasChanged deliberately ignores it) at
	// nodeStatusReportFrequency — 5m default plus up to 50% jitter —
	// so a HEALTHY kubelet routinely reads minutes stale on the old
	// 120s heartbeat gate and got tainted exactly during the
	// konnectivity/proxy outage this gate exists to ride out.
	alive, err := r.kubeletAlive(ctx, name)
	if err != nil {
		// Fail closed: an unreadable lease is not evidence of death
		// — tainting on our own read failure would punish live
		// kubelets during an apiserver flap. The per-node error
		// path meters it; the next 2m cycle retries.
		return fmt.Errorf("get lease %s/%s: %w", kubeletLeaseNamespace, name, err)
	}
	if !alive {
		if !has {
			// Per-target non-convergent circuit breaker — the 4th
			// taint of the same node inside the breaker window
			// defers: a kubelet this module keeps tainting without
			// it ever coming back is not converging, and re-patching
			// every 2m cycle is exactly the churn the breaker stops.
			// Same semantics as the module's other no-action paths:
			// log, skip, return nil — never an error (IncError would
			// page on our own fail-safe). The history clears the
			// moment a probe succeeds (the ok branch above), so a
			// kubelet restart ends the episode instead of banking
			// against the next one.
			if allowed, reason := heal.TryAcquireTarget(r.queue, name, r.now.Now()); !allowed {
				log.Info("DEFER: heal target circuit open — taint skipped",
					"node", name, "reason", reason)
				return nil
			}
			if err := kube.TaintNode(ctx, r.cs, name, kubeletReaperTaint, "true",
				corev1.TaintEffectNoSchedule); err != nil {
				return fmt.Errorf("taint %s on node %s: %w",
					kubeletReaperTaint, name, err)
			}
			log.Info("TAINT: kubelet :10250 down + lease stale/missing -> NoSchedule",
				"node", name, "probes", kubeletReaperProbes)
		} else {
			log.Info("KEEP-TAINT: lease stale/missing", "node", name)
		}
		return nil
	}
	if has {
		if err := kube.UntaintNode(ctx, r.cs, name, kubeletReaperTaint); err != nil {
			return fmt.Errorf("remove taint %s on node %s: %w",
				kubeletReaperTaint, name, err)
		}
		log.Info("UNTAINT: kubelet alive (lease fresh) -> taint removed", "node", name)
	} else {
		log.Info("SKIP-TAINT: probe fail but kubelet alive (lease fresh)", "node", name)
	}
	return nil
}

// kubeletAlive reports whether the kube-node-lease/<node> Lease's
// renewal stamp proves the kubelet is alive. A live kubelet renews
// every ~10s, so anything past kubeletReaperLeaseStale reads as dead
// — well above the renewal cadence, and a dead kubelet's stamp
// crosses it within a minute. A MISSING Lease or a zero renewTime
// means the kubelet never posted a heartbeat — dead (the same
// missing-evidence-is-stale convention the Ready gate used). A
// renewal dated in the FUTURE (clock skew between the kubelet's host
// and this pod) is still proof of life — fresh; conflating skew with
// staleness would mass-taint on an NTP flap.
func (r *kubeletReaper) kubeletAlive(ctx context.Context, node string) (bool, error) {
	lease, err := r.cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Get(ctx, node, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// No heartbeat ever posted — dead.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if lease.Spec.RenewTime.IsZero() {
		return false, nil
	}
	if age := r.now.Now().Sub(lease.Spec.RenewTime.Time); age < 0 {
		// A renewal 1-2s in the future is skew, not staleness.
		return true, nil
	} else {
		return age <= kubeletReaperLeaseStale, nil
	}
}
