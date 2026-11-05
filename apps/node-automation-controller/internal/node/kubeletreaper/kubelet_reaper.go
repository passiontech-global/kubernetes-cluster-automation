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
// tainting is gated on the Ready condition's lastHeartbeatTime: a
// fresh heartbeat means a broken proxy path (skip/untaint), a stale
// or missing heartbeat means the kubelet is really dead (taint).
// Without that gate a mesh flap mass-taints and the descheduler
// evicts hundreds of pods (has happened).
package kubeletreaper

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kubeletReaperTaint    = "node.ops/kubelet-unresponsive"
	kubeletReaperProbes   = 4                // all probes fail -> really down
	kubeletReaperProbeGap = 10 * time.Second // between probes
	// per-probe apiserver timeout (8s) lives in shared.KubeletHealthz
	kubeletReaperHBStaleS = 120 // Ready heartbeat older -> dead kubelet
)

type kubeletReaper struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// Probe seam: r.probe goes through the apiserver REST client,
	// which the fake clientset cannot serve — a field so tests can
	// stub the healthz outcome per node.
	probeFn func(ctx context.Context, node string) bool
}

func Setup(d shared.Deps) error {
	r := &kubeletReaper{cs: d.CS, queue: d.Name}
	r.probeFn = r.probe
	return shared.AddPeriodic(d.Mgr, r.queue, 2*time.Minute, r.run)
}

func (r *kubeletReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	nodes, err := shared.ListNodes(ctx, r.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}

	// Probe all workers in parallel so >=2 wedged nodes still finish
	// inside one ~62s run.
	type result struct {
		node string
		ok   bool
	}
	results := make(chan result, len(nodes))
	var wg sync.WaitGroup
	for i := range nodes {
		n := &nodes[i]
		if shared.IsControlPlane(n) {
			// k0s control planes run no kubelet — the probe would
			// always fail and taint an innocent node.
			log.Info("SKIP-CP", "node", n.Name)
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			results <- result{name, r.probeFn(ctx, name)}
		}(n.Name)
	}
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
		if shared.IsControlPlane(n) {
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

// probe asks shared.KubeletHealthz up to 4 times (10s apart, 8s per
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
		body, err := shared.KubeletHealthz(ctx, r.cs, node)
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
// when the probe FAILED: the heartbeat gate below needs a fresh read,
// while a healthy probe with no listed taint has literally nothing to
// decide — one fewer apiserver read per worker per cycle.
func (r *kubeletReaper) sweep(ctx context.Context, listed *corev1.Node, ok bool) error {
	log := logf.FromContext(ctx)

	if ok {
		if shared.HasTaint(listed.Spec.Taints, kubeletReaperTaint) {
			// shared.UntaintNode re-Gets the node inside before patching,
			// so a stale listed snapshot cannot remove a taint that
			// is already gone — no separate Get needed here either.
			if err := shared.UntaintNode(ctx, r.cs, listed.Name, kubeletReaperTaint); err != nil {
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
	has := shared.HasTaint(node.Spec.Taints, kubeletReaperTaint)
	name := listed.Name

	// Probe failed — heartbeat gate: fresh Ready heartbeat = broken
	// proxy path, not a dead kubelet. A MISSING Ready condition or a
	// zero LastHeartbeatTime means the kubelet never posted status —
	// stale (taint). A heartbeat dated in the FUTURE (age <= 0, clock
	// skew between the kubelet's host and this pod) is still proof of
	// life — fresh (no taint); conflating skew with staleness would
	// mass-taint on an NTP flap.
	age := -1 // sentinel: no usable timestamp -> stale
	if c := shared.NodeCondition(node, corev1.NodeReady); c != nil &&
		!c.LastHeartbeatTime.IsZero() {
		age = int(time.Since(c.LastHeartbeatTime.Time) / time.Second)
		if age < 0 {
			// A heartbeat 1-2s in the future computes -1 and would
			// collide with the sentinel — clamp so skew reads as
			// the proof of life it is, never as staleness.
			age = 0
		}
	}
	if age == -1 || age > kubeletReaperHBStaleS {
		if !has {
			if err := shared.TaintNode(ctx, r.cs, name, kubeletReaperTaint, "true",
				corev1.TaintEffectNoSchedule); err != nil {
				return fmt.Errorf("taint %s on node %s: %w",
					kubeletReaperTaint, name, err)
			}
			log.Info("TAINT: kubelet :10250 down + heartbeat stale/missing -> NoSchedule",
				"node", name, "probes", kubeletReaperProbes, "heartbeatAgeS", age)
		} else {
			log.Info("KEEP-TAINT: heartbeat stale/missing", "node", name, "heartbeatAgeS", age)
		}
		return nil
	}
	if has {
		if err := shared.UntaintNode(ctx, r.cs, name, kubeletReaperTaint); err != nil {
			return fmt.Errorf("remove taint %s on node %s: %w",
				kubeletReaperTaint, name, err)
		}
		log.Info("UNTAINT: heartbeat fresh -> taint removed", "node", name, "heartbeatAgeS", age)
	} else {
		log.Info("SKIP-TAINT: probe fail but heartbeat fresh", "node", name, "heartbeatAgeS", age)
	}
	return nil
}
