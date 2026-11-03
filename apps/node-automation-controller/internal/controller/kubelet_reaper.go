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
package controller

import (
	"context"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kubeletReaperQueue    = "kubelet-liveness-reaper"
	kubeletReaperTaint    = "node.ops/kubelet-unresponsive"
	kubeletReaperProbes   = 4                // all probes fail -> really down
	kubeletReaperProbeGap = 10 * time.Second // between probes
	kubeletReaperProbeTO  = 8 * time.Second  // per-probe apiserver timeout
	kubeletReaperHBStaleS = 120              // Ready heartbeat older -> dead kubelet
)

type kubeletReaper struct {
	cs kubernetes.Interface
	// Probe seam: r.probe goes through the apiserver REST client,
	// which the fake clientset cannot serve — a field so tests can
	// stub the healthz outcome per node.
	probeFn func(ctx context.Context, node string) bool
}

func SetupKubeletReaper(mgr ctrl.Manager, cs kubernetes.Interface) error {
	r := &kubeletReaper{cs: cs}
	r.probeFn = r.probe
	return addPeriodic(mgr, kubeletReaperQueue, 2*time.Minute, r.run)
}

func (r *kubeletReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	nodes, err := listNodes(ctx, r.cs)
	if err != nil {
		return err
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
		if isControlPlane(n) {
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

	for i := range nodes {
		n := &nodes[i]
		if isControlPlane(n) {
			continue
		}
		if err := r.sweep(ctx, n, ok[n.Name]); err != nil {
			// Best-effort per node — like the bash loop a failure on
			// one node must not skip the rest of the sweep.
			log.Error(err, "sweep failed — node skipped", "node", n.Name)
		}
	}
	log.Info("sweep done")
	return nil
}

// probe GETs /api/v1/nodes/<node>/proxy/healthz through the apiserver
// up to 4 times (10s apart, 8s each) — a body starting with "ok" wins.
func (r *kubeletReaper) probe(ctx context.Context, node string) bool {
	for i := 0; i < kubeletReaperProbes; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(kubeletReaperProbeGap):
			}
		}
		body, err := r.cs.CoreV1().RESTClient().Get().
			AbsPath("/api/v1/nodes", node, "proxy", "healthz").
			Timeout(kubeletReaperProbeTO).
			DoRaw(ctx)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(body)), "ok") {
			return true
		}
	}
	return false
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
		if hasTaint(listed.Spec.Taints, kubeletReaperTaint) {
			// untaintNode re-Gets the node inside before patching,
			// so a stale listed snapshot cannot remove a taint that
			// is already gone — no separate Get needed here either.
			if err := untaintNode(ctx, r.cs, listed.Name, kubeletReaperTaint); err != nil {
				return err
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
		return err
	}
	has := hasTaint(node.Spec.Taints, kubeletReaperTaint)
	name := listed.Name

	// Probe failed — heartbeat gate: fresh Ready heartbeat = broken
	// proxy path, not a dead kubelet. Missing condition/timestamp or
	// age > HB_STALE_S = kubelet really dead.
	age := -1
	if c := nodeCondition(node, corev1.NodeReady); c != nil {
		age = int(time.Since(c.LastHeartbeatTime.Time) / time.Second)
	}
	if age < 0 || age > kubeletReaperHBStaleS {
		if !has {
			if err := taintNode(ctx, r.cs, name, kubeletReaperTaint, "true",
				corev1.TaintEffectNoSchedule); err != nil {
				return err
			}
			log.Info("TAINT: kubelet :10250 down + heartbeat stale/missing -> NoSchedule",
				"node", name, "probes", kubeletReaperProbes, "heartbeatAgeS", age)
		} else {
			log.Info("KEEP-TAINT: heartbeat stale/missing", "node", name, "heartbeatAgeS", age)
		}
		return nil
	}
	if has {
		if err := untaintNode(ctx, r.cs, name, kubeletReaperTaint); err != nil {
			return err
		}
		log.Info("UNTAINT: heartbeat fresh -> taint removed", "node", name, "heartbeatAgeS", age)
	} else {
		log.Info("SKIP-TAINT: probe fail but heartbeat fresh", "node", name, "heartbeatAgeS", age)
	}
	return nil
}
