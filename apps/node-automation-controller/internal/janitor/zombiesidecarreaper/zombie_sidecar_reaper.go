// zombie-sidecar-reaper — B2, the stuck Job-pod ungluer.
//
// A Job pod whose app container(s) finished but whose service-mesh
// sidecar (linkerd-proxy / istio-proxy) keeps running sits in phase
// Running forever: the Job controller sees a live pod and never marks
// the Job complete, so CronJob schedules stack up successfulJobsHistory
// entries, the Job's completions never reconcile, and (on k0s+linkerd)
// the pod is a zombie — app long dead, sidecar immortal because it
// only exits when TERM'd and nothing TERM's a container inside a pod
// whose main process is gone.
//
// Two-step graceful-then-forceful reap:
//
//  1. POST the sidecar admin quit endpoint — the direct
//     http://<podIP>:<port>/<path> call first (linkerd :4191/
//     shutdown, istio :15000/quitquitquit, 2s timeout), then — when
//     the direct dial fails or times out (e.g. a Cilium
//     default-deny ingress policy blocking pod-IP traffic from
//     node-ops) or the pod has no IP at all — the apiserver
//     pods/<name>:<port>/proxy subresource, which reaches the
//     sidecar through kubelet and is immune to pod netpol (W10-FIX3).
//     A sidecar that honors it exits cleanly and kubelet
//     transitions the pod itself; the pod is recorded in the
//     `poked` ledger and left alone for exactly one cycle.
//  2. Next cycle: a pod STILL qualifying (or a pod whose shutdown
//     call failed outright on both paths) is deleted — the Job
//     controller recreates or completes it, and
//     zombie_sidecar_pods_reaped_total counts the reap. A Job with
//     spec.backoffLimit==0 spawns no replacement pod, so once a
//     shutdown attempt already ran (this or a prior cycle —
//     tracked in the `tried` ledger) an all-exit-0 zombie may be
//     reaped even while job.Status.Succeeded is still 0.
//
// Qualification (fail closed — every clause must hold): phase
// Running and not already terminating, an ownerReference of kind
// Job, at least one app container
// (name != linkerd-proxy && != istio-proxy) in spec, EVERY app
// container Terminated >= zombieSidecarTermAge ago with a final exit
// (exitCode==0, or spec.restartPolicy==Never so a non-zero exit is
// still terminal), every non-sidecar init container finished, and
// at least one sidecar still Running — whether it sits in
// spec.containers or in spec.initContainers as a native sidecar
// (restartPolicy: Always, the shape istio's native-sidecar mode and
// newer linkerd injection use).
// Pods are read through the direct clientset — the manager cache is
// list/watch-locked to kube-system cilium pods.
package zombiesidecarreaper

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	zombieSidecarReaperInterval = 5 * time.Minute
	// zombieSidecarListPageSize bounds each Running-pod List page —
	// continue-token pagination keeps a busy cluster's pod fleet
	// from arriving as one giant response body.
	zombieSidecarListPageSize = 500
)

type zombieSidecarReaper struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// dyn is accepted for Setup-signature parity with the other
	// wave modules — the reaper only needs typed Pod access today.
	dyn dynamic.Interface
	// now is the clock seam — tests pin it so the >5m
	// termination window is deterministic. nil → time.Now.
	now shared.Clock
	// shutdownFn POSTs the sidecar's admin shutdown over the direct
	// pod-IP path — a seam so tests never leave the process. The
	// sidecar name selects the admin endpoint (linkerd :4191/
	// shutdown, istio :15000/quitquitquit). nil →
	// zombieSidecarShutdown.
	shutdownFn func(ctx context.Context, podIP, sidecar string) error
	// proxyFn POSTs the same admin endpoint through the apiserver
	// pods/<name>:<port>/proxy subresource — the W10-FIX3 fallback
	// for when the direct dial is blocked (pod-ingress netpol) or
	// the pod has no IP. nil → (*zombieSidecarReaper).proxyShutdown.
	proxyFn func(ctx context.Context, pod *corev1.Pod, sidecar string) error
	mu      sync.Mutex
	// poked records "ns/name/uid" of pods already sent /shutdown:
	// one graceful cycle, then delete. UID is part of the key so a
	// same-named replacement pod never inherits the ledger entry.
	poked map[string]bool
	// tried records "ns/name/uid" of pods for which ANY shutdown
	// attempt (direct or proxy, success or failure) already ran —
	// W10-FIX3 lets jobAllowsReap force a backoffLimit==0 reap only
	// after one full attempt cycle, never on first sight.
	tried map[string]bool
}

// Setup registers the 5-minute sweep. Disabled
// clusters (ZOMBIE_SIDECAR_REAPER_ENABLED=false — resolved by
// setupModules into Deps.Disabled) skip registration entirely — same
// contract as volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	if d.Disabled {
		return nil
	}
	r := &zombieSidecarReaper{cs: d.CS, dyn: d.Dyn, queue: d.Name,
		now: shared.SystemClock, shutdownFn: zombieSidecarShutdown,
		poked: map[string]bool{}, tried: map[string]bool{}}
	return shared.AddPeriodic(d.Mgr, r.queue, zombieSidecarReaperInterval, r.run)
}

func (r *zombieSidecarReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	// Lazily arm the zero-value struct — unit tests construct the
	// reaper literally without the Setup path.
	if r.shutdownFn == nil {
		r.shutdownFn = zombieSidecarShutdown
	}
	if r.poked == nil {
		r.poked = map[string]bool{}
	}
	if r.tried == nil {
		r.tried = map[string]bool{}
	}

	// Server-side phase filter — zombies are always Running; the
	// in-code phase check stays for fake clients (field selectors
	// are ignored there).
	pods, err := shared.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		Limit:         zombieSidecarListPageSize,
	}, shared.Pods(r.cs, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	now := r.now.Now()
	seen := map[string]bool{} // qualifying keys this cycle
	deleted := 0
	for i := range pods {
		p := &pods[i]
		sidecar := r.zombiePod(p, now)
		if sidecar == "" {
			continue
		}
		key := zombieKey(p)
		seen[key] = true
		if r.poked[key] {
			// Already sent the admin quit call last cycle and the
			// pod STILL qualifies — the sidecar ignored the
			// graceful path, so the pod itself goes away. The
			// Job-completion gate still applies: deleting a
			// still-Running pod of an unfinished Job recreates it
			// and re-runs the Job. poked implies a shutdown attempt
			// already ran — the backoffLimit==0 exemption applies.
			if !r.jobAllowsReap(ctx, p, true) {
				continue
			}
			delete(r.poked, key)
			if err := r.reap(ctx, p, "still stuck after sidecar shutdown"); err != nil {
				continue
			}
			deleted++
			continue
		}
		// Graceful path: direct pod-IP admin call, then the apiserver
		// pods/<name>:<port>/proxy fallback when the direct dial is
		// unreachable (netpol) or the pod has no IP (W10-FIX3). A pod
		// with no podIP skips straight to the proxy attempt.
		attemptedBefore := r.tried[key]
		err := r.shutdownPod(ctx, p, sidecar)
		r.tried[key] = true
		if err != nil {
			// Both shutdown paths failed — graceful is impossible,
			// so delete now rather than burn a cycle. BUG-C1: with
			// every app container at exit 0 the Job must already be
			// Complete first — deleting a still-Running pod whose
			// Job has not counted it makes the job-controller
			// recreate the pod and re-run the Job.
			if !r.jobAllowsReap(ctx, p, attemptedBefore) {
				continue
			}
			if derr := r.reap(ctx, p, fmt.Sprintf("sidecar shutdown failed: %v", err)); derr != nil {
				continue
			}
			deleted++
			continue
		}
		r.poked[key] = true
		log.Info("SHUTDOWN: asked zombie sidecar to exit",
			"pod", p.Namespace+"/"+p.Name, "podIP", p.Status.PodIP,
			"sidecar", sidecar)
	}
	pods = nil

	// Prune ledger entries for pods that vanished or stopped
	// qualifying — a pod that honored /shutdown leaves phase
	// Running within seconds, so its key must not linger.
	for k := range r.poked {
		if !seen[k] {
			delete(r.poked, k)
		}
	}
	for k := range r.tried {
		if !seen[k] {
			delete(r.tried, k)
		}
	}
	log.Info("sweep done", "zombies", len(seen), "deleted", deleted)
	return nil
}

// zombieKey is the ledger key — UID-scoped so a recreated pod with
// the same name starts a fresh graceful cycle.
func zombieKey(p *corev1.Pod) string {
	return p.Namespace + "/" + p.Name + "/" + string(p.UID)
}
