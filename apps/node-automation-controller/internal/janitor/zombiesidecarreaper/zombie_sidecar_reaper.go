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
//     sidecar through kubelet and is immune to pod netpol (sidecar-shutdown-fallback).
//     A sidecar that honors it exits cleanly and kubelet
//     transitions the pod itself; the pod is recorded in the
//     `poked` ledger and left alone for exactly one cycle.
//  2. Next cycle: a pod STILL qualifying (or a pod whose shutdown
//     call failed outright on both paths) is deleted — but ONLY once
//     the parent Job is Complete (jobAllowsReap): deleting a
//     still-Running pod of an unfinished Job counts as a pod failure
//     — an instant BackoffLimitExceeded on backoffLimit==0 Jobs —
//     and zombie_sidecar_pods_reaped_total counts the reap. A Job
//     whose sidecar never exits keeps its zombie pod and stays
//     visibly stuck rather than being failed by the reaper itself.
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
// The graceful attempts are capped per cycle (zombieShutdownCapPerCycle):
// each is two sequential network hops with 2s timeouts — a large
// zombie backlog must not block the tick for minutes — so pods past
// the cap defer their shutdown to the next 5-minute sweep.
// Pods are read through the direct clientset — the manager cache is
// list/watch-locked to kube-system cilium pods.
package zombiesidecarreaper

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	zombieSidecarReaperInterval = 5 * time.Minute

	// batchv1JobNameLabel is the server-side pod filter: the label the
	// Job controller stamps on every pod it creates (k8s ≥1.27 naming;
	// the legacy "job-name" twin carries the same value). Zombies are
	// Job-owned by definition, so the apiserver drops every non-Job
	// pod before it is ever serialized.
	batchv1JobNameLabel = "batch.kubernetes.io/job-name"

	// zombieShutdownCapPerCycle bounds the graceful sidecar shutdown
	// attempts per sweep: each attempt is up to two sequential
	// network hops with 2s timeouts (the direct pod-IP dial, then
	// the apiserver proxy), so a 50-zombie backlog would otherwise
	// block the tick for 200-400s. Pods past the cap are deferred —
	// not dropped: the next 5-minute sweep gives them their attempt.
	zombieShutdownCapPerCycle = 10
)

type zombieSidecarReaper struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// dyn is accepted for Setup-signature parity with the other
	// janitor modules — the reaper only needs typed Pod access today.
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
	// pods/<name>:<port>/proxy subresource — the sidecar-shutdown-fallback fallback
	// for when the direct dial is blocked (pod-ingress netpol) or
	// the pod has no IP. nil → (*zombieSidecarReaper).proxyShutdown.
	proxyFn func(ctx context.Context, pod *corev1.Pod, sidecar string) error
	// poked records "ns/name/uid" of pods already sent /shutdown:
	// one graceful cycle, then delete. UID is part of the key so a
	// same-named replacement pod never inherits the ledger entry.
	poked map[string]bool
}

// Setup registers the 5-minute sweep. Disabled
// clusters (ZOMBIE_SIDECAR_REAPER_ENABLED=false — resolved by
// setupModules into Deps.Disabled) skip registration entirely — same
// contract as volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		r := &zombieSidecarReaper{cs: d.CS, dyn: d.Dyn, queue: d.Name,
			now: shared.SystemClock, shutdownFn: zombieSidecarShutdown,
			poked: map[string]bool{}}
		return shared.AddPeriodic(d.Mgr, r.queue, zombieSidecarReaperInterval, r.run)
	})
}

func (r *zombieSidecarReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// reaper literally without the Setup path.
	if r.shutdownFn == nil {
		r.shutdownFn = zombieSidecarShutdown
	}
	if r.poked == nil {
		r.poked = map[string]bool{}
	}

	// Server-side filters — zombies are always Running pods of a Job,
	// and every Job-created pod carries the batch.kubernetes.io/job-name
	// label the Job controller stamps (k8s ≥1.27 label policy), so the
	// apiserver pre-filters both server-side and the census stops
	// deserializing the whole cluster's pods to throw most away. The
	// in-code phase + ownerReference checks stay — fake clientsets
	// ignore FIELD selectors (labels ARE filtered by the v0.37 typed
	// fake, so test fixtures carry the label) and zombiePod's
	// qualification is fail-closed.
	// The qualification/shutdown walk runs INSIDE the page visit:
	// each page's pod bodies die with it, and only the vetted
	// zombieTargets (plus the poked ledger) survive the tick.
	now := r.now.Now()
	seen := map[string]bool{} // qualifying keys this cycle

	// zombieTarget is a pod that reached the delete step this cycle —
	// either poked last cycle and still stuck, or freshly attempted
	// with both shutdown paths failing. The Job-completion gate
	// (jobAllowsReap) decides inside Confirm; reason feeds the
	// DELETE log line.
	type zombieTarget struct {
		pod    *corev1.Pod
		key    string
		reason string
	}
	var targets []zombieTarget
	// shutdownAttempts counts graceful sidecar shutdown calls this
	// cycle — the cap keeps the tick's wall time bounded (each call
	// is two sequential 2s-timeout hops). The poked branch makes no
	// network call and never counts.
	shutdownAttempts, shutdownSkipped := 0, 0
	err := kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		LabelSelector: batchv1JobNameLabel,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(r.cs, metav1.NamespaceAll),
		func(page []corev1.Pod) error {
			for i := range page {
				// Copy the pod out of the page buffer — targets
				// outlive this callback, and a &page[i] pointer
				// pins the whole ~500-element backing array for
				// the rest of the sweep.
				cp := page[i]
				p := &cp
				sidecar := r.zombiePod(p, now)
				if sidecar == "" {
					continue
				}
				key := zombieKey(p)
				seen[key] = true
				if r.poked[key] {
					// Already sent the admin quit call last cycle and the
					// pod STILL qualifies — the sidecar ignored the
					// graceful path, so the pod itself goes away (subject
					// to the Job-completion gate in Confirm).
					targets = append(targets, zombieTarget{pod: p, key: key,
						reason: "still stuck after sidecar shutdown"})
					continue
				}
				if shutdownAttempts >= zombieShutdownCapPerCycle {
					// Past the cap: no dial, no poked stamp — the pod keeps
					// its graceful cycle for the next sweep, unmodified.
					shutdownSkipped++
					continue
				}
				shutdownAttempts++
				// Graceful path: direct pod-IP admin call, then the apiserver
				// pods/<name>:<port>/proxy fallback when the direct dial is
				// unreachable (netpol) or the pod has no IP (sidecar-shutdown-fallback). A pod
				// with no podIP skips straight to the proxy attempt.
				err := r.shutdownPod(ctx, p, sidecar)
				if err != nil {
					// Both shutdown paths failed — graceful is impossible,
					// so the pod goes to the delete step; the
					// jobAllowsReap gate inside Confirm decides whether
					// the Job may spare it (BUG-C1 / backoffLimit).
					targets = append(targets, zombieTarget{pod: p, key: key,
						reason: fmt.Sprintf("sidecar shutdown failed: %v", err)})
					continue
				}
				r.poked[key] = true
				log.Info("SHUTDOWN: asked zombie sidecar to exit",
					"pod", p.Namespace+"/"+p.Name, "podIP", p.Status.PodIP,
					"sidecar", sidecar)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	deleted, _, _ := reap.Sweep(ctx, log, targets, reap.Options[zombieTarget]{
		// The Job-completion gate still applies on every delete
		// path: deleting a still-Running pod of an unfinished Job
		// recreates it and re-runs the Job (BUG-C1).
		Confirm: func(ctx context.Context, t zombieTarget) (bool, error) {
			if r.jobAllowsReap(ctx, t.pod) {
				return true, nil
			}
			// The Job gate vetoed the delete — release the poked
			// ledger entry too, or the pod is stuck forever: a key
			// still in `poked` skips the shutdown path every cycle
			// and re-lands here unconfirmed (the delete step was the
			// only poked release — the catch-22). Dropping it makes
			// the next cycle retry the graceful /shutdown.
			delete(r.poked, t.key)
			return false, nil
		},
		LogTarget: func(log logr.Logger, t zombieTarget) {
			log.Info("DELETE: zombie sidecar pod",
				"pod", t.pod.Namespace+"/"+t.pod.Name, "reason", t.reason)
		},
		Delete: func(ctx context.Context, t zombieTarget) error {
			// The graceful ledger entry is spent whether the delete
			// lands or not — a failed delete re-arms the shutdown
			// path next cycle.
			delete(r.poked, t.key)
			// UID precondition: the listed object is the zombie we
			// vetted — a same-named replacement must start its own
			// graceful cycle, not inherit this delete.
			if err := r.cs.CoreV1().Pods(t.pod.Namespace).
				Delete(ctx, t.pod.Name, kube.UIDDeleteOptions(t.pod.UID, "")); err != nil {
				return err
			}
			metrics.ZombieSidecarPodsReapedTotal.WithLabelValues(t.pod.Namespace).Inc()
			return nil
		},
		OnError: func(log logr.Logger, t zombieTarget, err error) {
			switch {
			case apierrors.IsNotFound(err):
				// The pod was deleted under us — raced with an
				// external cleanup; nothing failed.
				log.Info("SKIP: zombie pod already gone — raced with an external delete",
					"pod", t.pod.Namespace+"/"+t.pod.Name)
			case apierrors.IsConflict(err):
				// The UID precondition fired — a same-named pod was
				// recreated since the list; not ours to reap.
				log.Info("SKIP: zombie pod recreated since the list — UID precondition fired",
					"pod", t.pod.Namespace+"/"+t.pod.Name)
			default:
				metrics.IncError(r.queue)
				log.Error(err, "zombie pod delete failed",
					"pod", t.pod.Namespace+"/"+t.pod.Name)
			}
		},
	})

	// Prune ledger entries for pods that vanished or stopped
	// qualifying — a pod that honored /shutdown leaves phase
	// Running within seconds, so its key must not linger.
	for k := range r.poked {
		if !seen[k] {
			delete(r.poked, k)
		}
	}
	if shutdownSkipped > 0 {
		log.Info("SKIP: shutdown attempt cap reached — zombies deferred to next cycle",
			"skipped", shutdownSkipped, "cap", zombieShutdownCapPerCycle)
	}
	log.Info("sweep done", "zombies", len(seen), "deleted", deleted)
	return nil
}

// zombieKey is the ledger key — UID-scoped so a recreated pod with
// the same name starts a fresh graceful cycle.
func zombieKey(p *corev1.Pod) string {
	return p.Namespace + "/" + p.Name + "/" + string(p.UID)
}
