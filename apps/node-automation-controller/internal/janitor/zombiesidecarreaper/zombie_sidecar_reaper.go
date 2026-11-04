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
//  1. POST http://<podIP>:4191/shutdown — the linkerd admin
//     endpoint (3s timeout). A sidecar that honors it exits cleanly
//     and kubelet transitions the pod itself; the pod is recorded
//     in the `poked` ledger and left alone for exactly one cycle.
//  2. Next cycle: a pod STILL qualifying (or a pod whose shutdown
//     call failed outright) is deleted — the Job controller recreates
//     or completes it, and zombie_sidecar_pods_reaped_total counts
//     the reap.
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
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	zombieSidecarReaperQueue    = "zombie-sidecar-reaper"
	zombieSidecarReaperInterval = 5 * time.Minute
	// zombieSidecarTermAge: how long every app container must have
	// been Terminated before the pod counts as a zombie — covers
	// legit post-completion grace (preStop of the sidecar, log
	// shipping) so a normally-finishing pod is never touched.
	zombieSidecarTermAge = 5 * time.Minute
	// zombieSidecarShutdownPort is the linkerd admin port that
	// serves /shutdown.
	zombieSidecarShutdownPort = 4191
	// zombieSidecarShutdownTimeout bounds the admin call — a
	// wedged proxy must not stall the sweep.
	zombieSidecarShutdownTimeout = 3 * time.Second
	// zombieSidecarListPageSize bounds each Running-pod List page —
	// continue-token pagination keeps a busy cluster's pod fleet
	// from arriving as one giant response body.
	zombieSidecarListPageSize = 500
)

// zombieSidecarNames are the injected sidecars that keep a finished
// Job pod Running — linkerd is the offender this module was built
// for, istio shares the shape.
var zombieSidecarNames = map[string]bool{
	"linkerd-proxy": true,
	"istio-proxy":   true,
}

type zombieSidecarReaper struct {
	cs kubernetes.Interface
	// dyn is accepted for Setup-signature parity with the other
	// wave modules — the reaper only needs typed Pod access today.
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so the >5m
	// termination window is deterministic. nil → time.Now.
	nowFn func() time.Time
	// shutdownFn POSTs the sidecar's admin shutdown — a seam so
	// tests never leave the process. nil → zombieSidecarShutdown.
	shutdownFn func(ctx context.Context, podIP string) error
	mu         sync.Mutex
	// poked records "ns/name/uid" of pods already sent /shutdown:
	// one graceful cycle, then delete. UID is part of the key so a
	// same-named replacement pod never inherits the ledger entry.
	poked map[string]bool
}

// zombieSidecarHTTPClient is the module's single http.Client — the
// 3s timeout lives here so a wedged sidecar cannot hold the sweep.
var zombieSidecarHTTPClient = &http.Client{Timeout: zombieSidecarShutdownTimeout}

// Setup registers the 5-minute sweep. Disabled
// clusters (ZOMBIE_SIDECAR_REAPER_ENABLED=false) skip registration
// entirely — same contract as volumeattachment-cleaner.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(zombieSidecarReaperQueue).Info("disabled — module not registered")
		return nil
	}
	r := &zombieSidecarReaper{cs: cs, dyn: dyn, nowFn: time.Now,
		shutdownFn: zombieSidecarShutdown, poked: map[string]bool{}}
	return shared.AddPeriodic(mgr, zombieSidecarReaperQueue, zombieSidecarReaperInterval, r.run)
}

func (r *zombieSidecarReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	// Lazily arm the zero-value struct — unit tests construct the
	// reaper literally without the Setup path.
	if r.nowFn == nil {
		r.nowFn = time.Now
	}
	if r.shutdownFn == nil {
		r.shutdownFn = zombieSidecarShutdown
	}
	if r.poked == nil {
		r.poked = map[string]bool{}
	}

	// Server-side phase filter — zombies are always Running; the
	// in-code phase check stays for fake clients (field selectors
	// are ignored there).
	var pods []corev1.Pod
	cont := ""
	for {
		page, err := r.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
			FieldSelector: "status.phase=Running",
			Limit:         zombieSidecarListPageSize,
			Continue:      cont,
		})
		if err != nil {
			return fmt.Errorf("list pods: %w", err)
		}
		pods = append(pods, page.Items...)
		if cont = page.Continue; cont == "" {
			break
		}
	}

	now := r.nowFn()
	seen := map[string]bool{} // qualifying keys this cycle
	deleted := 0
	for i := range pods {
		p := &pods[i]
		if !r.zombiePod(p, now) {
			continue
		}
		key := zombieKey(p)
		seen[key] = true
		if r.poked[key] {
			// Already sent /shutdown last cycle and the pod STILL
			// qualifies — the sidecar ignored the graceful path, so
			// the pod itself goes away.
			delete(r.poked, key)
			if err := r.reap(ctx, p, "still stuck after /shutdown"); err != nil {
				continue
			}
			deleted++
			continue
		}
		if p.Status.PodIP == "" {
			// No admin endpoint to poke — straight to delete.
			if err := r.reap(ctx, p, "no podIP for /shutdown"); err != nil {
				continue
			}
			deleted++
			continue
		}
		if err := r.shutdownFn(ctx, p.Status.PodIP); err != nil {
			// A failed shutdown call cannot reach the sidecar —
			// graceful is impossible, so delete now rather than
			// burn a cycle.
			if derr := r.reap(ctx, p, fmt.Sprintf("/shutdown failed: %v", err)); derr != nil {
				continue
			}
			deleted++
			continue
		}
		r.poked[key] = true
		log.Info("SHUTDOWN: asked zombie sidecar to exit",
			"pod", p.Namespace+"/"+p.Name, "podIP", p.Status.PodIP)
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
	log.Info("sweep done", "zombies", len(seen), "deleted", deleted)
	return nil
}

// zombiePod reports whether the pod matches every zombie clause —
// phase Running and not already terminating, Job-owned, all app
// containers Terminated >= termAge with a final exit, every
// non-sidecar init container finished, at least one sidecar still
// Running in EITHER status list (native sidecars live in
// spec.initContainers + status.initContainerStatuses).
func (r *zombieSidecarReaper) zombiePod(p *corev1.Pod, now time.Time) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	if !p.DeletionTimestamp.IsZero() {
		return false // already terminating — a delete is in flight, don't pile on
	}
	jobOwned := false
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" {
			jobOwned = true
			break
		}
	}
	if !jobOwned {
		return false
	}

	statusByName := make(map[string]*corev1.ContainerStatus, len(p.Status.ContainerStatuses))
	for i := range p.Status.ContainerStatuses {
		statusByName[p.Status.ContainerStatuses[i].Name] = &p.Status.ContainerStatuses[i]
	}
	initStatusByName := make(map[string]*corev1.ContainerStatus, len(p.Status.InitContainerStatuses))
	for i := range p.Status.InitContainerStatuses {
		initStatusByName[p.Status.InitContainerStatuses[i].Name] = &p.Status.InitContainerStatuses[i]
	}

	appSeen := false
	for _, c := range p.Spec.Containers {
		if zombieSidecarNames[c.Name] {
			continue
		}
		appSeen = true
		st := statusByName[c.Name]
		if st == nil || st.State.Terminated == nil {
			return false // app container still running or never started
		}
		term := st.State.Terminated
		if now.Sub(term.FinishedAt.Time) < zombieSidecarTermAge {
			return false // too fresh — may still be inside normal completion
		}
		if term.ExitCode != 0 && p.Spec.RestartPolicy != corev1.RestartPolicyNever {
			return false // non-zero exit with a restartable policy — not final
		}
	}
	if !appSeen {
		return false // no app containers — nothing to prove the job finished
	}

	// Native sidecars (initContainers with restartPolicy:Always)
	// hold the pod Running exactly like an injected regular
	// container. Named mesh sidecars are the liveness candidates
	// below; every OTHER init container must have finished — a
	// plain init still running means the pod is not done starting,
	// and a non-mesh always-restart init still running is a shape
	// this reaper does not understand: fail closed either way.
	for _, c := range p.Spec.InitContainers {
		if zombieSidecarNames[c.Name] {
			continue
		}
		st := initStatusByName[c.Name]
		if st == nil || st.State.Terminated == nil {
			return false
		}
	}

	// At least one sidecar must still be Running — a pod whose
	// sidecar also exited is just a finishing Job pod, not a zombie.
	for _, statuses := range [][]corev1.ContainerStatus{
		p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
		for i := range statuses {
			st := &statuses[i]
			if zombieSidecarNames[st.Name] && st.State.Running != nil {
				return true
			}
		}
	}
	return false
}

// reap deletes the zombie pod and counts the reap — the Job
// controller reconciles completions once the live pod is gone.
func (r *zombieSidecarReaper) reap(ctx context.Context, p *corev1.Pod, why string) error {
	log := logf.FromContext(ctx)
	log.Info("DELETE: zombie sidecar pod", "pod", p.Namespace+"/"+p.Name, "reason", why)
	// UID precondition: the listed object is the zombie we vetted —
	// a same-named replacement must start its own graceful cycle,
	// not inherit this delete.
	uid := p.UID
	if err := r.cs.CoreV1().Pods(p.Namespace).
		Delete(ctx, p.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		log.Error(err, "zombie pod delete failed", "pod", p.Namespace+"/"+p.Name)
		metrics.IncError(zombieSidecarReaperQueue)
		return err
	}
	metrics.ZombieSidecarPodsReapedTotal.WithLabelValues(p.Namespace).Inc()
	return nil
}

// zombieKey is the ledger key — UID-scoped so a recreated pod with
// the same name starts a fresh graceful cycle.
func zombieKey(p *corev1.Pod) string {
	return p.Namespace + "/" + p.Name + "/" + string(p.UID)
}

// zombieSidecarShutdown POSTs the linkerd admin /shutdown endpoint —
// the graceful exit path the proxy honors even when its pod's app
// containers are gone.
func zombieSidecarShutdown(ctx context.Context, podIP string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		// JoinHostPort brackets IPv6 podIPs — plain %s:%d breaks on them.
		"http://"+net.JoinHostPort(podIP,
			strconv.Itoa(zombieSidecarShutdownPort))+"/shutdown", nil)
	if err != nil {
		return err
	}
	resp, err := zombieSidecarHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain before Close so the keep-alive connection can be
		// reused; bounded so a chatty endpoint cannot stall the
		// sweep.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sidecar /shutdown returned %s", resp.Status)
	}
	return nil
}
