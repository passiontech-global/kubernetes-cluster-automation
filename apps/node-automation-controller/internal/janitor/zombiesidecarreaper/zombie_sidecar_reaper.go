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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	// zombieSidecarShutdownTimeout bounds the admin call — a
	// wedged proxy must not stall the sweep. W10-FIX3: 2s per the
	// plan; shared by the direct HTTP POST and the apiserver pod
	// proxy fallback.
	zombieSidecarShutdownTimeout = 2 * time.Second
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

// zombieSidecarShutdownTargets maps each supported sidecar to its
// admin quit endpoint — linkerd's admin serves POST /shutdown on
// :4191, istio's pilot-agent serves POST /quitquitquit on :15000.
var zombieSidecarShutdownTargets = map[string]struct {
	port int
	path string
}{
	"linkerd-proxy": {port: 4191, path: "/shutdown"},
	"istio-proxy":   {port: 15000, path: "/quitquitquit"},
}

type zombieSidecarReaper struct {
	cs kubernetes.Interface
	// dyn is accepted for Setup-signature parity with the other
	// wave modules — the reaper only needs typed Pod access today.
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so the >5m
	// termination window is deterministic. nil → time.Now.
	nowFn func() time.Time
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

// zombieSidecarHTTPClient is the module's single http.Client — the
// 2s timeout lives here so a wedged sidecar cannot hold the sweep.
var zombieSidecarHTTPClient = &http.Client{Timeout: zombieSidecarShutdownTimeout}

// Setup registers the 5-minute sweep. Disabled
// clusters (ZOMBIE_SIDECAR_REAPER_ENABLED=false) skip registration
// entirely — same contract as volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	if !shared.Gate("ZOMBIE_SIDECAR_REAPER_ENABLED", true) {
		logf.Log.WithName(zombieSidecarReaperQueue).Info("disabled — module not registered")
		return nil
	}
	r := &zombieSidecarReaper{cs: d.CS, dyn: d.Dyn, nowFn: time.Now,
		shutdownFn: zombieSidecarShutdown, poked: map[string]bool{},
		tried: map[string]bool{}}
	return shared.AddPeriodic(d.Mgr, zombieSidecarReaperQueue, zombieSidecarReaperInterval, r.run)
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

	now := r.nowFn()
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

// zombiePod returns the name of the still-Running mesh sidecar when
// the pod matches every zombie clause — phase Running and not already
// terminating, Job-owned, all app containers Terminated >= termAge
// with a final exit, every non-sidecar init container finished, at
// least one sidecar still Running in EITHER status list (native
// sidecars live in spec.initContainers + status.initContainerStatuses).
// "" means not a zombie — the empty string doubles as the sentinel so
// the caller picks the right admin endpoint per sidecar.
func (r *zombieSidecarReaper) zombiePod(p *corev1.Pod, now time.Time) string {
	if p.Status.Phase != corev1.PodRunning {
		return ""
	}
	if !p.DeletionTimestamp.IsZero() {
		return "" // already terminating — a delete is in flight, don't pile on
	}
	jobOwned := false
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" {
			jobOwned = true
			break
		}
	}
	if !jobOwned {
		return ""
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
			return "" // app container still running or never started
		}
		term := st.State.Terminated
		if now.Sub(term.FinishedAt.Time) < zombieSidecarTermAge {
			return "" // too fresh — may still be inside normal completion
		}
		if term.ExitCode != 0 && p.Spec.RestartPolicy != corev1.RestartPolicyNever {
			return "" // non-zero exit with a restartable policy — not final
		}
	}
	if !appSeen {
		return "" // no app containers — nothing to prove the job finished
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
			return ""
		}
	}

	// At least one sidecar must still be Running — a pod whose
	// sidecar also exited is just a finishing Job pod, not a zombie.
	for _, statuses := range [][]corev1.ContainerStatus{
		p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
		for i := range statuses {
			st := &statuses[i]
			if zombieSidecarNames[st.Name] && st.State.Running != nil {
				return st.Name
			}
		}
	}
	return ""
}

// allZeroExit reports whether every app (non-sidecar) container in
// spec.containers terminated with exit code 0 — the "Job succeeded but
// the sidecar never noticed" shape, where a forced pod delete must
// first prove the parent Job already counted the completion.
func allZeroExit(p *corev1.Pod) bool {
	statusByName := make(map[string]*corev1.ContainerStatus, len(p.Status.ContainerStatuses))
	for i := range p.Status.ContainerStatuses {
		statusByName[p.Status.ContainerStatuses[i].Name] = &p.Status.ContainerStatuses[i]
	}
	for _, c := range p.Spec.Containers {
		if zombieSidecarNames[c.Name] {
			continue
		}
		st := statusByName[c.Name]
		if st == nil || st.State.Terminated == nil || st.State.Terminated.ExitCode != 0 {
			return false
		}
	}
	return true
}

// jobAllowsReap gates the forced-delete paths (shutdown unreachable,
// still stuck after the graceful call): when every app container
// exited 0, a still-Running pod may only be deleted once the parent
// Job already recorded the success — job.Status.Succeeded >= 1.
// Deleting earlier makes the job-controller recreate the pod and
// re-run the Job (BUG-C1). A pod with any non-zero app exit needs no
// such gate: a re-run after a failed exit is the Job's own retry
// semantics, not a double-success. A missing Job object means no
// controller can recreate the pod — safe to reap; any other Get
// failure is "cannot verify" and fails closed.
//
// W10-FIX3 exception: a Job with spec.backoffLimit==0 spawns NO
// replacement pod once its single pod terminates, so the BUG-C1
// re-run hazard cannot happen — once a shutdown attempt already ran
// (shutdownAttempted: this cycle's failed call counted only from
// the NEXT cycle on via the `tried` ledger, or unconditionally on
// the poked path), the zombie may be reaped even while
// job.Status.Succeeded is still 0.
func (r *zombieSidecarReaper) jobAllowsReap(ctx context.Context, p *corev1.Pod, shutdownAttempted bool) bool {
	if !allZeroExit(p) {
		return true
	}
	jobName := ""
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" {
			jobName = ref.Name
			break
		}
	}
	if jobName == "" {
		return false // qualification guarantees a Job owner — unreachable
	}
	log := logf.FromContext(ctx)
	job, err := r.cs.BatchV1().Jobs(p.Namespace).Get(ctx, jobName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return true // Job gone — nobody recreates the pod
	case err != nil:
		metrics.IncError(zombieSidecarReaperQueue)
		log.Info("WARN: job lookup failed — keeping still-Running exit-0 pod (fail closed)",
			"pod", p.Namespace+"/"+p.Name, "job", jobName, "error", err)
		return false
	case job.Status.Succeeded >= 1:
		return true
	case shutdownAttempted && job.Spec.BackoffLimit != nil &&
		*job.Spec.BackoffLimit == 0:
		// backoffLimit==0: no replacement pod can spawn, so the
		// BUG-C1 re-run hazard is impossible — reap the zombie
		// even though the Job never counted the exit-0 completion.
		log.Info("REAP: backoffLimit=0 Job cannot respawn — allowing zombie reap",
			"pod", p.Namespace+"/"+p.Name, "job", jobName)
		return true
	default:
		log.Info("KEEP: Job not Complete — deleting the Running pod would re-run it",
			"pod", p.Namespace+"/"+p.Name, "job", jobName,
			"succeeded", job.Status.Succeeded)
		return false
	}
}

// shutdownPod runs the graceful sidecar shutdown: the direct
// pod-IP admin call first, then — when the dial fails or times out
// (e.g. Cilium default-deny ingress from node-ops, W10-FIX3) or the
// pod carries no IP — the apiserver pods/<name>:<port>/proxy
// subresource, which reaches the sidecar through kubelet regardless
// of pod-ingress NetworkPolicy.
func (r *zombieSidecarReaper) shutdownPod(ctx context.Context, p *corev1.Pod, sidecar string) error {
	var directErr error
	if p.Status.PodIP != "" {
		if err := r.shutdownFn(ctx, p.Status.PodIP, sidecar); err == nil {
			return nil
		} else {
			directErr = err
		}
	}
	if r.proxyFn == nil {
		r.proxyFn = r.proxyShutdown
	}
	if err := r.proxyFn(ctx, p, sidecar); err != nil {
		if directErr != nil {
			return fmt.Errorf("direct shutdown: %v; proxy shutdown: %w",
				directErr, err)
		}
		return fmt.Errorf("proxy shutdown: %w", err)
	}
	return nil
}

// proxyShutdown POSTs the sidecar admin endpoint through the
// apiserver pods proxy subresource —
// POST /api/v1/namespaces/<ns>/pods/<name>:<port>/proxy/<path> —
// the same request shape kubectl's pod proxy uses. The apiserver
// dials the pod via kubelet, so pod-ingress NetworkPolicy cannot
// blackhole it the way it blackholes the direct pod-IP call.
func (r *zombieSidecarReaper) proxyShutdown(ctx context.Context, p *corev1.Pod, sidecar string) error {
	target, ok := zombieSidecarShutdownTargets[sidecar]
	if !ok {
		target = zombieSidecarShutdownTargets["linkerd-proxy"]
	}
	rc := r.cs.CoreV1().RESTClient()
	// The fake clientset returns a typed-nil *rest.RESTClient —
	// guard before dereferencing so unit tests degrade to "proxy
	// unreachable" instead of panicking.
	if rc == nil {
		return errors.New("pods/proxy REST client unavailable")
	}
	if restClient, ok := rc.(*rest.RESTClient); ok && restClient == nil {
		return errors.New("pods/proxy REST client unavailable")
	}
	return rc.Post().
		Namespace(p.Namespace).
		Resource("pods").
		Name(p.Name + ":" + strconv.Itoa(target.port)).
		SubResource("proxy").
		Suffix(strings.TrimPrefix(target.path, "/")).
		Timeout(zombieSidecarShutdownTimeout).
		Do(ctx).Error()
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

// zombieSidecarShutdown POSTs the sidecar's admin quit endpoint — the
// graceful exit path the proxy honors even when its pod's app
// containers are gone (linkerd :4191/shutdown, istio
// :15000/quitquitquit). An unknown sidecar name falls back to the
// linkerd endpoint: zombieSidecarNames only admits the two known
// names, so the fallback is unreachable in practice.
func zombieSidecarShutdown(ctx context.Context, podIP, sidecar string) error {
	target, ok := zombieSidecarShutdownTargets[sidecar]
	if !ok {
		target = zombieSidecarShutdownTargets["linkerd-proxy"]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		// JoinHostPort brackets IPv6 podIPs — plain %s:%d breaks on them.
		"http://"+net.JoinHostPort(podIP,
			strconv.Itoa(target.port))+target.path, nil)
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
		return fmt.Errorf("sidecar %s returned %s", target.path, resp.Status)
	}
	return nil
}
