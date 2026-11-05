// zombie_reap.go — the forceful exit: the Job-completion gate that
// must pass before a still-Running pod may be deleted
// (jobAllowsReap, backed by allZeroExit) and the pod delete itself
// (reap). Deleting a pod whose Job has not counted its exit-0
// completion makes the job-controller recreate it and re-run the
// Job (BUG-C1); the backoffLimit==0 exemption (W10-FIX3) exists
// because such a Job can spawn no replacement.
package zombiesidecarreaper

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

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
		metrics.IncError(r.queue)
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
		Delete(ctx, p.Name, shared.UIDDeleteOptions(uid, "")); err != nil {
		log.Error(err, "zombie pod delete failed", "pod", p.Namespace+"/"+p.Name)
		metrics.IncError(r.queue)
		return err
	}
	metrics.ZombieSidecarPodsReapedTotal.WithLabelValues(p.Namespace).Inc()
	return nil
}
