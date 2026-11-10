// zombie_reap.go — the forceful-exit gate: the Job-completion check
// that must pass before a still-Running pod may be deleted
// (jobAllowsReap, backed by allZeroExit) — wired as the Confirm step
// of the reap.Sweep delete loop in zombie_sidecar_reaper.go.
// Deleting a pod whose Job has not counted its exit-0
// completion makes the job-controller recreate it and re-run the
// Job (BUG-C1); the backoffLimit==0 exemption (sidecar-shutdown-fallback) exists
// because such a Job can spawn no replacement.
package zombiesidecarreaper

import (
	"context"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
// Job already recorded the success — JobComplete=True, or
// Status.Succeeded covering spec.completions. Deleting earlier makes
// the job-controller recreate the pod and re-run the Job (BUG-C1);
// on a parallel Job (completions>1) the FIRST finished pod alone
// must not unlock the reap of its still-Running siblings — the Job
// controller would count each deleted pod as lost work and spawn
// replacements that re-run it. A pod with any non-zero app exit
// needs no such gate: a re-run after a failed exit is the Job's own
// retry semantics, not a double-success. A missing Job object means
// no controller can recreate the pod — safe to reap; any other Get
// failure is "cannot verify" and fails closed.
//
// sidecar-shutdown-fallback exception: a Job with spec.backoffLimit==0 spawns NO
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
	job, getErr := r.cs.BatchV1().Jobs(p.Namespace).Get(ctx, jobName, metav1.GetOptions{})
	jobGone, err := kube.ConfirmAbsent(getErr)
	switch {
	case jobGone:
		return true // Job gone — nobody recreates the pod
	case err != nil:
		metrics.IncError(r.queue)
		log.Info("WARN: job lookup failed — keeping still-Running exit-0 pod (fail closed)",
			"pod", p.Namespace+"/"+p.Name, "job", jobName, "error", err)
		return false
	case jobComplete(job):
		return true
	case shutdownAttempted && job.Spec.BackoffLimit != nil &&
		*job.Spec.BackoffLimit == 0 && singleCompletionJob(job):
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

// jobComplete reports whether the Job has finished ALL of its work:
// either the JobComplete condition is True or the succeeded count
// already covers spec.completions (unset means 1). Status.Succeeded
// >= 1 alone is NOT enough — a parallel Job keeps scheduling pods
// until every completion is counted, so reaping a still-Running
// sibling after the first success would make the job-controller
// spawn a replacement and re-run work.
func jobComplete(job *batchv1.Job) bool {
	want := int32(1)
	if job.Spec.Completions != nil {
		want = *job.Spec.Completions
	}
	if job.Status.Succeeded >= want {
		return true
	}
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// singleCompletionJob reports whether the Job schedules exactly one
// pod (spec.completions unset or 1) — the shape the backoffLimit==0
// exemption was designed for. On a parallel Job a deleted pod counts
// as a failure against backoffLimit, so reaping a zombie sibling
// would fail the whole Job rather than merely skip a respawn.
func singleCompletionJob(job *batchv1.Job) bool {
	return job.Spec.Completions == nil || *job.Spec.Completions <= 1
}
