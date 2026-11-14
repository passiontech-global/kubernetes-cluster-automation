// helmrelease-unlocker failed helm-hook Job cleanup (C3a): the Job
// objects a killed release left behind block the retried release, so
// the pending-secret unlock sweeps them from the RELEASE namespace.
// split from helmrelease_unlocker.go (see its header for the module contract).
package helmreleaseunlocker

import (
	"context"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// cleanFailedHookJobs deletes batchv1 Jobs in ns that carry the
// helm.sh/hook annotation AND this release's attribution — the
// meta.helm.sh/release-name label helm stamps on every rendered
// resource, hooks included — and report JobFailed=True, with
// background propagation so their pods go with them. A hook Job
// without the label (or naming another release) is not provably
// this release's: unlocking one HelmRelease must never delete
// another release's failed hook residue an operator may be keeping
// for debugging, so unattributed Jobs are logged and skipped. Only
// FAILED hook Jobs are targets — a Running one is a live workload,
// never reaped. Each deletion bumps
// metrics.HelmHookJobsCleanedTotal{namespace}. Errors are logged and
// skipped — hook cleanup never fails the caller.
func (u *helmReleaseUnlocker) cleanFailedHookJobs(ctx context.Context, ns, release string) {
	log := logf.FromContext(ctx)
	jobs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Jobs(u.cs, ns))
	if err != nil {
		log.Error(err, "helm-hook job list failed — hook cleanup skipped", "ns", ns)
		return
	}
	var targets []*batchv1.Job
	for i := range jobs {
		j := &jobs[i]
		if _, ok := j.Annotations["helm.sh/hook"]; !ok {
			continue // not a helm hook — never ours to reap
		}
		if j.Labels[helmReleaseNameLabel] != release {
			log.Info("SKIP: helm-hook Job carries no attribution for this release — left alone",
				"ns", ns, "job", j.Name,
				"labeledRelease", j.Labels[helmReleaseNameLabel], "release", release)
			continue
		}
		if !kube.JobHasCondition(j, batchv1.JobFailed) {
			continue // still running or succeeded — leave it
		}
		targets = append(targets, j)
	}
	reap.Sweep(ctx, log, targets, reap.Options[*batchv1.Job]{
		LogTarget: func(log logr.Logger, j *batchv1.Job) {
			log.Info("ACTION: delete failed helm-hook Job",
				"ns", ns, "job", j.Name)
		},
		Delete: func(ctx context.Context, j *batchv1.Job) error {
			if err := u.cs.BatchV1().Jobs(ns).Delete(ctx, j.Name,
				kube.UIDDeleteOptions(j.UID, metav1.DeletePropagationBackground)); err != nil {
				return err
			}
			metrics.HelmHookJobsCleanedTotal.WithLabelValues(ns).Inc()
			return nil
		},
		// Delete failures are logged and skipped, never IncError'd —
		// the sweep is best-effort residue cleanup riding a heal,
		// and the periodic wrapper already counts the run error.
		OnError: reap.DeleteErrorHandler("helm-hook job",
			func(j *batchv1.Job) string { return ns + "/" + j.Name }, nil),
	})
}
