// superseded_secret_prune.go — the kine-bloat-guard Kine bloat guard of
// helmrelease-unlocker: caps superseded helm release secrets per
// release (helm writes one sh.helm.release.v1 Secret per revision,
// each embedding the full compressed chart, and never GCs them).
// Runs on every sweep, independent of the stuck signatures.
package helmreleaseunlocker

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// maxSupersededSecrets caps the superseded helm release secrets
	// kept per release (kine-bloat-guard — Kine bloat guard): every revision
	// secret embeds the full compressed chart and helm never GCs
	// them, so a hot release grows Kine without bound.
	maxSupersededSecrets = 10
)

// pruneSupersededSecrets caps superseded helm release secrets per
// release — the kine-bloat-guard hygiene sweep on the shared
// kube.PruneSupersededHelmSecrets prune (its header documents the
// deliberate duplication with api-object-sprawl-report-gc's census
// and why both cluster-wide reads stay). This site keeps its failure
// posture: a list failure must not fail the run — the next sweep
// retries, and IncError keeps it on the alert path.
func (u *helmReleaseUnlocker) pruneSupersededSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)
	pruned := 0
	_, err := kube.PruneSupersededHelmSecrets(ctx, u.cs,
		maxSupersededSecrets, kube.HelmSecretPruneHooks{
			PreDelete: func(s *corev1.Secret, version, supersededTotal int) {
				log.Info("ACTION: prune superseded helm release secret",
					"release", s.Namespace+"/"+s.Labels["name"],
					"secret", s.Name, "version", version,
					"supersededTotal", supersededTotal)
			},
			Deleted: func(s *corev1.Secret, _ int) {
				metrics.HelmSecretsPrunedTotal.WithLabelValues(s.Namespace).Inc()
				pruned++
			},
			DeleteFailed: func(s *corev1.Secret, err error) {
				metrics.IncError(u.queue)
				log.Error(err, "superseded secret delete failed",
					"secret", s.Namespace+"/"+s.Name)
			},
		})
	if err != nil {
		// Hygiene sweep — a list failure must not fail the run
		// (same posture as cleanFailedHookJobs): the next sweep
		// retries, and IncError keeps it on the alert path.
		metrics.IncError(u.queue)
		log.Error(err, "superseded secret prune: list failed — skipped")
		return nil
	}
	if pruned > 0 {
		log.Info("superseded helm secret prune done", "pruned", pruned)
	}
	return nil
}
