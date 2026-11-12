// helm_secret_prune.go — the helm release secret census + superseded
// revision prune of the api-object-sprawl-report-gc check, parallel to
// helmrelease-unlocker's pruneSupersededSecrets.
package sprawl

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/helmprune"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// sprawlMaxSuperseded is the per-release keep cap for superseded
	// helm revision secrets.
	sprawlMaxSuperseded = 10

	// sprawlHelmSecretsResource is the resource label the census
	// reports helm release secrets under (they are core Secrets, so
	// no GVR of their own exists to reuse).
	sprawlHelmSecretsResource = "helm_release_secrets"
)

var (
	// Superseded helm revision secrets above the keep cap, per release.
	helmSecretsExcessGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_helm_release_secrets_excess",
		Help: "Superseded helm release secrets beyond the per-release keep cap.",
	}, []string{"namespace", "release"})

	// Superseded helm revision secrets pruned by this check.
	helmReleaseSecretsPrunedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_helm_release_secrets_pruned_total",
		Help: "Superseded helm release secrets pruned by the sprawl GC, by namespace.",
	}, []string{"namespace"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(helmSecretsExcessGauge, helmReleaseSecretsPrunedTotal)
}

// pruneHelmSecrets counts helm release secrets into the census and
// caps superseded revisions per release. The selection + delete
// policy lives in the shared helmprune.PruneSupersededHelmSecrets (its
// header documents the deliberate duplication with
// helmrelease-unlocker and why both cluster-wide reads stay); this
// site keeps only its census/report side effects.
func (p *apiObjectSprawlReportGCCheck) pruneHelmSecrets(ctx context.Context,
	log logr.Logger, objects, helmRep *probefw.SweepReport) error {

	secrets, err := helmprune.PruneSupersededHelmSecrets(ctx, p.CS,
		sprawlMaxSuperseded, helmprune.HelmSecretPruneHooks{
			Excess: func(ns, release string, superseded, cap int) {
				helmRep.Set(helmSecretsExcessGauge,
					float64(superseded-cap), ns+"/"+release,
					[]string{ns, release})
				objects.Find(fmt.Sprintf(
					"release %s/%s holds %d superseded secrets (cap %d)",
					ns, release, superseded, cap))
			},
			Deleted: func(s *corev1.Secret, version int) {
				helmReleaseSecretsPrunedTotal.WithLabelValues(s.Namespace).Inc()
				log.Info("DELETE: superseded helm release secret above keep cap",
					"release", s.Namespace+"/"+s.Labels["name"],
					"secret", s.Name, "version", version)
			},
			DeleteFailed: func(s *corev1.Secret, err error) {
				metrics.IncError(p.Name)
				log.Error(err, "superseded helm secret delete failed",
					"secret", s.Namespace+"/"+s.Name)
			},
		})
	if err != nil {
		return fmt.Errorf("list helm release secrets: %w", err)
	}
	perNS := map[string]int{}
	for i := range secrets {
		perNS[secrets[i].Namespace]++
	}
	for ns, count := range perNS {
		objects.Set(apiObjectCountGauge, float64(count),
			sprawlHelmSecretsResource+"/"+ns,
			[]string{sprawlHelmSecretsResource, ns})
	}
	return nil
}
