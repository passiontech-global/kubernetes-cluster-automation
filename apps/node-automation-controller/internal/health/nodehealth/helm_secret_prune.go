// helm_secret_prune.go — the helm release secret census + superseded
// revision prune of the api-object-sprawl-report-gc check, parallel to
// helmrelease-unlocker's pruneSupersededSecrets.
package nodehealth

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// sprawlMaxSuperseded is the per-release keep cap for superseded
	// helm revision secrets.
	sprawlMaxSuperseded = 10

	// sprawlHelmSecretType is the Secret type helm writes per
	// revision — same literal helmrelease-unlocker selects on.
	sprawlHelmSecretType = "helm.sh/release.v1"
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
// caps superseded revisions per release. This is parallel logic to
// helmrelease-unlocker's pruneSupersededSecrets — that one is a
// method on the unlocker's private type and cannot be imported, so
// the parity contract is kept verbatim here: group by namespace +
// `name` label, only `status=superseded` secrets with a valid integer
// `version` label are prune candidates, the oldest beyond the cap are
// deleted with a UID precondition, and the highest-version secret of
// the release is NEVER touched (it stays the newest rollback point
// even when itself superseded). Findings for the check's why string
// and the helm-excess gauge tuples are recorded on the reports.
func (p *apiObjectSprawlReportGCCheck) pruneHelmSecrets(ctx context.Context,
	log logr.Logger, objects, helmRep *probefw.SweepReport) error {

	// owner=helm,status=superseded server-side: every superseded
	// revision carries that label pair (helm v3 convention — the same
	// labels pruneSupersededSecrets and the test fixtures use), so
	// the live deployed/pending/failed revisions never cross the wire.
	// The census below therefore counts the superseded population —
	// the actual bloat the helm_release_secrets series exists to
	// track. The per-release "highest" guard still protects the
	// newest superseded revision (the rollback point), and a
	// non-superseded current revision was never a candidate anyway.
	//
	// NOTE: this cluster-wide LIST duplicates
	// integration/helmreleaseunlocker's superseded_secret_prune.go
	// (helmrelease-unlocker, 10m) — same owner=helm,status=superseded
	// selector, same per-release cap. Deliberate: the trees cannot
	// share a read (different sweep ctx and cadence), and THIS side's
	// list is load-bearing beyond the prune — it feeds the
	// api_object_count helm_release_secrets/<ns> census and the
	// sprawl-report findings, so dropping or deferring it would
	// change the report, not just the deletes. There is no
	// helm-release-namespace index to namespace-scope either list to
	// (a per-namespace fan-out would replace one paged LIST with N).
	secrets, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm,status=superseded",
		Limit:         probefw.HealthListPageSize},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return fmt.Errorf("list helm release secrets: %w", err)
	}
	type relKey struct{ ns, release string }
	byRelease := map[relKey][]*corev1.Secret{}
	perNS := map[string]int{}
	for i := range secrets {
		s := &secrets[i]
		if s.Type != corev1.SecretType(sprawlHelmSecretType) {
			continue
		}
		perNS[s.Namespace]++
		release := s.Labels["name"]
		if release == "" {
			continue
		}
		k := relKey{s.Namespace, release}
		byRelease[k] = append(byRelease[k], s)
	}
	for ns, count := range perNS {
		objects.Set(apiObjectCountGauge, float64(count),
			sprawlHelmSecretsResource+"/"+ns,
			[]string{sprawlHelmSecretsResource, ns})
	}

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
	for k, relSecrets := range byRelease {
		highest := -1
		var superseded []supersededSecret
		for _, s := range relSecrets {
			v, verr := strconv.Atoi(s.Labels["version"])
			if verr != nil {
				continue // unversioned — never ours to judge
			}
			if v > highest {
				highest = v
			}
			if s.Labels["status"] == "superseded" {
				superseded = append(superseded, supersededSecret{s, v})
			}
		}
		excess := len(superseded) - sprawlMaxSuperseded
		if excess <= 0 {
			continue
		}
		helmRep.Set(helmSecretsExcessGauge, float64(excess),
			k.ns+"/"+k.release, []string{k.ns, k.release})
		objects.Find(fmt.Sprintf(
			"release %s/%s holds %d superseded secrets (cap %d)",
			k.ns, k.release, len(superseded), sprawlMaxSuperseded))
		sort.Slice(superseded, func(i, j int) bool {
			return superseded[i].v < superseded[j].v
		})
		toDelete := excess
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if cand.v == highest {
				continue // never touch the newest rollback point
			}
			if err := p.CS.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, kube.UIDDeleteOptions(cand.s.UID, "")); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "superseded helm secret delete failed",
					"secret", cand.s.Namespace+"/"+cand.s.Name)
				continue // try the next-oldest instead of giving up
			}
			helmReleaseSecretsPrunedTotal.WithLabelValues(cand.s.Namespace).Inc()
			log.Info("DELETE: superseded helm release secret above keep cap",
				"release", k.ns+"/"+k.release, "secret", cand.s.Name,
				"version", cand.v)
			toDelete--
		}
	}
	return nil
}
