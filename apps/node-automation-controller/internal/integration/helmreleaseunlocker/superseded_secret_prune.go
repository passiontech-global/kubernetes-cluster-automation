// superseded_secret_prune.go — the W9-CP2 Kine bloat guard of
// helmrelease-unlocker: caps superseded helm release secrets per
// release (helm writes one sh.helm.release.v1 Secret per revision,
// each embedding the full compressed chart, and never GCs them).
// Runs on every sweep, independent of the stuck signatures.
package helmreleaseunlocker

import (
	"context"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	// maxSupersededSecrets caps the superseded helm release secrets
	// kept per release (W9-CP2 — Kine bloat guard): every revision
	// secret embeds the full compressed chart and helm never GCs
	// them, so a hot release grows Kine without bound.
	maxSupersededSecrets = 10
)

// pruneSupersededSecrets caps superseded helm release secrets per
// release. Helm writes one sh.helm.release.v1 Secret per revision and
// never garbage-collects the superseded ones — each embeds the full
// compressed chart, so a frequently-upgraded release grows Kine
// (and the storage backend behind it) without bound.
//
// For every release — grouped by storage namespace + the `name`
// label, the same identity unlock() scopes its revision scan to —
// secrets with status=="superseded" and a valid integer `version`
// label are sorted ascending; when a release holds more than
// maxSupersededSecrets the OLDEST excess are deleted with a UID
// precondition. deployed, pending-*, and failed secrets are NEVER
// touched — they are live install/rollback state, not history — and
// neither is the highest-version secret of the release, which stays
// the newest rollback point even when it is itself superseded.
func (u *helmReleaseUnlocker) pruneSupersededSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Cluster-wide, server-side filtered to helm release secrets —
	// owner=helm is the same label unlock() selects on. Paged like
	// every cluster-wide list in this module.
	secrets, err := shared.ListAll(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm", Limit: helmListPageSize},
		shared.Secrets(u.cs, metav1.NamespaceAll))
	if err != nil {
		// Hygiene sweep — a list failure must not fail the run
		// (same posture as cleanFailedHookJobs): the next sweep
		// retries, and IncError keeps it on the alert path.
		metrics.IncError(u.queue)
		log.Error(err, "superseded secret prune: list failed — skipped")
		return nil
	}
	// Group by storage namespace + release name.
	type relKey struct{ ns, name string }
	byRelease := map[relKey][]*corev1.Secret{}
	for i := range secrets {
		s := &secrets[i]
		release := s.Labels["name"]
		if release == "" || s.Type != corev1.SecretType(helmSecretType) {
			continue
		}
		k := relKey{s.Namespace, release}
		byRelease[k] = append(byRelease[k], s)
	}
	secrets = nil // release the cluster-wide slice before issuing deletes

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
	pruned := 0
	for k, relSecrets := range byRelease {
		// Highest revision across ALL statuses — the one secret that
		// is never pruned even when it is itself superseded.
		highest := -1
		var superseded []supersededSecret
		for _, s := range relSecrets {
			v, err := strconv.Atoi(s.Labels["version"])
			if err != nil {
				continue // unversioned — never ours to judge
			}
			if v > highest {
				highest = v
			}
			if s.Labels["status"] == "superseded" {
				superseded = append(superseded, supersededSecret{s, v})
			}
		}
		if len(superseded) <= maxSupersededSecrets {
			continue
		}
		sort.Slice(superseded, func(i, j int) bool {
			return superseded[i].v < superseded[j].v
		})
		toDelete := len(superseded) - maxSupersededSecrets
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if cand.v == highest {
				continue // never touch the highest-version secret
			}
			log.Info("ACTION: prune superseded helm release secret",
				"release", k.ns+"/"+k.name, "secret", cand.s.Name,
				"version", cand.v, "supersededTotal", len(superseded))
			if err := u.cs.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, shared.UIDDeleteOptions(cand.s.UID, "")); err != nil {
				metrics.IncError(u.queue)
				log.Error(err, "superseded secret delete failed",
					"secret", cand.s.Namespace+"/"+cand.s.Name)
				continue // try the next-oldest instead of giving up
			}
			metrics.HelmSecretsPrunedTotal.WithLabelValues(cand.s.Namespace).Inc()
			pruned++
			toDelete--
		}
	}
	if pruned > 0 {
		log.Info("superseded helm secret prune done", "pruned", pruned)
	}
	return nil
}
