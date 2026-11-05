// replicated_secret_audit.go — Check E of cert-drift-auditor
// (W7-C6): diffs each replicator.v1.mittwald.de/replicated-from TLS
// copy's tls.crt against its source. A mismatch that persists for
// replicationDriftScans consecutive sweeps flags
// replicated_secret_drift=1 and (W8-NM2) strips the
// replicated-from-version stamp to force a kubernetes-replicator
// resync — rate-limited to once per destination per hour.
package certdriftauditor

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Check E — kubernetes-replicator sync drift (W7-C6)
// ---------------------------------------------------------------------------

// auditReplicatedSecrets diffs each replicated TLS secret's tls.crt
// against its source. The comparison is bytes — the replicator
// copies data verbatim, so ANY byte difference is drift (a rotated
// source cert the copy missed, or a hand-edited destination). A
// mismatch must persist replicationDriftScans consecutive sweeps
// before the gauge fires: a single-scan diff is the replicator
// mid-sync, not a wedge. A matched copy resets the streak and drops
// any held series via DeleteLabelValues.
func (a *certDriftAuditor) auditReplicatedSecrets(ctx context.Context,
	tlsData map[string][]byte, replicated []replicatedSecretRef) {
	log := logf.FromContext(ctx)

	for _, d := range replicated {
		k := replicationMetricKey{
			namespace: d.namespace, name: d.name, source: d.source}
		src, ok := tlsData[d.source]
		if !ok {
			// Source not in the TLS sweep — it may be a non-TLS
			// (Opaque) secret; a direct Get resolves it. Malformed
			// refs and genuinely-missing sources are skipped —
			// "can't compare" is not drift. A transient Get failure
			// carries the last verdict forward (same shape as the
			// cainjector path's carry-forward).
			srcNS, srcName, refOK := splitNSName(d.source)
			if !refOK {
				log.Info("skip: malformed replicated-from annotation",
					"secret", d.namespace+"/"+d.name, "value", d.source)
				continue
			}
			s, err := a.cs.CoreV1().Secrets(srcNS).Get(ctx, srcName, metav1.GetOptions{})
			switch {
			case err == nil:
				src = s.Data["tls.crt"]
				if len(src) == 0 {
					continue // source has no tls.crt — nothing to compare
				}
			case apierrors.IsNotFound(err):
				continue // source gone — the replica's problem, not drift
			default:
				log.Error(err, "replicated source get failed — verdict carried forward",
					"secret", d.namespace+"/"+d.name, "source", d.source)
				if lv, ok := a.seenReplication.Last()[k]; ok {
					a.seenReplication.Emit(k, lv...)
				}
				continue
			}
		}
		a.seenReplication.Emit(k, k.namespace, k.name, k.source)
		if bytes.Equal(d.dest, src) {
			delete(a.replicationMismatch, k)
			if _, ok := a.seenReplication.Last()[k]; ok {
				metrics.ReplicatedSecretDrift.
					DeleteLabelValues(k.namespace, k.name, k.source)
			}
			continue
		}
		a.replicationMismatch[k]++
		if a.replicationMismatch[k] < replicationDriftScans {
			continue // first mismatch — the replicator may be mid-sync
		}
		metrics.ReplicatedSecretDrift.
			WithLabelValues(k.namespace, k.name, k.source).Set(1)
		log.Info("replicated tls secret drifted from source across scans",
			"secret", d.namespace+"/"+d.name, "source", d.source,
			"consecutiveScans", a.replicationMismatch[k])
		// W8-NM2: a confirmed drift means the replicator missed the
		// update — stripping the replicated-from-version stamp
		// makes it resync on its next reconcile (1h cooldown).
		a.forceReplicationResync(ctx, d, k)
	}

	// Prune series + streaks for replicas gone (or sources no longer
	// comparable) since the last sweep.
	a.seenReplication.Prune(metrics.ReplicatedSecretDrift.DeleteLabelValues)
	for k := range a.replicationMismatch {
		if _, ok := a.seenReplication.Last()[k]; !ok {
			delete(a.replicationMismatch, k)
		}
	}
}

// forceReplicationResync strips the replicated-from-version
// annotation on a drifted destination so kubernetes-replicator copies
// the source fresh on its next pass — rate-limited to once per
// destination per hour (in-RAM: the annotation removal is the heal).
func (a *certDriftAuditor) forceReplicationResync(ctx context.Context,
	d replicatedSecretRef, k replicationMetricKey) {
	log := logf.FromContext(ctx)
	if a.resyncNudged == nil {
		a.resyncNudged = map[replicationMetricKey]time.Time{} // literal-constructed auditors (tests)
	}
	now := a.now.Now()
	if last, ok := a.resyncNudged[k]; ok && now.Sub(last) < replicationResyncCooldown {
		log.Info("skip resync: replicated secret inside cooldown",
			"secret", d.namespace+"/"+d.name,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			replicatedFromVersionAnno: nil,
		}},
	})
	if err != nil {
		return
	}
	if _, err := a.cs.CoreV1().Secrets(d.namespace).Patch(ctx, d.name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "replicated-from-version strip failed",
			"secret", d.namespace+"/"+d.name)
		return
	}
	a.resyncNudged[k] = now
	log.Info("ACTION: stripped replicated-from-version — forcing kubernetes-replicator resync",
		"secret", d.namespace+"/"+d.name, "source", d.source)
}
