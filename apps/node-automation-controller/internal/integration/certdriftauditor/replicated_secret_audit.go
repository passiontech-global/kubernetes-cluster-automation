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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Check E — kubernetes-replicator sync drift (W7-C6)
// ---------------------------------------------------------------------------

// replStreakKey flattens the replicationMetricKey tuple into the
// StreakLedger's string key space (the gauge ledger keeps the struct
// key; StreakLedger is string-keyed — a slash inside the source VALUE
// is unambiguous, same contract as the metric labels).
func replStreakKey(k replicationMetricKey) string {
	return k.namespace + "/" + k.name + "/" + k.source
}

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
	a.seenReplication.Begin() // drop any aborted sweep's leftover emissions
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
			a.replicationMismatch.Reset(replStreakKey(k))
			if _, ok := a.seenReplication.Last()[k]; ok {
				metrics.ReplicatedSecretDrift.
					DeleteLabelValues(k.namespace, k.name, k.source)
			}
			continue
		}
		if streak := a.replicationMismatch.Hit(replStreakKey(k)); streak < replicationDriftScans {
			continue // first mismatch — the replicator may be mid-sync
		}
		a.seenReplication.Set(metrics.ReplicatedSecretDrift, 1,
			k, k.namespace, k.name, k.source)
		log.Info("replicated tls secret drifted from source across scans",
			"secret", d.namespace+"/"+d.name, "source", d.source,
			"consecutiveScans", a.replicationMismatch.Count(replStreakKey(k)))
		// W8-NM2: a confirmed drift means the replicator missed the
		// update — stripping the replicated-from-version stamp
		// makes it resync on its next reconcile (1h cooldown).
		a.forceReplicationResync(ctx, d, k)
	}

	// Prune series + streaks for replicas gone (or sources no longer
	// comparable) since the last sweep.
	a.seenReplication.Prune(metrics.ReplicatedSecretDrift.DeleteLabelValues)
	live := map[string]bool{}
	for k := range a.seenReplication.Last() {
		live[replStreakKey(k)] = true
	}
	a.replicationMismatch.Prune(func(key string) bool { return live[key] })
	// Same complete-sweep point, same leak bound as the streaks: the
	// resync cooldown ledger keys on destination names that can be
	// decommissioned, and a stamp past the 1h window can never
	// suppress a future strip anyway — evict it instead of pinning it
	// forever.
	a.resyncHeals.PruneExpired(a.now.Now(), replicationResyncCooldown)
}

// forceReplicationResync strips the replicated-from-version
// annotation on a drifted destination so kubernetes-replicator copies
// the source fresh on its next pass — rate-limited to once per
// destination per hour (in-RAM: the annotation removal is the heal;
// CooldownSet arms itself lazily for literal-constructed fixtures).
func (a *certDriftAuditor) forceReplicationResync(ctx context.Context,
	d replicatedSecretRef, k replicationMetricKey) {
	log := logf.FromContext(ctx)
	now := a.now.Now()
	if last, ok := a.resyncHeals.Last(replStreakKey(k)); ok &&
		now.Sub(last) < replicationResyncCooldown {
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
	a.resyncHeals.Stamp(replStreakKey(k), now)
	log.Info("ACTION: stripped replicated-from-version — forcing kubernetes-replicator resync",
		"secret", d.namespace+"/"+d.name, "source", d.source)
}
