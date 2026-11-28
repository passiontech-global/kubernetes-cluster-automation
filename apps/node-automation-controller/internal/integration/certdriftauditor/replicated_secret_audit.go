// replicated_secret_audit.go — Check E of cert-drift-auditor
// (replicator-cert-drift): diffs each replicator.v1.mittwald.de/replicated-from TLS
// copy's tls.crt against its source. A mismatch that persists for
// replicationDriftScans consecutive sweeps flags
// replicated_secret_drift=1 and (issuer-serial-watch) strips the
// replicated-from-version stamp to force a kubernetes-replicator
// resync — rate-limited to once per destination per hour.
package certdriftauditor

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Check E — kubernetes-replicator sync drift (replicator-cert-drift)
// ---------------------------------------------------------------------------

// replStreakKey flattens the replicationMetricKey tuple into the
// StreakLedger's string key space (the gauge ledger keeps the struct
// key; StreakLedger is string-keyed — a slash inside the source VALUE
// is unambiguous, same contract as the metric labels).
func replStreakKey(k replicationMetricKey) string {
	return k.namespace + "/" + k.name + "/" + k.source
}

// parseLiteralReplicateTo parses a comma-separated replicate-to
// annotation into deduplicated literal target namespace names, skipping
// empty tokens, regex-metacharacter patterns, and the source namespace.
func parseLiteralReplicateTo(srcNS, raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	var seen map[string]bool
	for tok := range strings.SplitSeq(raw, ",") {
		ns := strings.TrimSpace(tok)
		if ns == "" || ns == srcNS {
			continue
		}
		if strings.ContainsAny(ns, `*?+[]()^$|\`) {
			continue
		}
		if seen == nil {
			seen = map[string]bool{}
		}
		if seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, ns)
	}
	return out
}

// auditReplicatedSecrets diffs each replicated TLS secret's tls.crt
// against its source — the source is a direct Secret GET per replica
// (replicated secrets are rare; the audit no longer retains a
// cluster-wide tls.crt map). The comparison is bytes — the replicator
// copies data verbatim, so ANY byte difference is drift (a rotated
// source cert the copy missed, or a hand-edited destination). A
// mismatch must persist replicationDriftScans consecutive sweeps
// before the gauge fires: a single-scan diff is the replicator
// mid-sync, not a wedge. A matched copy resets the streak and drops
// any held series via DeleteLabelValues. It also checks literal
// replicate-to targets against active namespaces to catch silent push
// rejections (e.g. -push-allowed-source-namespaces exclusions).
func (a *certDriftAuditor) auditReplicatedSecrets(ctx context.Context,
	replicated []replicatedSecretRef,
	replicateToSources []replicateToSourceRef,
	presentTLS map[secretMetricKey]bool) {
	a.seenReplication.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	for _, d := range replicated {
		k := replicationMetricKey{
			namespace: d.namespace, name: d.name, source: d.source}
		// The source is fetched directly — replicated secrets are a
		// handful per cluster, so one GET each beats retaining every
		// TLS secret's tls.crt bytes for the whole audit. A
		// malformed ref or genuinely-missing source is skipped —
		// "can't compare" is not drift. A transient Get failure
		// carries the last verdict forward (same shape as the
		// cainjector path's carry-forward).
		var srcSecret *corev1.Secret
		var src []byte
		{
			srcNS, srcName, refOK := splitNSName(d.source)
			if !refOK {
				log.Info("skip: malformed replicated-from annotation",
					"secret", d.namespace+"/"+d.name, "value", d.source)
				continue
			}
			s, err := a.cs.CoreV1().Secrets(srcNS).Get(ctx, srcName, metav1.GetOptions{})
			switch {
			case err == nil:
				srcSecret = s
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
		if bytes.Equal(d.dest, src) {
			a.replicationMismatch.Reset(replStreakKey(k))
			if _, ok := a.seenReplication.Last()[k]; ok {
				metrics.ReplicatedSecretDrift.
					DeleteLabelValues(k.namespace, k.name, k.source)
			}
			continue
		}
		// Mismatch — register the tuple ONLY now: the ledger entry is
		// what keeps this key in the `live` set the streak Prune
		// reads, so a warmup streak survives to confirm. Emitting for
		// HEALTHY secrets too (the old placement) pinned every replica
		// in the ledger forever — its streak key never pruned and its
		// DeleteLabelValues re-ran every sweep for a series that does
		// not exist.
		a.seenReplication.Emit(k, k.namespace, k.name, k.source)
		streak := a.replicationMismatch.Hit(replStreakKey(k))
		if streak < replicationDriftScans {
			continue // first mismatch — the replicator may be mid-sync
		}
		a.seenReplication.Set(metrics.ReplicatedSecretDrift, 1,
			k, k.namespace, k.name, k.source)
		log.Info("replicated tls secret drifted from source across scans",
			"secret", d.namespace+"/"+d.name, "source", d.source,
			"consecutiveScans", streak)
		// Escalate to direct data fallback sync if kubernetes-replicator did
		// not converge 2+ sweeps after stripping replicated-from-version.
		if streak >= replicationDirectSyncScans && !a.disableReplicatedDirectSync {
			a.directSyncReplicatedSecret(ctx, d, k, srcSecret)
			continue
		}
		// issuer-serial-watch: a confirmed drift means the replicator missed the
		// update — stripping the replicated-from-version stamp
		// makes it resync on its next reconcile (1h cooldown).
		a.forceReplicationResync(ctx, d, k)
	}

	if len(replicateToSources) > 0 {
		a.auditMissingReplicateToTargets(ctx, replicateToSources, presentTLS)
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
	// resync/direct-sync cooldown ledgers key on destination names that
	// can be decommissioned, and a stamp past the 1h window can never
	// suppress a future heal anyway — evict it instead of pinning it
	// forever.
	now := a.now.Now()
	a.resyncHeals.PruneExpired(now, replicationResyncCooldown)
	a.directSyncHeals.PruneExpired(now, replicationResyncCooldown)
}

func (a *certDriftAuditor) auditMissingReplicateToTargets(ctx context.Context,
	sources []replicateToSourceRef,
	presentTLS map[secretMetricKey]bool) {
	log := logf.FromContext(ctx)
	nsList, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize, ResourceVersion: "0"},
		kube.Namespaces(a.cs))
	if err != nil {
		// Transient namespace-list failure must not prune active
		// replicate-to drift alerts or wipe mismatch streaks: carry
		// forward previously-emitted target entries for these sources.
		log.Info("skip replicate-to target audit: list namespaces failed — carrying prior series", "error", err)
		srcRefs := make(map[string]bool, len(sources))
		for _, src := range sources {
			srcRefs[src.namespace+"/"+src.name] = true
		}
		for k, lv := range a.seenReplication.Last() {
			if len(lv) >= 3 && srcRefs[lv[2]] && !presentTLS[secretMetricKey{k.namespace, k.name}] {
				a.seenReplication.Emit(k, lv...)
			}
		}
		return
	}
	activeNS := make(map[string]bool, len(nsList))
	for i := range nsList {
		ns := &nsList[i]
		if ns.DeletionTimestamp == nil && ns.Status.Phase != corev1.NamespaceTerminating {
			activeNS[ns.Name] = true
		}
	}
	for _, src := range sources {
		sourceRef := src.namespace + "/" + src.name
		for _, targetNS := range src.targets {
			if !activeNS[targetNS] {
				continue
			}
			if presentTLS[secretMetricKey{targetNS, src.name}] {
				continue
			}
			k := replicationMetricKey{
				namespace: targetNS,
				name:      src.name,
				source:    sourceRef,
			}
			a.seenReplication.Emit(k, k.namespace, k.name, k.source)
			streak := a.replicationMismatch.Hit(replStreakKey(k))
			if streak < replicationDriftScans {
				continue
			}
			a.seenReplication.Set(metrics.ReplicatedSecretDrift, 1,
				k, k.namespace, k.name, k.source)
			log.Info("replicated tls secret missing in replicate-to target namespace",
				"namespace", targetNS, "secret", targetNS+"/"+src.name,
				"source", sourceRef, "consecutiveScans", streak)
		}
	}
}

// directSyncReplicatedSecret merge-patches tls.crt (and tls.key, ca.crt
// when present) from the source Secret onto a persistently drifted
// destination when kubernetes-replicator fails to converge after
// replicated-from-version stripping (rate-limited to 1h per destination).
func (a *certDriftAuditor) directSyncReplicatedSecret(ctx context.Context,
	d replicatedSecretRef, k replicationMetricKey, srcSecret *corev1.Secret) {
	if srcSecret == nil {
		return
	}
	log := logf.FromContext(ctx)
	now := a.now.Now()
	if last, ok := a.directSyncHeals.Last(replStreakKey(k)); ok &&
		now.Sub(last) < replicationResyncCooldown {
		log.Info("skip direct sync: replicated secret inside cooldown",
			"secret", d.namespace+"/"+d.name,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	patchData := map[string][]byte{}
	for _, key := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if v := srcSecret.Data[key]; len(v) > 0 {
			patchData[key] = v
		}
	}
	if len(patchData) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]any{"data": patchData})
	if err != nil {
		return
	}
	if _, err := a.cs.CoreV1().Secrets(d.namespace).Patch(ctx, d.name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "direct sync patch failed",
			"secret", d.namespace+"/"+d.name, "source", d.source)
		return
	}
	a.directSyncHeals.Stamp(replStreakKey(k), now)
	log.Info("ACTION: direct-synced drifted replicated TLS secret from source (kubernetes-replicator did not converge)",
		"secret", d.namespace+"/"+d.name, "source", d.source)
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
