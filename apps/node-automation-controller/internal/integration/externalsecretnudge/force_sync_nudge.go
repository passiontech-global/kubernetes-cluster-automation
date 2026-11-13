// force_sync_nudge.go — the nudge pass of externalsecret-nudge: every
// ExternalSecret Ready=False for longer than esStuckAge gets the
// force-sync + passiontech.dev/last-es-nudge annotations merge-patched on,
// forcing an immediate ESO reconcile that skips the remaining
// backoff. Rate-limited to one stamp per esNudgeCooldown by the
// persisted stamps esNudgeStamp reads back — durable across restarts,
// so no in-RAM ledger is needed.
// Also carries the externalsecret-storm-guard storm census: a mass-failure storm
// suppresses every stamp and feeds the connect auto-heal — and the
// empty-key-audit hygiene pair: the empty/whitespace-key audit on Ready=True
// ExternalSecrets, plus the empty-skeleton Secret delete that runs
// right before each delivered stamp.
package externalsecretnudge

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// nudge stamps force-sync on every eligible ExternalSecret Ready=
// False for longer than esStuckAge, at most once per esNudgeCooldown.
// recovered=true is the edge fast-path (any stuck ES qualifies); with
// recovered=false only ESs whose referenced stores are ALL Ready=True
// qualify (state-based path). anyReady reports whether at least one
// store is currently Ready=True — with neither it and no recovery
// edge there is nobody to poke, so the sweep is a no-op census.
//
// externalsecret-storm-guard storm guard: when >=esStormMinFailing ExternalSecrets are
// Ready=False AND they are at least half the population, the failure
// is an upstream ESO/1Password outage, not N independent wedged ESs —
// stamping force-sync on all of them would amplify the outage, so the
// pass logs STORM-GUARD, sets the suppression gauge and skips every
// stamp. A storm (or a ClusterSecretStore down) persisting
// esConnectHealMinAge also triggers the onepassword-connect pod
// bounce via maybeHealConnect.
func (n *externalSecretNudge) nudge(ctx context.Context, recovered, anyReady bool) error {
	log := logf.FromContext(ctx)
	// Fresh per-pass secret-read memoizer — the audit + skeleton
	// reaper share it, and it must not outlive the pass (a Secret
	// written between passes must be re-read).
	n.secretReads = map[string]secretRead{}
	// Release the per-pass caches when the pass ends — secretIndex
	// holds the whole Secret metadata census of every ES namespace,
	// pinned for the full 10-minute idle window otherwise. Deferred
	// so an early CRD-removal/error return releases them too.
	defer func() {
		n.secretReads = nil
		n.secretIndex = nil
		n.secretIndexOK = nil
	}()
	list, esGVR, err := n.listES(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			// CRD removal is a verified-empty census — prune every
			// emitted empty-key series so nothing flagged while ESO
			// was installed lingers after the CRDs go away. Begin
			// first so a previously-aborted pass's leftover
			// "current" emissions cannot survive the prune, then
			// reset the ESO-scoped maps/clocks with the CRDs.
			n.emptyKeyEmitted.Begin()
			n.emptyKeyEmitted.Prune(metrics.ExternalSecretEmptyKey.DeleteLabelValues)
			metrics.ExternalSecretStormSuppressed.Set(0)
			n.resetESOState()
			log.Info("skip: external-secrets CRDs not installed")
			return nil
		}
		return fmt.Errorf("list externalsecrets: %w", err)
	}
	now := n.now.Now()

	// secret-probe index (secret_probe.go): one metadata LIST per
	// ES namespace replaces the per-ES target-Secret GETs whenever
	// the Secret's RV is unchanged. Rebuilt every pass — the census
	// must never outlive it.
	n.buildSecretIndex(ctx, esProbeNamespaces(list))
	// Drop verdict-cache entries for ExternalSecrets that vanished —
	// same lifecycle as storeReady: a delete+recreate re-probes
	// fresh instead of inheriting the old object's verdicts.
	esLive := map[string]bool{}
	for i := range list.Items {
		esLive[list.Items[i].GetNamespace()+"/"+list.Items[i].GetName()] = true
	}
	for k := range n.secretVerdicts {
		if !esLive[k] {
			delete(n.secretVerdicts, k)
		}
	}

	// externalsecret-storm-guard — storm census over the WHOLE population: totalES is
	// every ExternalSecret, failingES every Ready=False one. The
	// ratio clause keeps a big healthy fleet from tripping on a
	// handful of unrelated failures.
	totalES, failingES := 0, 0
	for i := range list.Items {
		totalES++
		if c, _ := kube.ConditionOf(list.Items[i].Object, "Ready"); c.Status == "False" {
			failingES++
		}
	}
	storm := failingES >= esStormMinFailing && failingES*2 >= totalES
	if storm {
		metrics.ExternalSecretStormSuppressed.Set(1)
		if n.stormSince.IsZero() {
			n.stormSince = now
		}
		log.Info("STORM-GUARD: ExternalSecret failure storm — "+
			"suppressing force-sync nudges (upstream ESO/1Password outage)",
			"failing", failingES, "total", totalES,
			"stormFor", now.Sub(n.stormSince).Truncate(time.Minute))
	} else {
		metrics.ExternalSecretStormSuppressed.Set(0)
		n.stormSince = time.Time{}
	}

	// externalsecret-storm-guard — connect auto-heal runs on every census, storm or not:
	// a ClusterSecretStore down >=15m is itself a trigger.
	n.maybeHealConnect(ctx, storm, now)

	// empty-key-audit — the empty-key audit runs on every census too: it reads
	// Ready=True ESs only, so a storm (or a total store outage) must
	// not blind it — the early returns below come after it.
	n.auditEmptySecretKeys(ctx, list)

	if storm {
		log.Info("sweep done", "nudged", 0, "storm", true)
		return nil
	}
	if !recovered && !anyReady {
		log.Info("sweep done", "stores", "no-store-signal", "nudged", 0)
		return nil
	}

	nudgedNow := 0
	for i := range list.Items {
		es := &list.Items[i]
		key := es.GetNamespace() + "/" + es.GetName()
		c, _ := kube.ConditionOf(es.Object, "Ready")
		if c.Status != "False" {
			continue
		}
		readyMsg := c.Message
		since := c.LastTransitionTime
		if since.IsZero() {
			since = es.GetCreationTimestamp().Time
		}
		if now.Sub(since) < esStuckAge {
			continue // fresh failure — still inside normal reconcile, don't poke
		}
		// Eligibility: the recovery edge nudges every stuck ES (the
		// fast path); without an edge only ESs whose referenced
		// stores are ALL Ready=True ClusterSecretStores qualify — an
		// ES hanging off a still-broken store gets nothing by design.
		if !recovered && !n.esStoreReady(es) {
			continue
		}
		// Persisted cooldown — survives restarts: a force-sync /
		// last-es-nudge stamp younger than the cooldown means the
		// poke is already in flight.
		if last, ok := esNudgeStamp(es); ok && now.Sub(last) < esNudgeCooldown {
			log.Info("skip: persisted nudge stamp inside cooldown",
				"es", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		// empty-key-audit — clear the empty skeleton BEFORE stamping: ESO can
		// leave a len(Data)==0 target Secret behind after a failed
		// sync, and the forced reconcile recreates it populated.
		n.deleteEmptySkeletonSecret(ctx, es)
		patch, err := kube.MergePatchAnnos(map[string]any{
			esForceSyncAnno: strconv.FormatInt(now.Unix(), 10),
			// Same moment in RFC3339 — the persisted cooldown
			// marker operators can read (and esNudgeStamp accepts).
			esLastNudgeAnno: now.UTC().Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		if _, err := n.dyn.Resource(esGVR).Namespace(es.GetNamespace()).Patch(ctx,
			es.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			// Tolerated per-ES failure: absorbed (log + continue,
			// nil return) so it never reaches the periodic wrapper —
			// IncError here keeps it on the alert path.
			metrics.IncError(n.queue)
			log.Error(err, "force-sync patch failed", "es", key)
			continue // per-ES failures must not starve the rest
		}
		nudgedNow++
		log.Info("ACTION: force-sync ExternalSecret", "es", key,
			"stuckFor", now.Sub(since).Truncate(time.Minute),
			"readyMsg", readyMsg)
	}
	log.Info("sweep done", "nudged", nudgedNow)
	return nil
}

// esNudgeStamp returns the newest persisted nudge marker on the ES —
// force-sync or passiontech.dev/last-es-nudge, whichever parses latest. Both
// keys go through kube.ParseAnnoTime: absent/empty/unparseable values
// count as absent (a garbage stamp cannot prove a recent nudge, and
// stamping over it is exactly how the ES gets unstuck), and each
// accepts RFC3339 OR unix seconds — force-sync is written unix and
// last-es-nudge RFC3339 today, but older objects still carry the
// legacy unix stamp under last-es-nudge.
func esNudgeStamp(es *unstructured.Unstructured) (time.Time, bool) {
	var latest time.Time
	found := false
	if t, ok := kube.ParseAnnoTime(
		es.GetAnnotations()[esForceSyncAnno]); ok {
		latest, found = t, true
	}
	if t, ok := kube.ParseAnnoTime(
		es.GetAnnotations()[esLastNudgeAnno]); ok {
		found = true
		if t.After(latest) {
			latest = t
		}
	}
	return latest, found
}

// ---------------------------------------------------------------------------
// empty-key-audit — empty/whitespace-key audit + empty-skeleton Secret reaper
// ---------------------------------------------------------------------------

// auditEmptySecretKeys flags every empty credential ESO reports as
// synced: an ExternalSecret can sit Ready=True while a key it wrote is
// "" or whitespace-only — a 1Password item saved with an empty field,
// or a remoteRef property typo pulling a blank value. For every
// Ready=True ES (minus the passiontech.dev/allow-empty-secret-key
// opt-out) the target Secret is read once: each spec.data[].secretKey
// missing from the Secret AND each key present but
// bytes.TrimSpace-empty emits
// node_automation_externalsecret_empty_key{namespace,name,key}=1 via
// the emptyKeyEmitted ledger, so a key that later syncs populated gets
// its series deleted instead of pinning stale.
func (n *externalSecretNudge) auditEmptySecretKeys(ctx context.Context,
	list *unstructured.UnstructuredList) {
	n.emptyKeyEmitted.Begin() // drop any aborted sweep's leftover emissions
	if n.cs == nil {
		return // no typed client wired — cannot read target Secrets
	}
	log := logf.FromContext(ctx)
	for i := range list.Items {
		es := &list.Items[i]
		c, _ := kube.ConditionOf(es.Object, "Ready")
		if c.Status != "True" {
			continue // only a "successfully synced" ES can lie about content
		}
		if es.GetAnnotations()[kube.AnnoAllowEmptySecretKey] == "true" {
			continue // operator opted out — empty values are legitimate here
		}
		ns, name := es.GetNamespace(), es.GetName()
		target := esTargetSecretName(es)
		v, status, perr := n.secretVerdict(ctx, es)
		switch status {
		case probeNotFound:
			continue // no Secret yet — nothing to audit, not an error
		case probeError:
			// Unverifiable is not "clean": re-emit this ES's last-sweep
			// keys so a transient read flap doesn't drop a live alert.
			metrics.IncError(n.queue)
			log.Error(perr, "target secret probe failed — keeping last verdict",
				"es", ns+"/"+name, "secret", target)
			for k, lv := range n.emptyKeyEmitted.Last() {
				if k.ns == ns && k.name == name {
					n.emptyKeyEmitted.Emit(k, lv...)
				}
			}
			continue
		}
		for k, why := range v.emptyKeys {
			n.flagEmptyKey(log, es, k, why)
		}
	}
	n.emptyKeyEmitted.Prune(metrics.ExternalSecretEmptyKey.DeleteLabelValues)
}

// readTargetSecret fetches one ES target Secret, memoized per pass on
// n.secretReads — the audit reads every Ready ES's target and the
// skeleton reaper re-reads the same Secret for each stuck ES, so the
// shared cache turns 2N Gets into N. Errors memoize too: a NotFound
// or transient failure replays identically rather than re-hitting
// the apiserver for every ES sharing the target.
func (n *externalSecretNudge) readTargetSecret(ctx context.Context,
	ns, name string) (*corev1.Secret, error) {

	key := ns + "/" + name
	if r, ok := n.secretReads[key]; ok {
		return r.secret, r.err
	}
	secret, err := n.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if n.secretReads == nil {
		n.secretReads = map[string]secretRead{} // direct call — lazy init
	}
	n.secretReads[key] = secretRead{secret, err}
	return secret, err
}

// flagEmptyKey emits one empty-key series through the ledger — Set
// folds the gauge write and the emit bookkeeping into one call.
func (n *externalSecretNudge) flagEmptyKey(log logr.Logger,
	es *unstructured.Unstructured, key, why string) {
	ns, name := es.GetNamespace(), es.GetName()
	n.emptyKeyEmitted.Set(metrics.ExternalSecretEmptyKey, 1,
		esEmptyKey{ns: ns, name: name, key: key}, ns, name, key)
	log.Info("ALERT: ExternalSecret synced an empty secret key — "+
		"Ready=True but the credential is blank",
		"es", ns+"/"+name, "key", key, "why", why)
}

// esTargetSecretName resolves the Secret the ES writes:
// spec.target.name when set, else the ES's own name (the ESO
// default).
func esTargetSecretName(es *unstructured.Unstructured) string {
	if target, ok := kube.NestedString(
		es.Object, "spec", "target", "name"); ok && target != "" {
		return target
	}
	return es.GetName()
}

// esDeclaredKeys returns the target Secret key names spec.data[]
// declares — the keys ESO is expected to have written; a declared key
// absent from the Secret is as poisonous as an empty one.
func esDeclaredKeys(es *unstructured.Unstructured) map[string]bool {
	keys := map[string]bool{}
	entries, _ := kube.NestedSlice(es.Object, "spec", "data")
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if k, ok := kube.NestedString(m, "secretKey"); ok && k != "" {
			keys[k] = true
		}
	}
	return keys
}

// deleteEmptySkeletonSecret removes the zero-byte skeleton ESO leaves
// behind when a sync fails after creating the target Secret: a Secret
// provably owned by THIS ExternalSecret carrying len(Data)==0 never
// gets filled by a reconcile that errors before the write — deleting
// it lets the force-synced reconcile recreate the Secret wholesale.
// Skeleton GC is exempt from the maintenance mutex like every orphan
// cleanup (the mutex defers heal churn, not GC). Failures are
// tolerated: the skeleton survives for the next stamp cycle and the
// force-sync itself is still worth stamping.
func (n *externalSecretNudge) deleteEmptySkeletonSecret(ctx context.Context,
	es *unstructured.Unstructured) {
	if n.cs == nil {
		return
	}
	log := logf.FromContext(ctx)
	ns, name := es.GetNamespace(), es.GetName()
	target := esTargetSecretName(es)
	v, status, perr := n.secretVerdict(ctx, es)
	switch status {
	case probeNotFound:
		return // no skeleton at all — the common path
	case probeError:
		metrics.IncError(n.queue)
		log.Error(perr, "target secret probe failed — skeleton kept (fail closed)",
			"es", ns+"/"+name, "secret", target)
		return
	}
	if !v.skeleton {
		return // carries data or not ESO-owned — not the empty-skeleton shape
	}
	if err := n.cs.CoreV1().Secrets(ns).Delete(ctx, target,
		kube.UIDDeleteOptions(v.skeletonUID, metav1.DeletePropagationBackground)); err != nil {
		metrics.IncError(n.queue)
		log.Error(err, "empty skeleton secret delete failed",
			"es", ns+"/"+name, "secret", target)
		return
	}
	log.Info("DELETE secret: empty skeleton owned by failing ExternalSecret — "+
		"force-sync will recreate it populated",
		"es", ns+"/"+name, "secret", target)
}
