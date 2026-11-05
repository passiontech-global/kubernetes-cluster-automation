// force_sync_nudge.go — the nudge pass of externalsecret-nudge: every
// ExternalSecret Ready=False for longer than esStuckAge gets the
// force-sync + node.ops/last-es-nudge annotations merge-patched on,
// forcing an immediate ESO reconcile that skips the remaining
// backoff. Rate-limited to one stamp per esNudgeCooldown by BOTH the
// in-memory ledger and the persisted stamps esNudgeStamp reads back.
// Also carries the W9-GO1 storm census: a mass-failure storm
// suppresses every stamp and feeds the connect auto-heal.
package externalsecretnudge

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// nudge stamps force-sync on every eligible ExternalSecret Ready=
// False for longer than esStuckAge, at most once per esNudgeCooldown.
// recovered=true is the edge fast-path (any stuck ES qualifies); with
// recovered=false only ESs whose referenced stores are ALL Ready=True
// qualify (state-based path). anyReady reports whether at least one
// store is currently Ready=True — with neither it and no recovery
// edge there is nobody to poke, so the sweep is a no-op census.
//
// W9-GO1 storm guard: when >=esStormMinFailing ExternalSecrets are
// Ready=False AND they are at least half the population, the failure
// is an upstream ESO/1Password outage, not N independent wedged ESs —
// stamping force-sync on all of them would amplify the outage, so the
// pass logs STORM-GUARD, sets the suppression gauge and skips every
// stamp. A storm (or a ClusterSecretStore down) persisting
// esConnectHealMinAge also triggers the onepassword-connect pod
// bounce via maybeHealConnect.
func (n *externalSecretNudge) nudge(ctx context.Context, recovered, anyReady bool) error {
	log := logf.FromContext(ctx)
	list, esGVR, err := n.listES(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ExternalSecretStormSuppressed.Set(0)
			log.Info("skip: external-secrets CRDs not installed")
			return nil
		}
		return fmt.Errorf("list externalsecrets: %w", err)
	}
	now := n.now.Now()

	// W9-GO1 — storm census over the WHOLE population: totalES is
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

	// W9-GO1 — connect auto-heal runs on every census, storm or not:
	// a ClusterSecretStore down >=15m is itself a trigger.
	n.maybeHealConnect(ctx, storm, now)

	if storm {
		log.Info("sweep done", "nudged", 0, "storm", true)
		return nil
	}
	if !recovered && !anyReady {
		log.Info("sweep done", "stores", "no-store-signal", "nudged", 0)
		return nil
	}

	// The nudged ledger needs no prune pass: CooldownSet has no
	// enumeration (stamps past the cooldown read uncooled anyway,
	// and entries for vanished ESs are dead weight that ages out).
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
		// Persisted cooldown — survives restarts where n.nudged
		// cannot: a force-sync / last-es-nudge stamp younger than the
		// cooldown means the poke is already in flight.
		if last, ok := esNudgeStamp(es); ok && now.Sub(last) < esNudgeCooldown {
			log.Info("skip: persisted nudge stamp inside cooldown",
				"es", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		if n.nudged.CooledDown(key, esNudgeCooldown, now) {
			log.Info("skip: already nudged inside cooldown", "es", key)
			continue
		}
		patch, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				esForceSyncAnno: strconv.FormatInt(now.Unix(), 10),
				// Same moment in RFC3339 — the persisted cooldown
				// marker operators can read (and esNudgeStamp accepts).
				esLastNudgeAnno: now.UTC().Format(time.RFC3339),
			}},
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
		n.nudged.Stamp(key, now)
		nudgedNow++
		log.Info("ACTION: force-sync ExternalSecret", "es", key,
			"stuckFor", now.Sub(since).Truncate(time.Minute),
			"readyMsg", readyMsg)
	}
	log.Info("sweep done", "nudged", nudgedNow)
	return nil
}

// esNudgeStamp returns the newest persisted nudge marker on the ES —
// force-sync (unix) or node.ops/last-es-nudge (RFC3339 or unix),
// whichever parses latest. Unparseable values count as absent: a
// garbage stamp cannot prove a recent nudge, and stamping over it is
// exactly how the ES gets unstuck.
func esNudgeStamp(es *unstructured.Unstructured) (time.Time, bool) {
	var latest time.Time
	found := false
	if v := es.GetAnnotations()[esForceSyncAnno]; v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			latest = time.Unix(ts, 0)
			found = true
		}
	}
	if v := es.GetAnnotations()[esLastNudgeAnno]; v != "" {
		var t time.Time
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			t = parsed
		} else if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			t = time.Unix(ts, 0)
		}
		if !t.IsZero() {
			found = true
			if t.After(latest) {
				latest = t
			}
		}
	}
	return latest, found
}
