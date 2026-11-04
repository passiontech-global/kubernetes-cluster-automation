// externalsecret-nudge — workaround for external-secrets/
// external-secrets#4340: when a ClusterSecretStore flaps to
// Ready=False every ExternalSecret depending on it lands in a long
// exponential reconcile backoff, and when the store recovers the ESs
// stay backed-off (up to hours) instead of resyncing immediately.
//
// Detection: poll ClusterSecretStores and remember each one's last
// Ready state in memory — a previously-False store now reporting True
// is a "store recovered" transition (stores never seen before only
// seed the map; no transition on first sight). The False→True edge is
// only the FAST path: a store currently reporting Ready=True also
// arms the state-based path, so an ExternalSecret wedged in backoff
// while its store is healthy is nudged even when the restart wiped
// the edge bookkeeping before it could fire.
//
// Action: for every ExternalSecret still Ready=False for >15m whose
// referenced ClusterSecretStore is Ready=True (or any stuck ES right
// after a recovery edge), merge-patch the annotation
// `force-sync=<unix>` — the literal annotation key ESO watches; a
// changed value forces an immediate reconcile that skips the
// remaining backoff. Rate-limited to one nudge per ES per hour by
// BOTH the in-memory ledger and the persisted stamp itself — an ES
// whose force-sync (or node.ops/last-es-nudge) is younger than an
// hour is already poked, so a flapping store cannot stampede the API
// even across controller restarts.
package externalsecretnudge

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	esNudgeQueue    = "externalsecret-nudge"
	esNudgeInterval = 10 * time.Minute
	esStuckAge      = 15 * time.Minute // Ready=False this long before nudging
	esNudgeCooldown = time.Hour        // max 1 force-sync stamp per ES
	esForceSyncAnno = "force-sync"     // literal key — ESO watches it
	// esLastNudgeAnno is the human-readable half of the persisted
	// cooldown — force-sync is a bare unix stamp ESO consumes,
	// node.ops/last-es-nudge is the same moment for operators.
	esLastNudgeAnno = "node.ops/last-es-nudge"
)

var (
	clusterSecretStoreGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores"}
	externalSecretGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"}
)

type externalSecretNudge struct {
	cs      kubernetes.Interface // reserved for future typed reads
	dyn     dynamic.Interface
	enabled bool // EXTERNALSECRET_NUDGE_ENABLED — clusters without ESO skip
	mu      sync.Mutex
	// storeReady: clustersecretstore name → last observed Ready state.
	// Seeded on first sight; the False→True edge is what fires nudges.
	storeReady map[string]bool
	// nudged: ns/name → last force-sync stamp — the 1/hour rate
	// limit. Pruned inside nudge() once past the cooldown or when
	// the ES vanished.
	nudged map[string]time.Time
}

// Setup registers the 10-minute sweep. With
// enabled=false the tick only logs and returns nil — keeps the
// signature/queue uniform across clusters with and without ESO.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	n := &externalSecretNudge{
		cs:         cs,
		dyn:        dyn,
		enabled:    enabled,
		storeReady: map[string]bool{},
		nudged:     map[string]time.Time{},
	}
	return shared.AddPeriodic(mgr, esNudgeQueue, esNudgeInterval, n.run)
}

func (n *externalSecretNudge) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if !n.enabled {
		log.Info("skip: externalsecret-nudge disabled")
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	stores, err := n.dyn.Resource(clusterSecretStoreGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// ESO CRDs absent on this cluster (flag enabled but the
		// operator is not installed yet — e.g. a component opted in
		// before the ESO rollout finished). Not an operational
		// error — skip quietly instead of spamming "could not find
		// the requested resource" every 10 minutes.
		if apierrors.IsNotFound(err) {
			log.Info("skip: external-secrets CRDs not installed")
			return nil
		}
		return fmt.Errorf("list clustersecretstores: %w", err)
	}

	recovered := false
	seen := map[string]bool{}
	for i := range stores.Items {
		s := &stores.Items[i]
		name := s.GetName()
		seen[name] = true
		ready, _ := shared.ReadyCond(s)
		isReady := ready == "True"
		prev, tracked := n.storeReady[name]
		n.storeReady[name] = isReady
		if tracked && !prev && isReady {
			recovered = true
			log.Info("ClusterSecretStore recovered (Ready False→True) — nudging stuck ExternalSecrets",
				"store", name)
		}
	}
	// Drop vanished stores so a delete+recreate re-seeds fresh.
	for name := range n.storeReady {
		if !seen[name] {
			delete(n.storeReady, name)
		}
	}
	// A store currently Ready=True arms the state-based nudge — the
	// in-RAM False→True edge is only the fast path. Without either,
	// there is nobody to poke (an ES hanging off a broken store
	// must stay in backoff; poking it early is pure churn).
	anyReady := false
	for _, ready := range n.storeReady {
		if ready {
			anyReady = true
			break
		}
	}
	if !recovered && !anyReady {
		log.Info("sweep done", "stores", len(stores.Items), "storeRecovered", false)
		return nil
	}
	return n.nudge(ctx, recovered)
}

// nudge stamps force-sync on every eligible ExternalSecret Ready=
// False for longer than esStuckAge, at most once per esNudgeCooldown.
// recovered=true is the edge fast-path (any stuck ES qualifies); with
// recovered=false only ESs whose referenced ClusterSecretStore is
// currently Ready=True qualify (state-based path).
func (n *externalSecretNudge) nudge(ctx context.Context, recovered bool) error {
	log := logf.FromContext(ctx)
	list, err := n.dyn.Resource(externalSecretGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("skip: external-secrets CRDs not installed")
			return nil
		}
		return fmt.Errorf("list externalsecrets: %w", err)
	}
	now := time.Now()
	// Drop nudged entries past the cooldown or whose ExternalSecret
	// vanished — the map only ever shrinks here (nudged is written
	// solely in this function), same prune pattern as storeReady.
	live := map[string]bool{}
	for i := range list.Items {
		es := &list.Items[i]
		live[es.GetNamespace()+"/"+es.GetName()] = true
	}
	for key, last := range n.nudged {
		if !live[key] || now.Sub(last) >= esNudgeCooldown {
			delete(n.nudged, key)
		}
	}
	nudgedNow := 0
	for i := range list.Items {
		es := &list.Items[i]
		key := es.GetNamespace() + "/" + es.GetName()
		status, readyMsg := shared.ReadyCond(es)
		if status != "False" {
			continue
		}
		since, ok := shared.ReadySince(es)
		if !ok {
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
		if last, ok := n.nudged[key]; ok && now.Sub(last) < esNudgeCooldown {
			log.Info("skip: already nudged inside cooldown",
				"es", key, "ago", now.Sub(last).Truncate(time.Minute))
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
		if _, err := n.dyn.Resource(externalSecretGVR).Namespace(es.GetNamespace()).Patch(ctx,
			es.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			// Tolerated per-ES failure: absorbed (log + continue,
			// nil return) so it never reaches the periodic wrapper —
			// IncError here keeps it on the alert path.
			metrics.IncError(esNudgeQueue)
			log.Error(err, "force-sync patch failed", "es", key)
			continue // per-ES failures must not starve the rest
		}
		n.nudged[key] = now
		nudgedNow++
		log.Info("ACTION: force-sync ExternalSecret", "es", key,
			"stuckFor", now.Sub(since).Truncate(time.Minute),
			"readyMsg", readyMsg)
	}
	log.Info("sweep done", "nudged", nudgedNow)
	return nil
}

// esStoreReady reports whether every SecretStore the ES can pull from
// is a ClusterSecretStore currently reporting Ready=True. ESO defaults
// an unset kind to SecretStore (namespaced) — only an explicit
// kind=ClusterSecretStore qualifies, and ALL referenced stores must
// qualify: a namespaced SecretStore ref, an absent ref set, or a
// store we have never seen is "can't tell" → false.
func (n *externalSecretNudge) esStoreReady(es *unstructured.Unstructured) bool {
	any, ready := false, true
	esStoreRefs(es, func(name, kind string) {
		r, tracked := n.storeReady[name]
		if kind != "ClusterSecretStore" || !tracked || !r {
			ready = false
			return
		}
		any = true
	})
	return any && ready
}

// esStoreRefs walks every store reference the ExternalSecret carries —
// spec.secretStoreRef (the default store) plus each
// spec.dataFrom[].sourceRef.storeRef AND spec.data[].sourceRef.storeRef
// per-entry override — invoking fn(name, kind) for each ref that names
// a store. Refs without a name are genuinely absent; generator refs
// (sourceRef.generatorRef) are not stores and never reach fn.
func esStoreRefs(es *unstructured.Unstructured, fn func(name, kind string)) {
	if name, _, _ := unstructured.NestedString(
		es.Object, "spec", "secretStoreRef", "name"); name != "" {
		kind, _, _ := unstructured.NestedString(
			es.Object, "spec", "secretStoreRef", "kind")
		fn(name, kind)
	}
	// dataFrom[].sourceRef.storeRef and data[].sourceRef.storeRef are
	// the same per-entry override shape under two parent lists.
	for _, field := range []string{"dataFrom", "data"} {
		entries, _, _ := unstructured.NestedSlice(es.Object, "spec", field)
		for _, e := range entries {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if name, _, _ := unstructured.NestedString(
				m, "sourceRef", "storeRef", "name"); name != "" {
				kind, _, _ := unstructured.NestedString(
					m, "sourceRef", "storeRef", "kind")
				fn(name, kind)
			}
		}
	}
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
