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
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
	// W9-GO1 — storm guard + 1Password Connect auto-heal thresholds.
	// A storm is >=5 failing ExternalSecrets making up >=half the
	// population; either a ClusterSecretStore down or a storm must
	// persist esConnectHealMinAge before the connect pod is bounced,
	// and the bounce itself is capped at one per esConnectHealCooldown.
	esStormMinFailing     = 5
	esConnectHealMinAge   = 15 * time.Minute
	esConnectHealCooldown = time.Hour
)

// esConnectNamespaces are where the 1Password Connect pod can live —
// the ESO namespace on these clusters, or a dedicated connect ns.
// esConnectPodPrefix matches the helm-release pod names
// (onepassword-connect-<replica-hash>).
var (
	esConnectNamespaces = []string{"external-secrets", "onepassword"}
	esConnectPodPrefix  = "onepassword-connect"
)

// The external-secrets API exists at v1 AND v1beta1 — both GVRs are
// listed so either serving version works (each List is tolerant of a
// not-installed GVR). SecretStore joins ClusterSecretStore: ESO
// defaults spec.secretStoreRef.kind to the namespaced SecretStore,
// which is the common shape on these clusters.
var (
	clusterSecretStoreGVRs = shared.ClusterSecretStoreGVRs
	secretStoreGVRs        = shared.SecretStoreGVRs
	externalSecretGVRs     = shared.ExternalSecretGVRs
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
	// storeDownSince: store key → first sweep that observed
	// Ready=False — the persistence clock for the connect auto-heal
	// (a transient first False must not bounce the pod).
	storeDownSince map[string]time.Time
	// stormSince: first sweep of the current ExternalSecret failure
	// storm — same persistence clock, storm-triggered heal path.
	stormSince time.Time
	// connectHealAt: last delivered connect-pod bounce — the 1/hour
	// cooldown. In-memory only, like nudged: a restart re-arms it,
	// which is safe because the heal still needs 15m of fresh
	// down/storm observations first.
	connectHealAt time.Time
}

// Setup registers the 10-minute sweep. With the module gate off
// (EXTERNALSECRET_NUDGE_ENABLED != "true") the tick only logs and
// returns nil — keeps the signature/queue uniform across clusters
// with and without ESO.
func Setup(d shared.Deps) error {
	n := &externalSecretNudge{
		cs:             d.CS,
		dyn:            d.Dyn,
		enabled:        shared.Gate("EXTERNALSECRET_NUDGE_ENABLED", false),
		storeReady:     map[string]bool{},
		nudged:         map[string]time.Time{},
		storeDownSince: map[string]time.Time{},
	}
	return shared.AddPeriodic(d.Mgr, esNudgeQueue, esNudgeInterval, n.run)
}

func (n *externalSecretNudge) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if !n.enabled {
		log.Info("skip: externalsecret-nudge disabled")
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.storeDownSince == nil {
		n.storeDownSince = map[string]time.Time{} // literal-constructed fixtures
	}

	stores, err := n.listFirst(ctx, clusterSecretStoreGVRs)
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
	namespacedStores, err := n.listFirst(ctx, secretStoreGVRs)
	if err != nil {
		if apierrors.IsNotFound(err) {
			namespacedStores = nil // SecretStore absent — cluster-only install
		} else {
			return fmt.Errorf("list secretstores: %w", err)
		}
	}

	recovered := false
	seen := map[string]bool{}
	now := time.Now()
	track := func(kind, ns, name string, isReady bool) {
		key := kind + "/" + ns + "/" + name
		seen[key] = true
		prev, tracked := n.storeReady[key]
		n.storeReady[key] = isReady
		// W9-GO1 — the down-since clock for the connect auto-heal:
		// first observed False starts it, True or vanish clears it.
		if isReady {
			delete(n.storeDownSince, key)
		} else if _, down := n.storeDownSince[key]; !down {
			n.storeDownSince[key] = now
		}
		if tracked && !prev && isReady {
			recovered = true
			log.Info("SecretStore recovered (Ready False→True) — nudging stuck ExternalSecrets",
				"store", key)
		}
	}
	for i := range stores.Items {
		s := &stores.Items[i]
		ready, _ := shared.ReadyCond(s)
		track("ClusterSecretStore", "", s.GetName(), ready == "True")
	}
	if namespacedStores != nil {
		for i := range namespacedStores.Items {
			s := &namespacedStores.Items[i]
			ready, _ := shared.ReadyCond(s)
			track("SecretStore", s.GetNamespace(), s.GetName(), ready == "True")
		}
	}
	// Drop vanished stores so a delete+recreate re-seeds fresh —
	// storeReady and storeDownSince prune together.
	for name := range n.storeReady {
		if !seen[name] {
			delete(n.storeReady, name)
			delete(n.storeDownSince, name)
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
	// W9-GO1 — always census the ExternalSecrets: the storm guard
	// and the connect auto-heal must see a mass-failure storm even
	// when NO store is healthy and no recovery edge fired — a full
	// ESO/1Password outage is exactly that case, and skipping the
	// list here would blind both features to it.
	return n.nudge(ctx, recovered, anyReady)
}

// listFirst lists the first working GVR of a candidate set — the ESO
// API serves v1 on current installs and v1beta1 on older ones; a
// not-installed candidate is skipped, the first listable wins.
func (n *externalSecretNudge) listFirst(ctx context.Context,
	gvrs []schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
	var lastErr error
	for _, gvr := range gvrs {
		list, err := n.dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err == nil {
			return list, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// gvrForPatch returns the GVR the ES list answered on — patches must
// land on the same served version.
func (n *externalSecretNudge) listES(ctx context.Context) (*unstructured.UnstructuredList, schema.GroupVersionResource, error) {
	var lastErr error
	for _, gvr := range externalSecretGVRs {
		list, err := n.dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err == nil {
			return list, gvr, nil
		}
		lastErr = err
	}
	return nil, schema.GroupVersionResource{}, lastErr
}

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
	now := time.Now()

	// W9-GO1 — storm census over the WHOLE population: totalES is
	// every ExternalSecret, failingES every Ready=False one. The
	// ratio clause keeps a big healthy fleet from tripping on a
	// handful of unrelated failures.
	totalES, failingES := 0, 0
	for i := range list.Items {
		totalES++
		if status, _ := shared.ReadyCond(&list.Items[i]); status == "False" {
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
		if _, err := n.dyn.Resource(esGVR).Namespace(es.GetNamespace()).Patch(ctx,
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

// esStoreReady reports whether every store the ES can pull from is
// tracked AND currently Ready=True — ClusterSecretStore by name, or a
// namespaced SecretStore in the ES's own namespace (ESO defaults an
// unset kind to SecretStore). ALL referenced stores must qualify: an
// absent ref set or a store we have never seen is "can't tell" →
// false.
func (n *externalSecretNudge) esStoreReady(es *unstructured.Unstructured) bool {
	any, ready := false, true
	esStoreRefs(es, func(name, kind string) {
		key := ""
		switch kind {
		case "ClusterSecretStore":
			key = "ClusterSecretStore//" + name
		case "", "SecretStore":
			key = "SecretStore/" + es.GetNamespace() + "/" + name
		default:
			ready = false
			return
		}
		r, tracked := n.storeReady[key]
		if !tracked || !r {
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
	if name, ok := shared.NestedString(
		es.Object, "spec", "secretStoreRef", "name"); ok && name != "" {
		kind, _ := shared.NestedString(
			es.Object, "spec", "secretStoreRef", "kind")
		fn(name, kind)
	}
	// dataFrom[].sourceRef.storeRef and data[].sourceRef.storeRef are
	// the same per-entry override shape under two parent lists.
	for _, field := range []string{"dataFrom", "data"} {
		entries, _ := shared.NestedSlice(es.Object, "spec", field)
		for _, e := range entries {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := shared.NestedString(
				m, "sourceRef", "storeRef", "name"); ok && name != "" {
				kind, _ := shared.NestedString(
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

// ---------------------------------------------------------------------------
// W9-GO1 — 1Password Connect auto-heal
// ---------------------------------------------------------------------------

// maybeHealConnect bounces the oldest running onepassword-connect pod
// when the ESO data path has been broken long enough that a stuck
// connect pod is the likely culprit: either a ClusterSecretStore has
// reported Ready=False for >=esConnectHealMinAge, or the ExternalSecret
// storm has persisted that long. The delete is maintenance-gated,
// UID-preconditioned, and capped at one bounce per
// esConnectHealCooldown — and it NEVER fires on a transient first
// observation, because both clocks only start after the first sweep
// that sees the bad state.
func (n *externalSecretNudge) maybeHealConnect(ctx context.Context,
	storm bool, now time.Time) {
	log := logf.FromContext(ctx)

	// Trigger 1 — a ClusterSecretStore (cluster-scoped only; a
	// namespaced SecretStore outage does not bounce the shared
	// connect pod) down past the persistence window.
	storeDown := false
	for key, since := range n.storeDownSince {
		if strings.HasPrefix(key, "ClusterSecretStore/") &&
			now.Sub(since) >= esConnectHealMinAge {
			storeDown = true
			break
		}
	}
	// Trigger 2 — the ES storm itself persisting past the window.
	stormLong := storm && now.Sub(n.stormSince) >= esConnectHealMinAge
	if !storeDown && !stormLong {
		return
	}
	if now.Sub(n.connectHealAt) < esConnectHealCooldown {
		log.Info("DEFER: connect pod heal inside cooldown",
			"storeDown", storeDown, "stormLong", stormLong,
			"lastHeal", now.Sub(n.connectHealAt).Truncate(time.Minute))
		return
	}

	// Same fail-closed maintenance gate as every pod kill in this
	// module — cordon/drain/kured or an in-flight upgrade defers the
	// bounce, and "cannot verify" skips it.
	held, why, err := shared.MaintenanceActive(ctx, n.cs, n.dyn)
	if err != nil {
		metrics.IncError(esNudgeQueue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: connect pod heal skipped (fail closed)", "error", err)
		return
	}
	if held {
		log.Info("DEFER: maintenance active — connect pod heal skipped",
			"why", why)
		return
	}

	pod := n.oldestConnectPod(ctx)
	if pod == nil {
		log.Info("connect heal: no running onepassword-connect pod found")
		return
	}
	log.Info("ACTION: deleting oldest running onepassword-connect pod — "+
		"sustained store outage/storm", "pod", pod.Namespace+"/"+pod.Name,
		"storeDown", storeDown, "stormLong", stormLong)
	uid := pod.UID
	if err := n.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
		metrics.IncError(esNudgeQueue)
		log.Error(err, "connect pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	// Cooldown stamps on a DELIVERED delete only — a failed delete
	// leaves the pod stuck and the next sweep retries.
	n.connectHealAt = now
}

// oldestConnectPod returns the oldest Running pod named
// onepassword-connect* across the candidate namespaces, or nil when
// none qualifies. List errors other than NotFound are logged and
// skipped — an unverifiable namespace must not block the heal on the
// other one, but it also cannot produce a delete target.
func (n *externalSecretNudge) oldestConnectPod(ctx context.Context) *corev1.Pod {
	log := logf.FromContext(ctx)
	var oldest *corev1.Pod
	for _, ns := range esConnectNamespaces {
		pods, err := n.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				metrics.IncError(esNudgeQueue)
				log.Error(err, "connect pod list failed", "namespace", ns)
			}
			continue
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.DeletionTimestamp != nil ||
				p.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(p.Name, esConnectPodPrefix) {
				continue
			}
			if oldest == nil ||
				p.CreationTimestamp.Time.Before(oldest.CreationTimestamp.Time) {
				oldest = p
			}
		}
	}
	return oldest
}
