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
	"fmt"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
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

	// esListPageSize bounds each List page — the ExternalSecret and
	// store lists are cluster-wide and unbounded.
	esListPageSize = 500
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
	cs  kubernetes.Interface // reserved for future typed reads
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue   string
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
	storeDownSince shared.FirstSeenLedger
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
		cs:         d.CS,
		dyn:        d.Dyn,
		queue:      d.Name,
		enabled:    shared.Gate("EXTERNALSECRET_NUDGE_ENABLED", false),
		storeReady: map[string]bool{},
		nudged:     map[string]time.Time{},
	}
	return shared.AddPeriodic(d.Mgr, n.queue, esNudgeInterval, n.run)
}

func (n *externalSecretNudge) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if !n.enabled {
		log.Info("skip: externalsecret-nudge disabled")
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()

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
			n.storeDownSince.Forget(key)
		} else {
			n.storeDownSince.Observe(key, now)
		}
		if tracked && !prev && isReady {
			recovered = true
			log.Info("SecretStore recovered (Ready False→True) — nudging stuck ExternalSecrets",
				"store", key)
		}
	}
	for i := range stores.Items {
		s := &stores.Items[i]
		c, _ := shared.ConditionOf(s.Object, "Ready")
		track("ClusterSecretStore", "", s.GetName(), c.Status == "True")
	}
	if namespacedStores != nil {
		for i := range namespacedStores.Items {
			s := &namespacedStores.Items[i]
			c, _ := shared.ConditionOf(s.Object, "Ready")
			track("SecretStore", s.GetNamespace(), s.GetName(), c.Status == "True")
		}
	}
	// Drop vanished stores so a delete+recreate re-seeds fresh —
	// storeReady and storeDownSince prune together.
	for name := range n.storeReady {
		if !seen[name] {
			delete(n.storeReady, name)
			n.storeDownSince.Forget(name)
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
