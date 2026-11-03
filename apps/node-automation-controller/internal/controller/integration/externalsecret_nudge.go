// externalsecret-nudge — workaround for external-secrets/
// external-secrets#4340: when a ClusterSecretStore flaps to
// Ready=False every ExternalSecret depending on it lands in a long
// exponential reconcile backoff, and when the store recovers the ESs
// stay backed-off (up to hours) instead of resyncing immediately.
//
// Detection: poll ClusterSecretStores and remember each one's last
// Ready state in memory — a previously-False store now reporting True
// is a "store recovered" transition (stores never seen before only
// seed the map; no transition on first sight).
//
// Action: for every ExternalSecret still Ready=False for >15m, merge-
// patch the annotation `force-sync=<unix>` — the literal annotation
// key ESO watches; a changed value forces an immediate reconcile that
// skips the remaining backoff. Rate-limited to one nudge per ES per
// hour so a flapping store cannot stampede the API.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
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
)

var (
	clusterSecretStoreGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores"}
	externalSecretGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"}
)

type externalSecretNudge struct {
	cs      kubernetes.Interface
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

// SetupExternalSecretNudge registers the 10-minute sweep. With
// enabled=false the tick only logs and returns nil — keeps the
// signature/queue uniform across clusters with and without ESO.
func SetupExternalSecretNudge(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
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
		ready, _ := readyCond(s)
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
	if !recovered {
		log.Info("sweep done", "stores", len(stores.Items), "storeRecovered", false)
		return nil
	}
	return n.nudge(ctx)
}

// nudge stamps force-sync on every ExternalSecret Ready=False for
// longer than esStuckAge, at most once per esNudgeCooldown.
func (n *externalSecretNudge) nudge(ctx context.Context) error {
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
		status, readyMsg := readyCond(es)
		if status != "False" {
			continue
		}
		since, ok := readySince(es)
		if !ok {
			since = es.GetCreationTimestamp().Time
		}
		if now.Sub(since) < esStuckAge {
			continue // fresh failure — still inside normal reconcile, don't poke
		}
		if last, ok := n.nudged[key]; ok && now.Sub(last) < esNudgeCooldown {
			log.Info("skip: already nudged inside cooldown",
				"es", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		patch, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				esForceSyncAnno: strconv.FormatInt(now.Unix(), 10),
			}},
		})
		if err != nil {
			return err
		}
		if _, err := n.dyn.Resource(externalSecretGVR).Namespace(es.GetNamespace()).Patch(ctx,
			es.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
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

// ---------------------------------------------------------------------------
// Shared unstructured Ready-condition helpers (helmrelease-unlocker too).
// ---------------------------------------------------------------------------

// readyCond returns the Ready condition's status and message for an
// unstructured object ("", "" when absent or malformed).
func readyCond(obj *unstructured.Unstructured) (status, message string) {
	for _, c := range readyConds(obj) {
		if c["type"] != "Ready" {
			continue
		}
		s, _ := c["status"].(string)
		m, _ := c["message"].(string)
		return s, m
	}
	return "", ""
}

// readySince returns the Ready condition's lastTransitionTime —
// how long the object has been in its current Ready state.
func readySince(obj *unstructured.Unstructured) (time.Time, bool) {
	for _, c := range readyConds(obj) {
		if c["type"] != "Ready" {
			continue
		}
		ts, _ := c["lastTransitionTime"].(string)
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}

// readyConds extracts .status.conditions as maps (empty on absence).
func readyConds(obj *unstructured.Unstructured) []map[string]any {
	raw, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
