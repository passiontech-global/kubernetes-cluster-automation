// self_healing_shared.go — shared state + helpers for the
// self-healing probe checks (the checks formerly grouped under the
// Wave-10 workstream, W10-NM*/CP*/ST*/GI*):
//
//   - healLedger on deps: first-seen streak ledger + emitted-gauge
//     hygiene shared by every check that needs a persistence window
//     (there is exactly one prober per process, so deps has the same
//     lifetime the package-level probeHealLedger had).
//   - healCooledDown / markHealStamp / deletePodHeal: the shared
//     pod-delete heal shape — per-target cooldown on the deps
//     meshHealed ledger, maintenance mutex (fail closed),
//     UID-preconditioned delete.
//   - podUnreadySince / podFromList: pod readiness helpers.
//   - promSample / promLabelValue / promInstantQuery: the Prometheus
//     instant-query seam every metrics-backed check shares.
package clusterhealthprobes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// healLedger is the first-seen streak + emitted-gauge ledger shared
// by every check that needs a persistence window. It lives on deps —
// the prober struct is the thin runner in cluster_health_probes.go,
// so the ledger moved off package scope onto the shared context.
type healLedger struct {
	sync.Mutex
	// seen: "<check>/<signature>" → first sweep the signature was
	// observed; pruned per-check when the signature resolves so a
	// later stall re-arms the window (same lifecycle as
	// stsZeroSince/scyllaFirstSeen).
	seen map[string]time.Time
	// emitted: check → emitted-gauge ledger, so a gauge tuple
	// that stops being reported gets DeleteLabelValues'd rather than
	// leaking a stale 1 (same hygiene as stsZeroEmitted).
	emitted map[string]*shared.GaugeLedger[string]
}

// seenFirstStreak returns the first-seen time for a signature,
// stamping `now` on first observation. ok=false means this is the
// first sighting — callers treat it as "inside the window".
func (d *deps) seenFirstStreak(check, key string, now time.Time) (time.Time, bool) {
	d.ledger.Lock()
	defer d.ledger.Unlock()
	k := check + "/" + key
	if t, ok := d.ledger.seen[k]; ok {
		return t, true
	}
	d.ledger.seen[k] = now
	return now, false
}

// pruneSeenStreaks drops first-seen entries under `check` whose
// signature key is absent from keep — resolved signatures re-arm.
func (d *deps) pruneSeenStreaks(check string, keep map[string]bool) {
	d.ledger.Lock()
	defer d.ledger.Unlock()
	prefix := check + "/"
	for k := range d.ledger.seen {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if !keep[strings.TrimPrefix(k, prefix)] {
			delete(d.ledger.seen, k)
		}
	}
}

// reconcileEmittedGauges reconciles one check's emitted-gauge ledger:
// tuples in `current` (dedup key → label values) stay; previously
// emitted tuples absent from current are DeleteLabelValues'd. Callers
// Set() their gauge values BEFORE calling this.
func (d *deps) reconcileEmittedGauges(check string, vec *prometheus.GaugeVec,
	current map[string][]string) {
	d.ledger.Lock()
	defer d.ledger.Unlock()
	g := d.ledger.emitted[check]
	if g == nil {
		g = &shared.GaugeLedger[string]{}
		d.ledger.emitted[check] = g
	}
	for k, lv := range current {
		g.Emit(k, lv...)
	}
	g.Prune(vec.DeleteLabelValues)
}

// healCooledDown reports whether key was healed inside cooldown — the
// read half of the shared deps meshHealed ledger under selfheal/ keys.
func (d *deps) healCooledDown(key string, cooldown time.Duration, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.meshHealed == nil {
		d.meshHealed = map[string]time.Time{}
	}
	last, ok := d.meshHealed[key]
	return ok && now.Sub(last) < cooldown
}

// markHealStamp stamps key on the shared heal ledger.
func (d *deps) markHealStamp(key string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.meshHealed == nil {
		d.meshHealed = map[string]time.Time{}
	}
	d.meshHealed[key] = now
}

// deletePodHeal is the Wave-10 pod-delete heal: per-target cooldown
// on the shared ledger, the maintenance mutex (fail closed on
// unverifiable), a UID-preconditioned delete, and the shared
// ControlPlanePodHealsTotal counter under the check name.
func (d *deps) deletePodHeal(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) {

	key := "selfheal/" + checkName + "/" + targetKey
	if d.healCooledDown(key, cooldown, now) {
		log.Info("skip heal: inside cooldown", "check", checkName,
			"target", targetKey)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, d.cs, d.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"check", checkName, "target", targetKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"check", checkName, "target", targetKey, "why", why)
		return
	}
	uid := pod.UID
	if err := d.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	d.markHealStamp(key, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
	log.Info("DELETE: pod heal — forcing pod restart",
		"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
}

// podUnreadySince returns when the pod's Ready condition last went
// non-True — the persistence clock for "stuck unready" heals. Absent
// Ready condition falls back to pod creation (a pod that never
// reported Ready is unready since birth).
func podUnreadySince(pod *corev1.Pod) (time.Time, bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		if c.Status == corev1.ConditionTrue {
			return time.Time{}, false
		}
		if !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time, true
		}
		return pod.CreationTimestamp.Time, true
	}
	return pod.CreationTimestamp.Time, true
}

// promSample is one instant-vector sample: metric labels plus
// the scalar value.
type promSample struct {
	metric map[string]string
	value  float64
}

// promLabelValue returns the first non-empty value among keys.
func promLabelValue(s promSample, keys ...string) string {
	for _, k := range keys {
		if v := s.metric[k]; v != "" {
			return v
		}
	}
	return ""
}

// promInstantQuery runs an instant PromQL query against the cluster
// Prometheus and returns the vector series. The endpoint resolves
// from HEALTH_PROMETHEUS_QUERY_URL (full /api/v1/query URL) or is
// derived from cfg.httpURL's scheme://host — the same Prometheus the
// http-content-check health-probes. d.httpClient is the shared seam
// tests already drive with httptest servers.
func (d *deps) promInstantQuery(ctx context.Context, query string) ([]promSample, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.checkTimeout)
	defer cancel()
	endpoint := shared.Getenv("HEALTH_PROMETHEUS_QUERY_URL", "")
	if endpoint == "" {
		u, err := url.Parse(d.cfg.httpURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("cannot derive prometheus base from httpURL %q", d.cfg.httpURL)
		}
		endpoint = u.Scheme + "://" + u.Host + "/api/v1/query"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"?query="+url.QueryEscape(query), nil)
	if err != nil {
		return nil, fmt.Errorf("build prometheus query: %w", err)
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read prometheus response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query status %d: %.200s",
			resp.StatusCode, string(body))
	}
	var parsed struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}
	if parsed.Status != "success" {
		return nil, fmt.Errorf("prometheus query failed: status=%s error=%s",
			parsed.Status, parsed.Error)
	}
	var out []promSample
	for _, r := range parsed.Data.Result {
		if len(r.Value) < 2 {
			continue
		}
		var raw string
		if err := json.Unmarshal(r.Value[1], &raw); err != nil {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		out = append(out, promSample{metric: r.Metric, value: v})
	}
	return out, nil
}
