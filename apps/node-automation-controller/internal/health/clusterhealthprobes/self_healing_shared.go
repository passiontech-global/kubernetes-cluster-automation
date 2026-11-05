// self_healing_shared.go — shared state + helpers for the
// self-healing probe checks (the checks formerly grouped under the
// Wave-10 workstream, W10-NM*/CP*/ST*/GI*):
//
//   - probeHealLedger: package-level first-seen streak ledger +
//     emitted-gauge hygiene shared by every check that needs a
//     persistence window (the prober struct's fields live in
//     cluster_health_probes.go).
//   - healCooledDown / markHealStamp / deletePodHeal: the shared
//     pod-delete heal shape — per-target cooldown on the
//     p.meshHealed ledger, maintenance mutex (fail closed),
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

// probeHealLedger is the package-level Wave-10 ledger. The prober struct
// is owned by cluster_health_probes.go, so first-seen streak windows
// and emitted-gauge tuples live here; there is exactly one prober per
// process so package scope is the correct lifetime.
var probeHealLedger = struct {
	sync.Mutex
	// seen: "<check>/<signature>" → first sweep the signature was
	// observed; pruned per-check when the signature resolves so a
	// later stall re-arms the window (same lifecycle as
	// stsZeroSince/scyllaFirstSeen).
	seen map[string]time.Time
	// emitted: check → dedup key → label values, so a gauge tuple
	// that stops being reported gets DeleteLabelValues'd rather than
	// leaking a stale 1 (same hygiene as stsZeroEmitted).
	emitted map[string]map[string][]string
}{
	seen:    map[string]time.Time{},
	emitted: map[string]map[string][]string{},
}

// seenFirstStreak returns the first-seen time for a signature,
// stamping `now` on first observation. ok=false means this is the
// first sighting — callers treat it as "inside the window".
func seenFirstStreak(check, key string, now time.Time) (time.Time, bool) {
	probeHealLedger.Lock()
	defer probeHealLedger.Unlock()
	k := check + "/" + key
	if t, ok := probeHealLedger.seen[k]; ok {
		return t, true
	}
	probeHealLedger.seen[k] = now
	return now, false
}

// pruneSeenStreaks drops first-seen entries under `check` whose
// signature key is absent from keep — resolved signatures re-arm.
func pruneSeenStreaks(check string, keep map[string]bool) {
	probeHealLedger.Lock()
	defer probeHealLedger.Unlock()
	prefix := check + "/"
	for k := range probeHealLedger.seen {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if !keep[strings.TrimPrefix(k, prefix)] {
			delete(probeHealLedger.seen, k)
		}
	}
}

// reconcileEmittedGauges reconciles one check's emitted-gauge ledger:
// tuples in `current` (dedup key → label values) stay; previously
// emitted tuples absent from current are DeleteLabelValues'd. Callers
// Set() their gauge values BEFORE calling this.
func reconcileEmittedGauges(check string, vec *prometheus.GaugeVec,
	current map[string][]string) {
	probeHealLedger.Lock()
	defer probeHealLedger.Unlock()
	em := probeHealLedger.emitted[check]
	if em == nil {
		em = map[string][]string{}
		probeHealLedger.emitted[check] = em
	}
	for k, lv := range em {
		if _, ok := current[k]; !ok {
			vec.DeleteLabelValues(lv...)
			delete(em, k)
		}
	}
	for k, lv := range current {
		if _, ok := em[k]; !ok {
			em[k] = lv
		}
	}
}

// healCooledDown reports whether key was healed inside cooldown — the
// read half of the shared p.meshHealed ledger under selfheal/ keys.
func (p *clusterHealthProber) healCooledDown(key string, cooldown time.Duration, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meshHealed == nil {
		p.meshHealed = map[string]time.Time{}
	}
	last, ok := p.meshHealed[key]
	return ok && now.Sub(last) < cooldown
}

// markHealStamp stamps key on the shared heal ledger.
func (p *clusterHealthProber) markHealStamp(key string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meshHealed == nil {
		p.meshHealed = map[string]time.Time{}
	}
	p.meshHealed[key] = now
}

// deletePodHeal is the Wave-10 pod-delete heal: per-target cooldown
// on the shared ledger, the maintenance mutex (fail closed on
// unverifiable), a UID-preconditioned delete, and the shared
// ControlPlanePodHealsTotal counter under the check name.
func (p *clusterHealthProber) deletePodHeal(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) {

	key := "selfheal/" + checkName + "/" + targetKey
	if p.healCooledDown(key, cooldown, now) {
		log.Info("skip heal: inside cooldown", "check", checkName,
			"target", targetKey)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
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
	if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	p.markHealStamp(key, now)
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
// http-content-check health-probes. p.httpClient is the shared seam
// tests already drive with httptest servers.
func (p *clusterHealthProber) promInstantQuery(ctx context.Context, query string) ([]promSample, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.checkTimeout)
	defer cancel()
	endpoint := healthEnv("HEALTH_PROMETHEUS_QUERY_URL", "")
	if endpoint == "" {
		u, err := url.Parse(p.cfg.httpURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("cannot derive prometheus base from httpURL %q", p.cfg.httpURL)
		}
		endpoint = u.Scheme + "://" + u.Host + "/api/v1/query"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"?query="+url.QueryEscape(query), nil)
	if err != nil {
		return nil, fmt.Errorf("build prometheus query: %w", err)
	}
	resp, err := p.httpClient.Do(req)
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
