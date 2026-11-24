// detect.go — dual-backend observability auto-detection for
// Prometheus (kube-prometheus-stack) and VictoriaMetrics
// (victoria-metrics-k8s-stack: vmauth / vmsingle).
//
// TargetDetector probes candidate health endpoints with a bounded 2s
// timeout and caches positive detections for 2 minutes, keyed by
// (ObsBackendMode, *http.Client) so distinct test clients never share
// or pollute global state. DetectBackend inspects URL hints first and
// falls back to separate count(vm_app_version) and
// count(prometheus_build_info) instant queries (never `or`, which strips
// __name__ labels).
package promq

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// BackendKind identifies the metrics backend answering PromQL queries.
type BackendKind int

const (
	BackendUnknown BackendKind = iota
	BackendPrometheus
	BackendVictoriaMetrics
)

// String returns the canonical lowercase backend name.
func (k BackendKind) String() string {
	switch k {
	case BackendPrometheus:
		return "prometheus"
	case BackendVictoriaMetrics:
		return "victoriametrics"
	default:
		return "unknown"
	}
}

// ObsBackendMode controls backend selection via NODE_AUTOMATION_OBS_BACKEND.
type ObsBackendMode string

const (
	ObsBackendAuto            ObsBackendMode = "auto"
	ObsBackendPrometheus      ObsBackendMode = "prometheus"
	ObsBackendVictoriaMetrics ObsBackendMode = "victoriametrics"
)

// ObsBackendEnvKey is the env var controlling backend auto-detection.
const ObsBackendEnvKey = "NODE_AUTOMATION_OBS_BACKEND"

// ParseObsBackendMode parses NODE_AUTOMATION_OBS_BACKEND. Empty string
// maps to ObsBackendAuto with ok=true; unrecognised values fall back to
// ObsBackendAuto with ok=false.
func ParseObsBackendMode(raw string) (ObsBackendMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(ObsBackendAuto):
		return ObsBackendAuto, true
	case string(ObsBackendPrometheus):
		return ObsBackendPrometheus, true
	case string(ObsBackendVictoriaMetrics):
		return ObsBackendVictoriaMetrics, true
	default:
		return ObsBackendAuto, false
	}
}

// EnvObsBackendMode resolves NODE_AUTOMATION_OBS_BACKEND once through
// envx, warning via envx.Warnf and falling back to ObsBackendAuto on
// invalid values.
func EnvObsBackendMode() ObsBackendMode {
	raw := envx.Getenv(ObsBackendEnvKey, string(ObsBackendAuto))
	mode, ok := ParseObsBackendMode(raw)
	if !ok {
		envx.Warnf("invalid NODE_AUTOMATION_OBS_BACKEND ignored — using default",
			"env", ObsBackendEnvKey, "value", raw, "default", string(ObsBackendAuto))
	}
	return mode
}

// ObsTarget describes a concrete observability service endpoint and its
// Kubernetes metadata for health checks, DNS checks, and Events.
type ObsTarget struct {
	Backend       BackendKind
	HealthURL     string
	ExpectedBody  string
	QueryURL      string
	DNSHost       string
	Namespace     string
	DefaultCRName string
}

// DefaultPrometheusTarget returns the primary Prometheus target
// (kube-prometheus-stack).
func DefaultPrometheusTarget() ObsTarget {
	return ObsTarget{
		Backend:       BackendPrometheus,
		HealthURL:     "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy",
		ExpectedBody:  "Healthy",
		QueryURL:      "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/api/v1/query",
		DNSHost:       "kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local",
		Namespace:     "prometheus-operator",
		DefaultCRName: "kube-prometheus-stack-prometheus",
	}
}

// DefaultVMAuthTarget returns the primary VictoriaMetrics target
// (vmauth unified query/alerts router).
func DefaultVMAuthTarget() ObsTarget {
	return ObsTarget{
		Backend:       BackendVictoriaMetrics,
		HealthURL:     "http://vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427/health",
		ExpectedBody:  "OK",
		QueryURL:      "http://vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427/api/v1/query",
		DNSHost:       "vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local",
		Namespace:     "victoria-metrics",
		DefaultCRName: "victoria-metrics-k8s-stack",
	}
}

// DefaultVMSingleTarget returns the fallback VictoriaMetrics single-node
// target (e.g. cicd when vmauth is unavailable).
func DefaultVMSingleTarget() ObsTarget {
	return ObsTarget{
		Backend:       BackendVictoriaMetrics,
		HealthURL:     "http://vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc:8428/health",
		ExpectedBody:  "OK",
		QueryURL:      "http://vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc:8428/api/v1/query",
		DNSHost:       "vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local",
		Namespace:     "victoria-metrics",
		DefaultCRName: "victoria-metrics-k8s-stack",
	}
}

// DefaultTargetForMode returns the primary fallback target for mode
// when live probing is skipped or all probes fail.
func DefaultTargetForMode(mode ObsBackendMode) ObsTarget {
	if mode == ObsBackendVictoriaMetrics {
		return DefaultVMAuthTarget()
	}
	return DefaultPrometheusTarget()
}

// DetectBackend determines whether endpoint serves Prometheus or
// VictoriaMetrics. URL host/path hints are checked first; when the URL
// is generic (e.g. an httptest server or custom proxy), separate
// instant queries for count(vm_app_version) and
// count(prometheus_build_info) are issued (never combined with `or`,
// which strips __name__ labels).
func DetectBackend(ctx context.Context, client *Client, endpoint string) (BackendKind, error) {
	if endpoint == "" {
		return BackendUnknown, errors.New("detect backend: empty endpoint")
	}
	if kind := detectBackendFromURL(endpoint); kind != BackendUnknown {
		return kind, nil
	}
	if client == nil {
		client = &Client{}
	}
	vmSamples, vmErr := client.InstantQuery(ctx, endpoint, "count(vm_app_version)")
	promSamples, promErr := client.InstantQuery(ctx, endpoint, "count(prometheus_build_info)")

	hasVM := vmErr == nil && len(vmSamples) > 0 && vmSamples[0].Value > 0
	hasProm := promErr == nil && len(promSamples) > 0 && promSamples[0].Value > 0

	switch {
	case hasVM && !hasProm:
		return BackendVictoriaMetrics, nil
	case hasProm && !hasVM:
		return BackendPrometheus, nil
	case hasVM && hasProm:
		// vm_app_version is native to VictoriaMetrics; during shadow-run
		// vmagent scrapes kube-prometheus-stack so VM may also carry
		// prometheus_build_info. Prefer VictoriaMetrics when both match
		// on a generic untyped URL.
		return BackendVictoriaMetrics, nil
	case vmErr != nil && promErr != nil:
		return BackendUnknown, errors.Join(vmErr, promErr)
	case vmErr != nil:
		return BackendUnknown, vmErr
	case promErr != nil:
		return BackendUnknown, promErr
	default:
		return BackendUnknown, nil
	}
}

func detectBackendFromURL(endpoint string) BackendKind {
	target := strings.ToLower(endpoint)
	if u, err := url.Parse(endpoint); err == nil && (u.Host != "" || u.Path != "") {
		target = strings.ToLower(u.Host + u.Path)
	}
	for _, hint := range []string{"vmauth", "vmsingle", "vmselect", "victoria-metrics"} {
		if strings.Contains(target, hint) {
			return BackendVictoriaMetrics
		}
	}
	for _, hint := range []string{"prometheus-operator", "kube-prometheus-stack"} {
		if strings.Contains(target, hint) {
			return BackendPrometheus
		}
	}
	return BackendUnknown
}

const (
	defaultProbeTimeout = 2 * time.Second
	defaultDetectTTL    = 2 * time.Minute
	maxProbeBodyBytes   = 64 << 10
)

type cacheKey struct {
	mode   ObsBackendMode
	client *http.Client
}

type cachedTarget struct {
	target    ObsTarget
	expiresAt time.Time
}

// TargetDetector probes candidate observability health endpoints with a
// bounded per-probe timeout and caches positive detections for TTL.
// Distinct *http.Client pointers maintain independent cache entries so
// custom test clients never pollute each other or production defaults.
type TargetDetector struct {
	Targets      []ObsTarget
	ProbeTimeout time.Duration
	TTL          time.Duration // 0 defaults to 2m; <0 disables caching
	Now          func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cachedTarget
}

var defaultTargetDetector = &TargetDetector{}

// AutoDetectTarget probes observability endpoints in priority order
// using the package-level 2m TTL detector.
func AutoDetectTarget(ctx context.Context, httpClient *http.Client, mode ObsBackendMode) (ObsTarget, bool) {
	return defaultTargetDetector.Detect(ctx, httpClient, mode)
}

// InvalidateAutoDetectCache clears cached detections on the package-level
// detector so the next AutoDetectTarget call probes live endpoints.
func InvalidateAutoDetectCache() {
	defaultTargetDetector.Invalidate()
}

// Invalidate clears all cached target detections on d.
func (d *TargetDetector) Invalidate() {
	d.mu.Lock()
	clear(d.cache)
	d.mu.Unlock()
}

// Detect returns the highest-priority healthy target allowed by mode.
// When all candidate probes fail, it returns DefaultTargetForMode(mode)
// and detected=false without caching the negative result.
func (d *TargetDetector) Detect(ctx context.Context, httpClient *http.Client, mode ObsBackendMode) (ObsTarget, bool) {
	normalizedMode, ok := ParseObsBackendMode(string(mode))
	if !ok {
		normalizedMode = ObsBackendAuto
	}
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}
	ttl := d.TTL
	if ttl == 0 {
		ttl = defaultDetectTTL
	}
	nowFn := d.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	key := cacheKey{mode: normalizedMode, client: httpClient}
	if ttl > 0 {
		now := nowFn()
		d.mu.Lock()
		entry, found := d.cache[key]
		d.mu.Unlock()
		if found && now.Before(entry.expiresAt) {
			return entry.target, true
		}
	}

	candidates := d.candidatesForMode(normalizedMode)
	timeout := d.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		if probeHealthTarget(ctx, httpClient, candidate, timeout) {
			if ttl > 0 {
				d.mu.Lock()
				if d.cache == nil {
					d.cache = map[cacheKey]cachedTarget{}
				}
				d.cache[key] = cachedTarget{
					target:    candidate,
					expiresAt: nowFn().Add(ttl),
				}
				d.mu.Unlock()
			}
			return candidate, true
		}
	}

	return d.fallbackForMode(normalizedMode), false
}

func (d *TargetDetector) allTargets() []ObsTarget {
	if len(d.Targets) > 0 {
		return d.Targets
	}
	return []ObsTarget{
		DefaultPrometheusTarget(),
		DefaultVMAuthTarget(),
		DefaultVMSingleTarget(),
	}
}

func (d *TargetDetector) candidatesForMode(mode ObsBackendMode) []ObsTarget {
	all := d.allTargets()
	if mode == ObsBackendAuto {
		return all
	}
	wantBackend := BackendPrometheus
	if mode == ObsBackendVictoriaMetrics {
		wantBackend = BackendVictoriaMetrics
	}
	var out []ObsTarget
	for _, t := range all {
		if t.Backend == wantBackend {
			out = append(out, t)
		}
	}
	return out
}

func (d *TargetDetector) fallbackForMode(mode ObsBackendMode) ObsTarget {
	candidates := d.candidatesForMode(mode)
	if len(candidates) > 0 {
		return candidates[0]
	}
	return DefaultTargetForMode(mode)
}

func probeHealthTarget(ctx context.Context, httpClient *http.Client, target ObsTarget, timeout time.Duration) bool {
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(pctx, http.MethodGet, target.HealthURL, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainOnClose))
	_ = resp.Body.Close()

	if readErr != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	if target.ExpectedBody != "" && !strings.Contains(string(body), target.ExpectedBody) {
		return false
	}
	return true
}
