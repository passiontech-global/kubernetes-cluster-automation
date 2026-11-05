// cluster_health_wave10.go — the Wave-10 checks riding the same
// 5-minute probe plumbing as cluster_health_wave8.go:
//
//   - cilium-bpf-map-pressure (W10-NM1): Prometheus
//     max by (node, map_name) (cilium_bpf_map_pressure) > 0.85 —
//     a BPF map approaching max_entries blackholes the traffic
//     class it serves (conntrack full = all new flows dropped).
//   - linkerd-protocol-detection-stall (W10-NM3): a meshed pod
//     (linkerd-proxy sidecar present) exposing a well-known
//     binary/stateful port not covered by
//     config.linkerd.io/opaque-ports or skip-inbound-ports gets
//     protocol detection it cannot survive; the owning workload
//     template is patched and the pod re-rolled (30m cooldown).
//   - coredns-upstream (W10-NM5): per-pod CoreDNS/node-local-dns
//     upstream healthcheck failures or SERVFAIL ratio from
//     Prometheus; an isolated failing pod is deleted (30m
//     cooldown) while siblings stay healthy.
//   - cilium-node-ipam-exhaustion (W10-NM6): node pod-IP free
//     ratio <15% (Prometheus cilium_operator_ipam_{used,available}_ips
//     vs podCIDR, pod-count fallback) — terminal pods on the node
//     are reaped and the
//     check FAILs for the CiliumNodeIPAMNearExhaustion alert.
//   - namespace-terminating-wedged (W10-CP1): Namespaces stuck
//     Terminating >20m with their content/finalizers conditions —
//     plus a throttled dead-owner finalizer sweep on CRs whose
//     controller workload no longer exists.
//   - argocd-app-stuck (W10-CP6): Applications Progressing >45m
//     or carrying ComparisonError/InvalidSpecError conditions —
//     refresh=hard patch (30m cooldown) and, on >=2 simultaneous
//     ComparisonErrors, an argocd-repo-server pod restart.
//   - rabbitmq-quorum-health (W10-ST3): RabbitMQ alarms / Mnesia
//     partition signals from Prometheus plus the stuck-unready
//     pod heal while >=2 siblings stay Ready.
//   - dragonfly-replica-sync-storm (W10-ST4): sustained
//     master-link-down + sync-full storm — restart ONLY the
//     desynced replica pod, never the master.
//   - image-pull-storm (W10-GI5): containers waiting in
//     ImagePullBackOff/ErrImagePull/RegistryUnavailable >10m —
//     single-namespace vs cluster-registry-outage classification.
//
// State note: clusterHealthProber's fields live in
// cluster_health_probes.go (owned by a parallel workstream), so the
// Wave-10 first-seen streak ledger and emitted-gauge hygiene live
// in the package-level wave10State below, and heal cooldowns ride
// the shared p.meshHealed component→time ledger under w10/-prefixed
// keys — the same wider-of-both in-RAM cooldown shape the W8/W9
// checks use.
//
// Metrics note: the Wave-10 gauge vectors are declared in this file
// (registered on ctrlmetrics.Registry via init) because
// internal/metrics is owned by parallel workstreams — same escape
// hatch internal/metrics/wave9.go documents.
package clusterhealthprobes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// ---------------------------------------------------------------------------
// Check names + knobs
// ---------------------------------------------------------------------------

const (
	checkNameCiliumBPFMapPressure = "cilium-bpf-map-pressure"
	checkNameLinkerdOpaqueStall   = "linkerd-protocol-detection-stall"
	checkNameCoreDNSUpstream      = "coredns-upstream"
	checkNameCiliumNodeIPAM       = "cilium-node-ipam-exhaustion"
	checkNameNamespaceWedged      = "namespace-terminating-wedged"
	checkNameArgoCDAppStuck       = "argocd-app-stuck"
	checkNameRabbitMQQuorum       = "rabbitmq-quorum-health"
	checkNameDragonflySyncStorm   = "dragonfly-replica-sync-storm"
	checkNameImagePullStorm       = "image-pull-storm"
)

const (
	// W10-NM1 — cilium-bpf-map-pressure knobs.
	ciliumBPFDefaultThreshold = 0.85

	// W10-NM3 — linkerd-protocol-detection-stall knobs.
	linkerdProxyContainer  = "linkerd-proxy"
	linkerdOpaquePortsAnno = "config.linkerd.io/opaque-ports"
	linkerdSkipInboundAnno = "config.linkerd.io/skip-inbound-ports"
	linkerdOpaqueHealCool  = 30 * time.Minute

	// W10-NM5 — coredns-upstream knobs.
	coreDNSUpstreamHealCool = 30 * time.Minute
	coreDNSFallbackMinAge   = 10 * time.Minute

	// W10-NM6 — cilium-node-ipam-exhaustion knobs.
	ciliumIPAMMinFreeRatio = 0.15
	ciliumIPAMNodeCool     = 30 * time.Minute
	ciliumIPAMMaxReaps     = 50

	// W10-CP1 — namespace-terminating-wedged knobs.
	nsTerminatingMinAge      = 20 * time.Minute
	nsFinalizerSweepCooldown = 30 * time.Minute
	nsFinalizerMaxStrips     = 20

	// W10-CP6 — argocd-app-stuck knobs.
	argocdAppProgressingMinAge = 45 * time.Minute
	argocdConditionMinAge      = 5 * time.Minute
	argocdRefreshCooldown      = 30 * time.Minute
	argocdRepoServerCool       = 30 * time.Minute
	argocdRefreshAnno          = "argocd.argoproj.io/refresh"

	// W10-ST3 — rabbitmq-quorum-health knobs.
	rabbitUnreadyMinAge  = 10 * time.Minute
	rabbitQuorumHealCool = 30 * time.Minute

	// W10-ST4 — dragonfly-replica-sync-storm knobs.
	dragonflyLinkMinAge   = 5 * time.Minute
	dragonflySyncHealCool = 30 * time.Minute

	// W10-GI5 — image-pull-storm knobs.
	imagePullMinAge = 10 * time.Minute
)

// argocdAppGVR is the Application CRD the W10-CP6 auditor reads —
// argoproj.io/v1alpha1 (distinct from the argoproj.io/v1beta1
// ArgoCD cluster CR the operator watchdog already scans).
var argocdAppGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}

// wave10LinkerdBinaryPorts are the well-known binary/stateful server
// ports Linkerd protocol detection cannot classify — a meshed pod
// exposing one of these without an opaque/skip annotation stalls on
// every new connection (the W6.2/W9 linkerd port lists live in
// check-linkerd-stateful-ports; this is the pod-level audit mirror).
var wave10LinkerdBinaryPorts = map[int]bool{
	3306: true, 5432: true, 6379: true, 27017: true, 9042: true,
	4369: true, 25672: true, 7000: true, 7001: true, 9999: true,
}

// ---------------------------------------------------------------------------
// Wave-10 state + shared helpers
// ---------------------------------------------------------------------------

// wave10State is the package-level Wave-10 ledger. The prober struct
// is owned by cluster_health_probes.go, so first-seen streak windows
// and emitted-gauge tuples live here; there is exactly one prober per
// process so package scope is the correct lifetime.
var wave10State = struct {
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

// wave10SeenFirst returns the first-seen time for a signature,
// stamping `now` on first observation. ok=false means this is the
// first sighting — callers treat it as "inside the window".
func wave10SeenFirst(check, key string, now time.Time) (time.Time, bool) {
	wave10State.Lock()
	defer wave10State.Unlock()
	k := check + "/" + key
	if t, ok := wave10State.seen[k]; ok {
		return t, true
	}
	wave10State.seen[k] = now
	return now, false
}

// wave10SeenPrune drops first-seen entries under `check` whose
// signature key is absent from keep — resolved signatures re-arm.
func wave10SeenPrune(check string, keep map[string]bool) {
	wave10State.Lock()
	defer wave10State.Unlock()
	prefix := check + "/"
	for k := range wave10State.seen {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if !keep[strings.TrimPrefix(k, prefix)] {
			delete(wave10State.seen, k)
		}
	}
}

// wave10ReconcileGauges reconciles one check's emitted-gauge ledger:
// tuples in `current` (dedup key → label values) stay; previously
// emitted tuples absent from current are DeleteLabelValues'd. Callers
// Set() their gauge values BEFORE calling this.
func wave10ReconcileGauges(check string, vec *prometheus.GaugeVec,
	current map[string][]string) {
	wave10State.Lock()
	defer wave10State.Unlock()
	em := wave10State.emitted[check]
	if em == nil {
		em = map[string][]string{}
		wave10State.emitted[check] = em
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

// wave10Cooled reports whether key was healed inside cooldown — the
// read half of the shared p.meshHealed ledger under w10/ keys.
func (p *clusterHealthProber) wave10Cooled(key string, cooldown time.Duration, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meshHealed == nil {
		p.meshHealed = map[string]time.Time{}
	}
	last, ok := p.meshHealed[key]
	return ok && now.Sub(last) < cooldown
}

// wave10MarkHealed stamps key on the shared heal ledger.
func (p *clusterHealthProber) wave10MarkHealed(key string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meshHealed == nil {
		p.meshHealed = map[string]time.Time{}
	}
	p.meshHealed[key] = now
}

// wave10DeletePod is the Wave-10 pod-delete heal: per-target cooldown
// on the shared ledger, the maintenance mutex (fail closed on
// unverifiable), a UID-preconditioned delete, and the shared
// ControlPlanePodHealsTotal counter under the check name.
func (p *clusterHealthProber) wave10DeletePod(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) {

	key := "w10/" + checkName + "/" + targetKey
	if p.wave10Cooled(key, cooldown, now) {
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
		log.Error(err, "wave10 heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	p.wave10MarkHealed(key, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
	log.Info("DELETE: wave10 heal — forcing pod restart",
		"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
}

// wave10UnreadySince returns when the pod's Ready condition last went
// non-True — the persistence clock for "stuck unready" heals. Absent
// Ready condition falls back to pod creation (a pod that never
// reported Ready is unready since birth).
func wave10UnreadySince(pod *corev1.Pod) (time.Time, bool) {
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

// wave10PromSeries is one instant-vector sample: metric labels plus
// the scalar value.
type wave10PromSeries struct {
	metric map[string]string
	value  float64
}

// wave10PromLabel returns the first non-empty value among keys.
func wave10PromLabel(s wave10PromSeries, keys ...string) string {
	for _, k := range keys {
		if v := s.metric[k]; v != "" {
			return v
		}
	}
	return ""
}

// wave10PromQuery runs an instant PromQL query against the cluster
// Prometheus and returns the vector series. The endpoint resolves
// from HEALTH_PROMETHEUS_QUERY_URL (full /api/v1/query URL) or is
// derived from cfg.httpURL's scheme://host — the same Prometheus the
// http-content-check health-probes. p.httpClient is the shared seam
// tests already drive with httptest servers.
func (p *clusterHealthProber) wave10PromQuery(ctx context.Context, query string) ([]wave10PromSeries, error) {
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
	var out []wave10PromSeries
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
		out = append(out, wave10PromSeries{metric: r.Metric, value: v})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Wave-10 gauge vectors — see package header for why they live here.
// ---------------------------------------------------------------------------

var (
	// W10-NM1 — Cilium BPF map fill ratio per node/map.
	wave10CiliumBPFMapPressure = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_bpf_map_pressure",
		Help: "Cilium BPF map fill ratio (used/max) per node and map_name — W10-NM1.",
	}, []string{"node", "map_name"})

	// W10-NM3 — meshed pod exposing an unannotated binary port.
	wave10LinkerdOpaquePortMissing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_opaque_port_missing",
		Help: "1 while the meshed pod exposes a well-known binary port without opaque/skip-inbound annotation — W10-NM3.",
	}, []string{"namespace", "pod", "port"})

	// W10-NM5 — per-pod DNS upstream failure signal.
	wave10CoreDNSUpstreamFailing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_coredns_upstream_failing",
		Help: "1 while the coredns/node-local-dns pod reports isolated upstream failures — W10-NM5.",
	}, []string{"namespace", "pod"})

	// W10-NM6 — free pod-IP ratio per node.
	wave10CiliumIPAMFreeRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_ipam_free_ratio",
		Help: "Free pod-IP ratio (0..1) per node — W10-NM6; <0.15 fails the check.",
	}, []string{"node"})

	// W10-CP1 — namespace stuck Terminating.
	wave10NamespaceTerminatingWedged = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_namespace_terminating_wedged",
		Help: "1 while the Namespace has been Terminating past the wedge threshold — W10-CP1.",
	}, []string{"namespace"})

	// W10-CP6 — ArgoCD Application stuck.
	wave10ArgoCDAppStuck = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_argocd_app_stuck",
		Help: "1 while the ArgoCD Application reports Progressing >45m or an error condition — W10-CP6.",
	}, []string{"namespace", "name", "reason"})

	// W10-ST3 — RabbitMQ quorum/partition signal.
	wave10RabbitMQQuorumUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_rabbitmq_quorum_unhealthy",
		Help: "1 while the RabbitMQ pod/cluster reports an alarm, partition or stuck-unready signature — W10-ST3.",
	}, []string{"namespace", "pod", "reason"})

	// W10-ST4 — Dragonfly/Valkey replica sync storm.
	wave10DragonflyReplicaSyncStorm = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_dragonfly_replica_sync_storm",
		Help: "1 while the replica pod shows sustained master-link-down during a sync storm — W10-ST4.",
	}, []string{"namespace", "pod"})

	// W10-GI5 — per-pod image-pull backoff.
	wave10ImagePullBackoffPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_image_pull_backoff",
		Help: "1 while the pod has a container waiting in an image-pull failure >10m — W10-GI5.",
	}, []string{"namespace", "pod"})

	// W10-GI5 — cluster-wide registry/pull outage latch.
	wave10RegistryPullOutage = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_registry_pull_outage",
		Help: "1 while image-pull failures span >=2 namespaces or carry a registry-outage signature — W10-GI5.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		wave10CiliumBPFMapPressure,
		wave10LinkerdOpaquePortMissing,
		wave10CoreDNSUpstreamFailing,
		wave10CiliumIPAMFreeRatio,
		wave10NamespaceTerminatingWedged,
		wave10ArgoCDAppStuck,
		wave10RabbitMQQuorumUnhealthy,
		wave10DragonflyReplicaSyncStorm,
		wave10ImagePullBackoffPods,
		wave10RegistryPullOutage)
}

// ---------------------------------------------------------------------------
// W10-NM1 — cilium-bpf-map-pressure
// ---------------------------------------------------------------------------

// checkCiliumBPFMapPressure queries Prometheus for BPF maps whose fill
// ratio exceeds the threshold — a map at max_entries drops the traffic
// class it serves silently (full conntrack = every new flow refused).
// Prometheus-unreachable is inconclusive (http-content-check already
// owns Prometheus liveness) — the check passes with a WARN, never a
// false FAIL.
func (p *clusterHealthProber) checkCiliumBPFMapPressure(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	threshold := healthEnvFloat("WAVE10_CILIUM_BPF_PRESSURE", ciliumBPFDefaultThreshold)
	query := fmt.Sprintf(
		`max by (node, map_name) (cilium_bpf_map_pressure) > %s`,
		strconv.FormatFloat(threshold, 'f', -1, 64))
	series, err := p.wave10PromQuery(ctx, query)
	if err != nil {
		log.Info("WARN: cilium bpf map pressure query failed — check inconclusive",
			"error", err)
		return probeResult{pass: true}
	}
	current := map[string][]string{}
	var findings []string
	for _, s := range series {
		node := wave10PromLabel(s, "node", "kubernetes_node", "instance")
		mapName := s.metric["map_name"]
		if node == "" || mapName == "" {
			continue
		}
		lv := []string{node, mapName}
		current[node+"/"+mapName] = lv
		wave10CiliumBPFMapPressure.WithLabelValues(lv...).Set(s.value)
		findings = append(findings,
			fmt.Sprintf("%s/%s=%.2f", node, mapName, s.value))
	}
	sort.Strings(findings)
	wave10ReconcileGauges(checkNameCiliumBPFMapPressure,
		wave10CiliumBPFMapPressure, current)
	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: fmt.Sprintf(
		"cilium_bpf_map_pressure>%s: %s",
		strconv.FormatFloat(threshold, 'f', -1, 64),
		strings.Join(findings, ", "))}
}

// ---------------------------------------------------------------------------
// W10-NM3 — linkerd-protocol-detection-stall
// ---------------------------------------------------------------------------

// wave10ParsePortSet parses a linkerd port annotation
// ("6379,8000-8010") into a set of concrete ports. Ranges are
// expanded — annotation values are small.
func wave10ParsePortSet(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || h < l || h-l > 1024 {
				continue
			}
			for p := l; p <= h; p++ {
				out[p] = true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out[n] = true
		}
	}
	return out
}

// wave10PortSetString renders a port set back as a sorted
// comma-separated annotation value.
func wave10PortSetString(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	return wave10JoinPorts(ports)
}

// wave10JoinPorts renders an already-sorted port list as a
// comma-separated annotation value.
func wave10JoinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

// wave10MissingBinaryPorts returns the sorted well-known binary ports
// the pod's containers expose that are covered by NEITHER
// opaque-ports NOR skip-inbound-ports — either annotation makes the
// proxy treat the port as opaque TCP (skip-inbound is the inbound-only
// spelling of the same escape).
func wave10MissingBinaryPorts(pod *corev1.Pod) []int {
	covered := wave10ParsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	for p := range wave10ParsePortSet(pod.Annotations[linkerdSkipInboundAnno]) {
		covered[p] = true
	}
	seen := map[int]bool{}
	var missing []int
	for _, c := range pod.Spec.Containers {
		for _, port := range c.Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
				continue
			}
			n := int(port.ContainerPort)
			if wave10LinkerdBinaryPorts[n] && !covered[n] && !seen[n] {
				seen[n] = true
				missing = append(missing, n)
			}
		}
	}
	sort.Ints(missing)
	return missing
}

// checkLinkerdProtocolDetectionStall audits running meshed pods for
// well-known binary/stateful ports missing the opaque/skip-inbound
// annotation — Linkerd's protocol detector cannot classify MySQL,
// Postgres, Redis, Mongo, Cassandra, RabbitMQ or Dragonfly wire
// protocols and stalls every new connection on them.
//
// Heal: patch config.linkerd.io/opaque-ports onto the owning
// workload's pod template (Deployment/StatefulSet/DaemonSet/Job/
// CronJob resolved through ownerReferences) AND the pod itself, then
// delete the pod so the proxy restarts with the corrected config — a
// running linkerd-proxy never re-reads its port annotations, so an
// annotation-only patch cannot heal. The pod is only deleted when the
// template patch succeeded (otherwise the replacement would inherit
// the same violation); 30m per-pod cooldown, maintenance-gated.
func (p *clusterHealthProber) checkLinkerdProtocolDetectionStall(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	current := map[string][]string{}
	var findings []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if !shared.PodSpecHasContainer(&pod.Spec, linkerdProxyContainer) {
			continue
		}
		missing := wave10MissingBinaryPorts(pod)
		if len(missing) == 0 {
			continue
		}
		for _, port := range missing {
			lv := []string{pod.Namespace, pod.Name, strconv.Itoa(port)}
			current[pod.Namespace+"/"+pod.Name+"/"+strconv.Itoa(port)] = lv
			wave10LinkerdOpaquePortMissing.WithLabelValues(lv...).Set(1)
		}
		findings = append(findings, fmt.Sprintf("%s/%s ports=%s",
			pod.Namespace, pod.Name, wave10JoinPorts(missing)))
		p.wave10HealLinkerdOpaquePorts(ctx, log, pod, missing, now)
	}
	sort.Strings(findings)
	wave10ReconcileGauges(checkNameLinkerdOpaqueStall,
		wave10LinkerdOpaquePortMissing, current)
	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "meshed pods exposing unannotated binary ports: " +
		strings.Join(findings, ", ")}
}

// wave10HealLinkerdOpaquePorts applies the opaque-ports heal for one
// violating pod: cooldown → maintenance gate → template patch → pod
// annotation patch → pod delete (only when the template took the
// annotation, else the replacement re-inherits the violation).
func (p *clusterHealthProber) wave10HealLinkerdOpaquePorts(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time) {

	ck := "w10/" + checkNameLinkerdOpaqueStall + "/" + pod.Namespace + "/" + pod.Name
	if p.wave10Cooled(ck, linkerdOpaqueHealCool, now) {
		log.Info("skip heal: inside cooldown", "check", checkNameLinkerdOpaqueStall,
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"check", checkNameLinkerdOpaqueStall,
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"check", checkNameLinkerdOpaqueStall,
			"pod", pod.Namespace+"/"+pod.Name, "why", why)
		return
	}
	templateOK := p.wave10PatchLinkerdTemplate(ctx, log, pod, missing)
	p.wave10PatchLinkerdPodAnno(ctx, log, pod, missing)
	if !templateOK {
		log.Info("opaque-ports heal: owning workload template not patched — leaving pod running (annotation alone cannot reach a live proxy)",
			"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
		return
	}
	uid := pod.UID
	if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "linkerd opaque-ports pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	p.wave10MarkHealed(ck, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkNameLinkerdOpaqueStall).Inc()
	log.Info("DELETE: linkerd protocol-detection stall — template patched, re-rolling pod",
		"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
}

// wave10PatchLinkerdTemplate resolves the pod's controller owner to
// its workload and merges the missing ports into the pod-template
// opaque-ports annotation. Returns true when the template now covers
// the ports (patched now, or already covered — the pod just needs a
// restart). False when no workload owner resolves or the patch fails
// (RBAC/not-found) — the caller must not delete the pod then.
func (p *clusterHealthProber) wave10PatchLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int) bool {

	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return false
	}
	ns := pod.Namespace
	switch ref.Kind {
	case "ReplicaSet":
		rs, err := p.cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — replicaset get failed",
				"rs", ns+"/"+ref.Name, "error", err)
			return false
		}
		dref := metav1.GetControllerOf(rs)
		if dref == nil || dref.Kind != "Deployment" {
			return false
		}
		dep, err := p.cs.AppsV1().Deployments(ns).Get(ctx, dref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — deployment get failed",
				"deployment", ns+"/"+dref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false)
	case "Deployment":
		dep, err := p.cs.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — deployment get failed",
				"deployment", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false)
	case "StatefulSet":
		sts, err := p.cs.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — statefulset get failed",
				"statefulset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "statefulset", ns, sts.Name,
			sts.Spec.Template.Annotations, missing, false)
	case "DaemonSet":
		ds, err := p.cs.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — daemonset get failed",
				"daemonset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "daemonset", ns, ds.Name,
			ds.Spec.Template.Annotations, missing, false)
	case "Job":
		job, err := p.cs.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — job get failed",
				"job", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "job", ns, job.Name,
			job.Spec.Template.Annotations, missing, false)
	case "CronJob":
		cj, err := p.cs.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — cronjob get failed",
				"cronjob", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.wave10PatchTemplatePorts(ctx, log, "cronjob", ns, cj.Name,
			cj.Spec.JobTemplate.Spec.Template.Annotations, missing, true)
	default:
		return false
	}
}

// wave10PatchTemplatePorts merge-patches the opaque-ports annotation
// into a workload's pod template. existing is the template's current
// annotations — when they already cover `missing` the patch is
// skipped but the template is still reported covered (the pod only
// needs a restart). Returns false on patch failure.
func (p *clusterHealthProber) wave10PatchTemplatePorts(ctx context.Context,
	log logr.Logger, kind, ns, name string, existing map[string]string,
	missing []int, cronJob bool) bool {

	covered := wave10ParsePortSet(existing[linkerdOpaquePortsAnno])
	for pt := range wave10ParsePortSet(existing[linkerdSkipInboundAnno]) {
		covered[pt] = true
	}
	stillMissing := map[int]bool{}
	for _, pt := range missing {
		if !covered[pt] {
			stillMissing[pt] = true
		}
	}
	if len(stillMissing) == 0 {
		log.Info("linkerd heal: template already covers ports — pod restart suffices",
			"kind", kind, "workload", ns+"/"+name)
		return true
	}
	for pt := range stillMissing {
		covered[pt] = true
	}
	value := wave10PortSetString(covered)
	var payload []byte
	var err error
	anno := map[string]string{linkerdOpaquePortsAnno: value}
	if cronJob {
		payload, err = json.Marshal(map[string]any{
			"spec": map[string]any{
				"jobTemplate": map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"metadata": map[string]any{"annotations": anno},
						},
					},
				},
			},
		})
	} else {
		payload, err = json.Marshal(map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{"annotations": anno},
				},
			},
		})
	}
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "linkerd heal: marshal template patch failed",
			"kind", kind, "workload", ns+"/"+name)
		return false
	}
	var patchErr error
	switch kind {
	case "deployment":
		_, patchErr = p.cs.AppsV1().Deployments(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "statefulset":
		_, patchErr = p.cs.AppsV1().StatefulSets(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "daemonset":
		_, patchErr = p.cs.AppsV1().DaemonSets(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "job":
		_, patchErr = p.cs.BatchV1().Jobs(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "cronjob":
		_, patchErr = p.cs.BatchV1().CronJobs(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	}
	if patchErr != nil {
		// Forbidden until the RBAC wave lands patch on pods /
		// daemonsets / jobs — log and fail closed (no pod delete).
		log.Info("WARN: linkerd heal — template patch failed",
			"kind", kind, "workload", ns+"/"+name, "error", patchErr)
		return false
	}
	log.Info("PATCH: linkerd opaque-ports added to workload template",
		"kind", kind, "workload", ns+"/"+name, "ports", value)
	return true
}

// wave10PatchLinkerdPodAnno merge-patches the pod's own
// opaque-ports annotation — best-effort bookkeeping (a running
// proxy does not re-read it; the template patch + restart is the
// real heal). Failures are logged, never fatal.
func (p *clusterHealthProber) wave10PatchLinkerdPodAnno(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int) {

	set := wave10ParsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	changed := false
	for _, pt := range missing {
		if !set[pt] {
			set[pt] = true
			changed = true
		}
	}
	if !changed {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				linkerdOpaquePortsAnno: wave10PortSetString(set),
			},
		},
	})
	if err != nil {
		return
	}
	if _, err := p.cs.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Info("WARN: linkerd heal — pod annotation patch failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
	}
}

// ---------------------------------------------------------------------------
// W10-NM5 — coredns-upstream
// ---------------------------------------------------------------------------

// wave10IsDNSPod reports whether the pod is a CoreDNS or
// node-local-dns member — by name prefix or the k8s-app label the
// upstream charts stamp.
func wave10IsDNSPod(pod *corev1.Pod) bool {
	if strings.HasPrefix(pod.Name, "coredns-") ||
		strings.HasPrefix(pod.Name, "node-local-dns-") {
		return true
	}
	switch pod.Labels["k8s-app"] {
	case "kube-dns", "node-local-dns":
		return true
	}
	return pod.Labels["app.kubernetes.io/name"] == "coredns" ||
		pod.Labels["app.kubernetes.io/name"] == "node-local-dns"
}

// checkCoreDNSUpstream detects per-pod CoreDNS/node-local-dns
// upstream failures via Prometheus: healthcheck failures
// (coredns_ForwardHealthcheckFailureCount_total rate >0.5/s over 5m)
// or a SERVFAIL ratio >15%. When a SINGLE dns pod fails while a
// sibling in the same namespace stays healthy, the pod is deleted
// (30m cooldown) — an upstream socket/conntrack wedge is per-pod
// state a restart clears. Both queries failing is inconclusive and
// falls back to the pod-readiness signature (unready >10m with a
// healthy sibling) rather than false-FAILing on a Prometheus outage.
func (p *clusterHealthProber) checkCoreDNSUpstream(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	healthSeries, errH := p.wave10PromQuery(ctx,
		`sum by (pod) (rate(coredns_ForwardHealthcheckFailureCount_total[5m])) > 0.5`)
	servfailSeries, errS := p.wave10PromQuery(ctx,
		`sum by (pod) (rate(coredns_dns_responses_total{rcode="SERVFAIL"}[5m]))`+
			` / clamp_min(sum by (pod) (rate(coredns_dns_responses_total[5m])), 1) > 0.15`)
	if errH != nil {
		log.Info("WARN: coredns healthcheck-failure query failed", "error", errH)
	}
	if errS != nil {
		log.Info("WARN: coredns SERVFAIL-ratio query failed", "error", errS)
	}
	if errH != nil && errS != nil {
		log.Info("WARN: prometheus unreachable for both coredns queries — readiness fallback")
		return p.wave10CoreDNSFallback(ctx, log, now)
	}

	// Pod census — dns pods only, for name→ns resolution, sibling
	// health and the heal target.
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	dnsByName := map[string]*corev1.Pod{}
	dnsByNS := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !wave10IsDNSPod(pod) {
			continue
		}
		dnsByName[pod.Name] = pod
		dnsByNS[pod.Namespace] = append(dnsByNS[pod.Namespace], pod)
	}

	flagged := map[string]string{} // "ns/name" -> reason detail
	record := func(podName, nsHint, detail string) {
		ns := nsHint
		if pod := dnsByName[podName]; pod != nil {
			ns = pod.Namespace // census wins over the series label
		}
		if ns == "" {
			ns = "unknown"
		}
		flagged[ns+"/"+podName] = detail
	}
	for _, s := range healthSeries {
		if name := wave10PromLabel(s, "pod", "pod_name"); name != "" {
			record(name, s.metric["namespace"],
				fmt.Sprintf("healthcheck_failures=%.2f", s.value))
		}
	}
	for _, s := range servfailSeries {
		if name := wave10PromLabel(s, "pod", "pod_name"); name != "" {
			record(name, s.metric["namespace"],
				fmt.Sprintf("servfail_ratio=%.2f", s.value))
		}
	}

	current := map[string][]string{}
	for key := range flagged {
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod := dnsByName[name]
		if pod != nil && pod.Namespace == ns {
			lv := []string{ns, name}
			current[key] = lv
			wave10CoreDNSUpstreamFailing.WithLabelValues(lv...).Set(1)
		}
		// Isolated-failure heal: a healthy Ready sibling in the same
		// namespace means this is per-pod wedge, not a fleet outage.
		if pod != nil && wave10HasHealthySibling(pod, dnsByNS[ns], flagged) {
			p.wave10DeletePod(ctx, log, checkNameCoreDNSUpstream,
				ns+"/"+name, pod, coreDNSUpstreamHealCool, now)
		}
	}
	wave10ReconcileGauges(checkNameCoreDNSUpstream,
		wave10CoreDNSUpstreamFailing, current)

	if len(flagged) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(flagged))
	for k, d := range flagged {
		keys = append(keys, k+"("+d+")")
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"coredns/node-local-dns upstream failures: %s",
		strings.Join(keys, ", "))}
}

// wave10HasHealthySibling reports whether another dns pod in the same
// namespace is Running+Ready and NOT itself flagged — the "isolated
// failure" precondition for the pod-delete heal.
func wave10HasHealthySibling(pod *corev1.Pod, siblings []*corev1.Pod,
	flagged map[string]string) bool {
	for _, s := range siblings {
		if s.Name == pod.Name || s.DeletionTimestamp != nil {
			continue
		}
		if _, bad := flagged[s.Namespace+"/"+s.Name]; bad {
			continue
		}
		if s.Status.Phase == corev1.PodRunning && shared.PodReadyCond(s) {
			return true
		}
	}
	return false
}

// wave10CoreDNSFallback is the Prometheus-unreachable path: the same
// isolated-failure shape detected from pod readiness — a dns pod
// unready >=10m while a sibling stays Ready.
func (p *clusterHealthProber) wave10CoreDNSFallback(ctx context.Context,
	log logr.Logger, now time.Time) probeResult {

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	dnsByNS := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if wave10IsDNSPod(pod) {
			dnsByNS[pod.Namespace] = append(dnsByNS[pod.Namespace], pod)
		}
	}
	flagged := map[string]string{}
	for ns, members := range dnsByNS {
		for _, pod := range members {
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase == corev1.PodSucceeded ||
				pod.Status.Phase == corev1.PodFailed {
				continue
			}
			since, unready := wave10UnreadySince(pod)
			if !unready || now.Sub(since) < coreDNSFallbackMinAge {
				continue
			}
			flagged[ns+"/"+pod.Name] = "unready>10m(readiness-fallback)"
		}
	}

	current := map[string][]string{}
	var findings []string
	for key, detail := range flagged {
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod := wave10PodFromList(pods.Items, ns, name)
		if pod == nil {
			continue
		}
		lv := []string{ns, name}
		current[key] = lv
		wave10CoreDNSUpstreamFailing.WithLabelValues(lv...).Set(1)
		if wave10HasHealthySibling(pod, dnsByNS[ns], flagged) {
			p.wave10DeletePod(ctx, log, checkNameCoreDNSUpstream,
				ns+"/"+name, pod, coreDNSUpstreamHealCool, now)
		}
		findings = append(findings, key+"("+detail+")")
	}
	sort.Strings(findings)
	wave10ReconcileGauges(checkNameCoreDNSUpstream,
		wave10CoreDNSUpstreamFailing, current)
	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "coredns/node-local-dns unready pods (prometheus fallback): " +
		strings.Join(findings, ", ")}
}

// wave10PodFromList resolves ns/name inside an already-fetched pod
// list — kept tiny to avoid a second cluster-wide List in the
// fallback path.
func wave10PodFromList(items []corev1.Pod, ns, name string) *corev1.Pod {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// W10-NM6 — cilium-node-ipam-exhaustion
// ---------------------------------------------------------------------------

// wave10PodCIDRCapacity returns the usable pod-IP count for a node
// podCIDR — total addresses minus network+broadcast (a /24 yields
// 254, matching the plan's convention). IPv6 podCIDRs and absent
// values report ok=false.
func wave10PodCIDRCapacity(podCIDR string) (int, bool) {
	if podCIDR == "" || strings.Contains(podCIDR, ":") {
		return 0, false
	}
	_, ipnet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if ones <= 0 || bits != 32 {
		return 0, false
	}
	total := int64(1) << uint(bits-ones)
	usable := total - 2
	if usable < 1 {
		usable = 1
	}
	return int(usable), true
}

// checkCiliumNodeIPAMExhaustion watches per-node pod-IP exhaustion:
// Prometheus cilium_operator_ipam_{used,available}_ips{target_node}
// vs the node's podCIDR
// capacity, with a non-hostNetwork pod count as the per-node
// fallback (and for nodes absent from the metric). Below 15% free
// the check FAILs (feeding CiliumNodeIPAMNearExhaustion) and, once
// per node per 30m, reaps Succeeded/Failed pods on that node —
// deleting the pod object makes kubelet tear down the sandbox and
// release the IP. Orphaned CRI sandboxes (pod object already gone)
// have no apiserver handle — noted, not actionable from here.
func (p *clusterHealthProber) checkCiliumNodeIPAMExhaustion(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	minFree := healthEnvFloat("WAVE10_IPAM_MIN_FREE_RATIO", ciliumIPAMMinFreeRatio)

	// Prometheus operator IPAM census — cilium_operator_ipam_{used,
	// available}_ips{target_node} (cilium >=1.15; the old
	// cilium_ipam_ips{type=used} metric does not exist). A query
	// failure or an empty result (metric absent on this Cilium
	// version) degrades to the pod-count path rather than
	// false-FAILing.
	usedProm := map[string]float64{}
	availProm := map[string]float64{}
	promOK := false
	if usedSeries, err := p.wave10PromQuery(ctx,
		`cilium_operator_ipam_used_ips`); err == nil && len(usedSeries) > 0 {
		if availSeries, aerr := p.wave10PromQuery(ctx,
			`cilium_operator_ipam_available_ips`); aerr == nil {
			promOK = true
			for _, s := range usedSeries {
				if node := wave10PromLabel(s, "target_node", "node",
					"kubernetes_node"); node != "" {
					usedProm[node] = s.value
				}
			}
			for _, s := range availSeries {
				if node := wave10PromLabel(s, "target_node", "node",
					"kubernetes_node"); node != "" {
					availProm[node] = s.value
				}
			}
		}
	} else if err != nil {
		log.Info("WARN: cilium_operator_ipam_used_ips query failed — pod-count fallback",
			"error", err)
	}

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	podCount := map[string]int{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.HostNetwork || pod.Spec.NodeName == "" {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		podCount[pod.Spec.NodeName]++
	}

	current := map[string][]string{}
	var exhausted []string
	for i := range nodes {
		node := &nodes[i]
		capacity, ok := wave10PodCIDRCapacity(node.Spec.PodCIDR)
		if !ok {
			continue
		}
		used := float64(podCount[node.Name])
		free := float64(capacity) - used
		if free < 0 {
			free = 0
		}
		ratio := free / float64(capacity)
		// Operator IPAM accounting is authoritative when present —
		// it counts allocated pod IPs the pod census misses. With
		// used+available the free ratio comes straight from the
		// operator's own PodCIDR math.
		if promOK {
			if u, ok := usedProm[node.Name]; ok {
				if a, aok := availProm[node.Name]; aok && u+a > 0 {
					ratio = a / (u + a)
					free = a
				} else {
					used = u
					free = float64(capacity) - used
					if free < 0 {
						free = 0
					}
					ratio = free / float64(capacity)
				}
			}
		}
		lv := []string{node.Name}
		current[node.Name] = lv
		wave10CiliumIPAMFreeRatio.WithLabelValues(lv...).Set(ratio)
		if ratio >= minFree {
			continue
		}
		exhausted = append(exhausted, fmt.Sprintf(
			"%s(free=%.0f/%d=%.0f%%)", node.Name, free, capacity, ratio*100))
		p.wave10ReapTerminalPodsOnNode(ctx, log, node.Name, now)
	}
	sort.Strings(exhausted)
	wave10ReconcileGauges(checkNameCiliumNodeIPAM,
		wave10CiliumIPAMFreeRatio, current)
	if len(exhausted) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: fmt.Sprintf(
		"nodes below %.0f%% free pod IPs: %s",
		minFree*100, strings.Join(exhausted, ", "))}
}

// wave10ReapTerminalPodsOnNode deletes Succeeded/Failed pods on an
// IP-exhausted node (capped) so kubelet releases their sandboxes and
// pod IPs — once per node per cooldown, maintenance-gated. Terminal
// pods hold no traffic; the delete is the safe existing shape (same
// as the evicted-pod janitor, scoped to the exhausted node).
func (p *clusterHealthProber) wave10ReapTerminalPodsOnNode(ctx context.Context,
	log logr.Logger, node string, now time.Time) {

	ck := "w10/" + checkNameCiliumNodeIPAM + "/reap/" + node
	if p.wave10Cooled(ck, ciliumIPAMNodeCool, now) {
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — ipam reap deferred (fail closed)",
			"node", node, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — ipam reap deferred",
			"node", node, "why", why)
		return
	}
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + node,
		})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list node pods failed — ipam reap deferred",
			"node", node, "error", err)
		return
	}
	reaped := 0
	for i := range pods.Items {
		if reaped >= ciliumIPAMMaxReaps {
			break
		}
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			(pod.Status.Phase != corev1.PodSucceeded &&
				pod.Status.Phase != corev1.PodFailed) {
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "ipam terminal-pod reap failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		reaped++
	}
	if reaped > 0 {
		p.wave10MarkHealed(ck, now)
		log.Info("REAP: deleted terminal pods on IP-exhausted node",
			"node", node, "count", reaped)
	}
}

// ---------------------------------------------------------------------------
// W10-CP1 — namespace-terminating-wedged
// ---------------------------------------------------------------------------

// checkNamespaceTerminatingWedged flags Namespaces stuck in
// Terminating >20m and reports their drain-blocking conditions
// (NamespaceContentRemaining / NamespaceFinalizersRemaining) plus
// spec.finalizers — the diagnostic payload for "what is holding
// this namespace". Once per namespace per 30m it also runs the
// conservative dead-owner finalizer sweep: CRs in the namespace
// whose controller ownerRef resolves to a workload that no longer
// exists get their non-protected finalizers stripped.
func (p *clusterHealthProber) checkNamespaceTerminatingWedged(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	nss, err := p.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list namespaces: %w", err)}
	}
	current := map[string][]string{}
	var wedged []string
	for i := range nss.Items {
		ns := &nss.Items[i]
		if ns.DeletionTimestamp == nil ||
			now.Sub(ns.DeletionTimestamp.Time) < nsTerminatingMinAge {
			continue
		}
		lv := []string{ns.Name}
		current[ns.Name] = lv
		wave10NamespaceTerminatingWedged.WithLabelValues(lv...).Set(1)
		wedged = append(wedged, wave10NsDiagnostic(ns, now))
		p.wave10NsFinalizerSweep(ctx, log, ns.Name, now)
	}
	sort.Strings(wedged)
	wave10ReconcileGauges(checkNameNamespaceWedged,
		wave10NamespaceTerminatingWedged, current)
	if len(wedged) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "namespaces wedged Terminating >" +
		nsTerminatingMinAge.String() + ": " + strings.Join(wedged, " | ")}
}

// wave10NsDiagnostic renders one wedged namespace's blocking state
// for the check's why string.
func wave10NsDiagnostic(ns *corev1.Namespace, now time.Time) string {
	var conds []string
	for _, c := range ns.Status.Conditions {
		conds = append(conds, fmt.Sprintf("%s=%s", c.Type, c.Status))
	}
	var fins []string
	for _, f := range ns.Spec.Finalizers {
		fins = append(fins, string(f))
	}
	return fmt.Sprintf("%s(terminatingFor=%s,conditions=[%s],finalizers=[%s])",
		ns.Name, now.Sub(ns.DeletionTimestamp.Time).Truncate(time.Minute),
		strings.Join(conds, ","), strings.Join(fins, ","))
}

// wave10ProtectedFinalizer lists finalizer values the dead-owner
// sweep must NEVER strip: the foreground-deletion propagation
// marker, every in-tree kubernetes.io/* finalizer (pvc-protection,
// pv-protection, service-protection, ... — each has its own
// controller contract), and the CSI external-attacher finalizer
// family the volumeattachment-cleaner owns.
func wave10ProtectedFinalizer(f string) bool {
	if f == "foregroundDeletion" {
		return true
	}
	return strings.HasPrefix(f, "kubernetes.io/") ||
		strings.HasPrefix(f, "external-attacher/")
}

// wave10NsFinalizerSweep enumerates namespaced resources in a wedged
// namespace via discovery and strips strippable finalizers from
// terminating CRs whose controller owner no longer exists. Throttled
// per namespace; a discovery failure skips the sweep (detection
// already FAILed the check).
func (p *clusterHealthProber) wave10NsFinalizerSweep(ctx context.Context,
	log logr.Logger, nsName string, now time.Time) {

	if p.dyn == nil {
		return
	}
	ck := "w10/" + checkNameNamespaceWedged + "/finalsweep/" + nsName
	if p.wave10Cooled(ck, nsFinalizerSweepCooldown, now) {
		return
	}
	lists, err := p.cs.Discovery().ServerPreferredResources()
	if err != nil {
		log.Info("WARN: namespace finalizer sweep — discovery failed, skipping",
			"namespace", nsName, "error", err)
		return
	}
	stripped := 0
	for _, rl := range lists {
		if rl == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range rl.APIResources {
			if !r.Namespaced || strings.Contains(r.Name, "/") {
				continue // cluster-scoped or subresource
			}
			gvr := schema.GroupVersionResource{
				Group: gv.Group, Version: gv.Version, Resource: r.Name}
			items, err := p.dyn.Resource(gvr).Namespace(nsName).
				List(ctx, metav1.ListOptions{})
			if err != nil {
				continue // no permission / absent — not evidence
			}
			for i := range items.Items {
				obj := &items.Items[i]
				if obj.GetDeletionTimestamp() == nil ||
					len(obj.GetFinalizers()) == 0 {
					continue
				}
				if p.wave10MaybeStripFinalizers(ctx, log, gvr, obj) {
					stripped++
					if stripped >= nsFinalizerMaxStrips {
						p.wave10MarkHealed(ck, now)
						log.Info("namespace finalizer sweep — strip cap reached",
							"namespace", nsName, "stripped", stripped)
						return
					}
				}
			}
		}
	}
	p.wave10MarkHealed(ck, now)
	if stripped > 0 {
		log.Info("namespace finalizer sweep done",
			"namespace", nsName, "stripped", stripped)
	}
}

// wave10MaybeStripFinalizers removes strippable finalizers from one
// terminating object — only when its controller ownerRef resolves to
// a workload that provably no longer exists. Returns true when a
// patch was applied.
func (p *clusterHealthProber) wave10MaybeStripFinalizers(ctx context.Context,
	log logr.Logger, gvr schema.GroupVersionResource,
	obj *unstructured.Unstructured) bool {

	var keep []string
	var strip []string
	for _, f := range obj.GetFinalizers() {
		if wave10ProtectedFinalizer(f) {
			keep = append(keep, f)
		} else {
			strip = append(strip, f)
		}
	}
	if len(strip) == 0 {
		return false
	}
	if !p.wave10OwnerGone(ctx, obj) {
		return false
	}
	var fin any
	if len(keep) > 0 {
		fin = keep
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": obj.GetResourceVersion(),
			"finalizers":      fin,
		},
	})
	if err != nil {
		return false
	}
	if _, err := p.dyn.Resource(gvr).Namespace(obj.GetNamespace()).Patch(ctx,
		obj.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		if apierrors.IsForbidden(err) {
			// Expected until the RBAC wave grants patch on the CR —
			// not an apiserver failure, don't count a run error.
			log.Info("WARN: finalizer strip forbidden (RBAC pending)",
				"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName())
			return false
		}
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "finalizer strip failed",
			"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName())
		return false
	}
	log.Info("PATCH-FINALIZERS: dead-owner CR in terminating namespace — stripped finalizers",
		"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName(),
		"stripped", strip, "kept", keep)
	return true
}

// wave10OwnerGone reports whether the object's controller ownerRef
// points at a workload that no longer exists — the "dead operator"
// proof required before stripping. Unknown kinds and lookup errors
// fail closed (owner presumed alive).
func (p *clusterHealthProber) wave10OwnerGone(ctx context.Context,
	obj *unstructured.Unstructured) bool {

	ref := metav1.GetControllerOf(obj)
	if ref == nil {
		return false
	}
	ns := obj.GetNamespace()
	get := func(kind, name string) error {
		switch kind {
		case "Deployment":
			_, err := p.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "StatefulSet":
			_, err := p.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "DaemonSet":
			_, err := p.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "ReplicaSet":
			_, err := p.cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "Job":
			_, err := p.cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "CronJob":
			_, err := p.cs.BatchV1().CronJobs(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}
		return fmt.Errorf("unresolvable owner kind %q", kind)
	}
	err := get(ref.Kind, ref.Name)
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil {
		return false // lookup failed or unknown kind — fail closed
	}
	// Owner object exists — except a ReplicaSet whose own Deployment
	// is gone: the RS is GC-pending garbage, so its finalizers are
	// just as dead.
	if ref.Kind == "ReplicaSet" {
		rs, err := p.cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		if dref := metav1.GetControllerOf(rs); dref != nil && dref.Kind == "Deployment" {
			_, err := p.cs.AppsV1().Deployments(ns).Get(ctx, dref.Name, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// W10-CP6 — argocd-app-stuck
// ---------------------------------------------------------------------------

// checkArgoCDAppStuck audits ArgoCD Applications for the two stuck
// shapes: status.health.status=="Progressing" persisting >45m
// (first-seen ledger — health carries no transition timestamp), and
// status.conditions of type ComparisonError / InvalidSpecError
// (aged by lastTransitionTime, 5m floor). Each stuck app gets a
// argocd.argoproj.io/refresh=hard patch on a 30m cooldown; >=2
// simultaneous ComparisonErrors additionally restart the oldest
// argocd-repo-server pod — the shared stale-cache signature. An
// absent Application CRD is a clean pass (ArgoCD not installed).
func (p *clusterHealthProber) checkArgoCDAppStuck(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — argocd app check unverifiable")}
	}
	now := p.now()
	apps, err := p.dyn.Resource(argocdAppGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return probeResult{pass: true} // CRD absent — ArgoCD not installed
	case err != nil:
		return probeResult{infra: fmt.Errorf("list applications: %w", err)}
	}

	current := map[string][]string{}
	seenKeep := map[string]bool{}
	var stuck []string
	comparisonErrors := 0
	for i := range apps.Items {
		app := &apps.Items[i]
		ns, name := app.GetNamespace(), app.GetName()
		var reasons []string

		health, _, _ := unstructured.NestedString(app.Object,
			"status", "health", "status")
		if health == "Progressing" {
			sig := "prog/" + ns + "/" + name
			seenKeep[sig] = true
			first, _ := wave10SeenFirst(checkNameArgoCDAppStuck, sig, now)
			if now.Sub(first) >= argocdAppProgressingMinAge {
				reasons = append(reasons,
					fmt.Sprintf("progressing>%s", argocdAppProgressingMinAge))
			}
		}
		reasonSet := map[string]bool{}
		hasComparisonError := false
		for _, c := range shared.ReadyConds(app) {
			typ, _ := c["type"].(string)
			lower := strings.ToLower(typ)
			isCmp := strings.Contains(lower, "comparisonerror")
			isInvalid := strings.Contains(lower, "invalidspecerror")
			// ArgoCD ApplicationCondition has NO status field —
			// presence in status.conditions IS the active signal.
			if !isCmp && !isInvalid {
				continue
			}
			sig := "cond/" + ns + "/" + name + "/" + typ
			seenKeep[sig] = true
			// lastTransitionTime is the condition's own clock;
			// absent/malformed falls back to first-seen.
			age := time.Duration(0)
			known := false
			if ts, _ := c["lastTransitionTime"].(string); ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					age = now.Sub(t)
					known = true
				}
			}
			if !known {
				first, _ := wave10SeenFirst(checkNameArgoCDAppStuck, sig, now)
				age = now.Sub(first)
			}
			if age < argocdConditionMinAge {
				continue
			}
			if isCmp {
				reasonSet["comparison_error"] = true
				hasComparisonError = true
			} else {
				reasonSet["invalid_spec_error"] = true
			}
		}
		for r := range reasonSet {
			reasons = append(reasons, r)
		}
		if hasComparisonError {
			comparisonErrors++ // count APPS, not conditions
		}
		if len(reasons) == 0 {
			continue
		}
		sort.Strings(reasons)
		reason := strings.Join(reasons, "+")
		lv := []string{ns, name, reason}
		current[ns+"/"+name+"/"+reason] = lv
		wave10ArgoCDAppStuck.WithLabelValues(lv...).Set(1)
		stuck = append(stuck, fmt.Sprintf("%s/%s(%s)", ns, name, reason))
		p.wave10RefreshArgoCDApp(ctx, log, app, now)
	}
	wave10SeenPrune(checkNameArgoCDAppStuck, seenKeep)
	wave10ReconcileGauges(checkNameArgoCDAppStuck, wave10ArgoCDAppStuck, current)

	// >=2 simultaneous ComparisonErrors = shared stale repo-server
	// cache — restart the oldest repo-server pod to flush it.
	if comparisonErrors >= 2 {
		p.wave10RestartArgoCDRepoServer(ctx, log, now)
	}
	if len(stuck) == 0 {
		return probeResult{pass: true}
	}
	sort.Strings(stuck)
	return probeResult{why: "argocd applications stuck: " + strings.Join(stuck, ", ")}
}

// wave10RefreshArgoCDApp patches argocd.argoproj.io/refresh=hard on a
// stuck Application — 30m per-app cooldown on the shared ledger.
func (p *clusterHealthProber) wave10RefreshArgoCDApp(ctx context.Context,
	log logr.Logger, app *unstructured.Unstructured, now time.Time) {

	ck := "w10/" + checkNameArgoCDAppStuck + "/refresh/" +
		app.GetNamespace() + "/" + app.GetName()
	if p.wave10Cooled(ck, argocdRefreshCooldown, now) {
		return
	}
	payload := []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"hard"}}}`, argocdRefreshAnno))
	if _, err := p.dyn.Resource(argocdAppGVR).
		Namespace(app.GetNamespace()).Patch(ctx, app.GetName(),
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Error(err, "argocd refresh patch failed",
			"application", app.GetNamespace()+"/"+app.GetName())
		return
	}
	p.wave10MarkHealed(ck, now)
	log.Info("PATCH: argocd application refresh=hard",
		"application", app.GetNamespace()+"/"+app.GetName())
}

// wave10RestartArgoCDRepoServer deletes the OLDEST argocd-repo-server
// pod — repo-server caches repo state; >=2 ComparisonErrors at once
// is the stale-cache signature and one restart flushes it. Matched
// by the argocd-operator label scheme (app.kubernetes.io/name or
// component) with a name-prefix fallback.
func (p *clusterHealthProber) wave10RestartArgoCDRepoServer(ctx context.Context,
	log logr.Logger, now time.Time) {

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list pods failed — repo-server restart deferred",
			"error", err)
		return
	}
	var oldest *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Labels["app.kubernetes.io/name"] != "argocd-repo-server" &&
			pod.Labels["app.kubernetes.io/component"] != "repo-server" &&
			!strings.HasPrefix(pod.Name, "argocd-repo-server-") {
			continue
		}
		if oldest == nil ||
			pod.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = pod
		}
	}
	if oldest == nil {
		log.Info("argocd repo-server restart requested but no repo-server pod found")
		return
	}
	p.wave10DeletePod(ctx, log, checkNameArgoCDAppStuck,
		"repo-server/"+oldest.Namespace+"/"+oldest.Name,
		oldest, argocdRepoServerCool, now)
}

// ---------------------------------------------------------------------------
// W10-ST3 — rabbitmq-quorum-health
// ---------------------------------------------------------------------------

// wave10RabbitPod reports whether the pod belongs to a RabbitMQ
// cluster — the operator stamps app.kubernetes.io/part-of=rabbitmq
// (stable across per-cluster renames) and
// app.kubernetes.io/component=rabbitmq.
func wave10RabbitPod(pod *corev1.Pod) bool {
	return pod.Labels["app.kubernetes.io/part-of"] == "rabbitmq" ||
		pod.Labels["app.kubernetes.io/component"] == "rabbitmq"
}

// checkRabbitMQQuorumHealth watches RabbitMQ quorum/partition
// health two ways: Prometheus alarms (fd-limit / memory / disk
// watermarks, erlang dist node_state != connected) and the
// stuck-unready pod signature — a rabbitmq pod unready >=10m while
// >=2 siblings stay Ready gets deleted (30m cooldown) so the
// cluster re-forms quorum around it.
func (p *clusterHealthProber) checkRabbitMQQuorumHealth(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	rabbitByName := map[string]*corev1.Pod{}
	rabbitByPodName := map[string]*corev1.Pod{}
	rabbitByNS := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !wave10RabbitPod(pod) {
			continue
		}
		rabbitByName[pod.Namespace+"/"+pod.Name] = pod
		rabbitByPodName[pod.Name] = pod // ns fallback for series w/o namespace label
		rabbitByNS[pod.Namespace] = append(rabbitByNS[pod.Namespace], pod)
	}

	// Prometheus alarm/partition signals.
	type sig struct{ q, reason string }
	queries := []sig{
		{`rabbitmq_alarms_file_descriptor_limit == 1`, "fd_limit_alarm"},
		{`rabbitmq_alarms_memory_used_watermark == 1`, "memory_watermark_alarm"},
		{`rabbitmq_alarms_free_disk_space_watermark == 1`, "disk_watermark_alarm"},
		{`erlang_vm_dist_node_state != 3`, "mnesia_partition"},
	}
	findings := map[string]map[string]bool{} // "ns/pod" -> reasons
	for _, q := range queries {
		series, err := p.wave10PromQuery(ctx, q.q)
		if err != nil {
			log.Info("WARN: rabbitmq prom query failed — signal skipped",
				"query", q.q, "error", err)
			continue
		}
		for _, s := range series {
			podName := wave10PromLabel(s, "pod", "pod_name")
			ns := s.metric["namespace"]
			if ns == "" {
				if pod := rabbitByPodName[podName]; pod != nil {
					ns = pod.Namespace
				}
			}
			key := ns + "/" + podName
			if podName == "" {
				key = "cluster/" + q.reason
			}
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key][q.reason] = true
		}
	}

	// Ready-sibling census per namespace — the quorum precondition
	// for every heal below (>=2 OTHER replicas Ready).
	readyByNS := map[string]int{}
	for ns, members := range rabbitByNS {
		for _, pod := range members {
			if pod.DeletionTimestamp == nil &&
				pod.Status.Phase == corev1.PodRunning &&
				shared.PodReadyCond(pod) {
				readyByNS[ns]++
			}
		}
	}

	// Stuck-unready pod signature — independent of Prometheus.
	seenKeep := map[string]bool{}
	for ns, members := range rabbitByNS {
		for _, pod := range members {
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase == corev1.PodSucceeded ||
				pod.Status.Phase == corev1.PodFailed {
				continue
			}
			since, unready := wave10UnreadySince(pod)
			if !unready {
				continue
			}
			key := ns + "/" + pod.Name
			if now.Sub(since) < rabbitUnreadyMinAge {
				continue
			}
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key]["stuck_unready"] = true
			// Heal only when quorum survives: >=2 OTHER replicas
			// Ready — the unready pod itself is never Ready, so the
			// running-ready count already excludes it.
			if readyByNS[ns] >= 2 {
				p.wave10DeletePod(ctx, log, checkNameRabbitMQQuorum,
					key, pod, rabbitQuorumHealCool, now)
			}
		}
	}

	// Prometheus-flagged pods (alarm / Mnesia partition) get the same
	// heal once the signal persists >=10m and quorum survives — a
	// partitioned-but-Ready member is exactly the "partitioned >10m"
	// shape the plan calls out. The shared cooldown key dedupes pods
	// already healed via the unready path.
	for key := range findings {
		pod, ok := rabbitByName[key]
		if !ok || pod.DeletionTimestamp != nil {
			continue
		}
		sig := "prom/" + key
		seenKeep[sig] = true
		first, _ := wave10SeenFirst(checkNameRabbitMQQuorum, sig, now)
		if now.Sub(first) < rabbitUnreadyMinAge {
			continue
		}
		if readyByNS[pod.Namespace] >= 2 {
			p.wave10DeletePod(ctx, log, checkNameRabbitMQQuorum,
				key, pod, rabbitQuorumHealCool, now)
		}
	}
	wave10SeenPrune(checkNameRabbitMQQuorum, seenKeep)

	current := map[string][]string{}
	var out []string
	for key, reasons := range findings {
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		parts := strings.SplitN(key, "/", 2)
		ns := parts[0]
		if pod, ok := rabbitByName[key]; ok {
			lv := []string{ns, pod.Name, strings.Join(rs, "+")}
			current[key+"/"+strings.Join(rs, "+")] = lv
			wave10RabbitMQQuorumUnhealthy.WithLabelValues(lv...).Set(1)
		}
		out = append(out, key+"("+strings.Join(rs, "+")+")")
	}
	sort.Strings(out)
	wave10ReconcileGauges(checkNameRabbitMQQuorum,
		wave10RabbitMQQuorumUnhealthy, current)
	if len(out) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "rabbitmq quorum/partition signals: " +
		strings.Join(out, ", ")}
}

// ---------------------------------------------------------------------------
// W10-ST4 — dragonfly-replica-sync-storm
// ---------------------------------------------------------------------------

// wave10DragonflyPod reports whether the pod belongs to a
// Dragonfly/Valkey workload — app.kubernetes.io/name=dragonfly per
// the fluxcd shared-spec, with part-of/created-by fallbacks.
func wave10DragonflyPod(pod *corev1.Pod) bool {
	if pod.Labels["app.kubernetes.io/name"] == "dragonfly" ||
		pod.Labels["app.kubernetes.io/part-of"] == "dragonfly" ||
		pod.Labels["app.kubernetes.io/created-by"] == "dragonfly-operator" {
		return true
	}
	for _, v := range pod.Labels {
		if strings.Contains(v, "dragonfly") {
			return true
		}
	}
	return false
}

// checkDragonflyReplicaSyncStorm detects the replica full-sync
// storm: a replica's master link stays down (link_status==0 for the
// whole 5m window via first-seen persistence) while sync-full
// counters climb (>=3 per 15m) or connected-slaves oscillates.
// Only the DESYNCED REPLICA pod is restarted — never the master
// (podMasterRole on role/redis-role/app.kubernetes.io/role labels)
// — 30m cooldown.
func (p *clusterHealthProber) checkDragonflyReplicaSyncStorm(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	linkSeries, errL := p.wave10PromQuery(ctx,
		`(dragonfly_master_link_status == 0) or (redis_master_link_status == 0)`)
	if errL != nil {
		log.Info("WARN: dragonfly master-link query failed — check inconclusive",
			"error", errL)
		return probeResult{pass: true}
	}
	stormSeries, errS := p.wave10PromQuery(ctx,
		`(increase(dragonfly_sync_full[15m]) >= 3) or (changes(redis_connected_slaves[15m]) >= 3)`)
	// Storm evidence is scoped per namespace when the series carry
	// one — a sync storm in ns A must not authorize restarts of
	// desynced replicas in ns B. Series WITHOUT a namespace label
	// are cluster-wide evidence (can't disprove locality).
	stormNS := map[string]bool{}
	stormPods := map[string]bool{}
	stormGlobal := false
	stormActive := false
	if errS != nil {
		log.Info("WARN: dragonfly sync-storm query failed — storm unconfirmed",
			"error", errS)
	} else {
		stormActive = len(stormSeries) > 0
		for _, s := range stormSeries {
			if ns := wave10PromLabel(s, "namespace"); ns != "" {
				stormNS[ns] = true
			}
			if pn := wave10PromLabel(s, "pod", "pod_name"); pn != "" {
				if ns := wave10PromLabel(s, "namespace"); ns != "" {
					stormPods[ns+"/"+pn] = true
				} else {
					stormGlobal = true // pod label w/o ns — can't scope
				}
			} else if wave10PromLabel(s, "namespace") == "" {
				stormGlobal = true
			}
		}
	}

	// Pod census for master-role + ownership checks.
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	podByKey := map[string]*corev1.Pod{}
	for i := range pods.Items {
		podByKey[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = &pods.Items[i]
	}

	current := map[string][]string{}
	seenKeep := map[string]bool{}
	var desynced []string
	for _, s := range linkSeries {
		ns := wave10PromLabel(s, "namespace")
		name := wave10PromLabel(s, "pod", "pod_name")
		if ns == "" || name == "" {
			continue
		}
		key := ns + "/" + name
		sig := "link/" + key
		seenKeep[sig] = true
		first, _ := wave10SeenFirst(checkNameDragonflySyncStorm, sig, now)
		if now.Sub(first) < dragonflyLinkMinAge {
			continue // link down must persist the window
		}
		lv := []string{ns, name}
		current[key] = lv
		wave10DragonflyReplicaSyncStorm.WithLabelValues(lv...).Set(1)
		desynced = append(desynced, key)

		pod := podByKey[key]
		if pod == nil || pod.DeletionTimestamp != nil {
			continue
		}
		if podMasterRole(pod) {
			log.Info("skip heal: pod holds master role — never restart the master",
				"pod", key)
			continue
		}
		if !wave10DragonflyPod(pod) {
			log.Info("skip heal: pod not dragonfly-owned",
				"pod", key)
			continue
		}
		if !stormActive ||
			(!stormGlobal && !stormNS[ns] && !stormPods[key]) {
			continue // sustained link-down alone FAILs but doesn't restart
		}
		p.wave10DeletePod(ctx, log, checkNameDragonflySyncStorm,
			key, pod, dragonflySyncHealCool, now)
	}
	wave10SeenPrune(checkNameDragonflySyncStorm, seenKeep)
	sort.Strings(desynced)
	wave10ReconcileGauges(checkNameDragonflySyncStorm,
		wave10DragonflyReplicaSyncStorm, current)
	if len(desynced) == 0 {
		return probeResult{pass: true}
	}
	stormNote := "storm=confirmed"
	if !stormActive {
		stormNote = "storm=unconfirmed"
	}
	return probeResult{why: fmt.Sprintf(
		"dragonfly/valkey replicas with master-link down >%s (%s): %s",
		dragonflyLinkMinAge, stormNote, strings.Join(desynced, ", "))}
}

// ---------------------------------------------------------------------------
// W10-GI5 — image-pull-storm
// ---------------------------------------------------------------------------

// wave10PullWaitingReasons are the container waiting reasons that
// mean "the image cannot be pulled".
var wave10PullWaitingReasons = map[string]bool{
	"ImagePullBackOff":    true,
	"ErrImagePull":        true,
	"RegistryUnavailable": true,
}

// wave10RegistryOutageMarkers are message substrings that flip a
// pull failure from "one bad tag" to "the registry path is down" —
// rate-limit, proxy and Harbor-cache signatures.
var wave10RegistryOutageMarkers = []string{
	"toomanyrequests", "429", "proxyconnect tcp", "harbor",
}

// checkImagePullStorm scans all non-Succeeded pods for containers
// waiting in an image-pull failure >10m. One affected namespace is
// a workload problem (workload_image_pull_backoff); >=2 namespaces
// or a registry-outage message marker is a cluster pull outage
// (cluster_registry_pull_outage → ClusterImagePullStorm alert).
func (p *clusterHealthProber) checkImagePullStorm(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	type offender struct {
		ns, name, reason, message string
	}
	var offenders []offender
	namespaces := map[string]bool{}
	outage := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodSucceeded ||
			pod.DeletionTimestamp != nil {
			continue
		}
		checkState := func(state corev1.ContainerState) {
			w := state.Waiting
			if w == nil || !wave10PullWaitingReasons[w.Reason] {
				return
			}
			// ContainerStateWaiting carries no timestamp in the
			// Kubernetes API (the plan's waiting.startedAt does not
			// exist) — pod creation time is the sanctioned age
			// source, same convention as probePodRestarts: a pod
			// still waiting on its image >10m after creation is a
			// prolonged pull failure, not a slow first pull.
			if now.Sub(pod.CreationTimestamp.Time) < imagePullMinAge {
				return
			}
			offenders = append(offenders, offender{
				ns: pod.Namespace, name: pod.Name,
				reason: w.Reason, message: w.Message,
			})
			namespaces[pod.Namespace] = true
			lower := strings.ToLower(w.Message)
			for _, marker := range wave10RegistryOutageMarkers {
				if strings.Contains(lower, marker) {
					outage = true
					break
				}
			}
		}
		for _, s := range pod.Status.InitContainerStatuses {
			checkState(s.State)
		}
		for _, s := range pod.Status.ContainerStatuses {
			checkState(s.State)
		}
		for _, s := range pod.Status.EphemeralContainerStatuses {
			checkState(s.State)
		}
	}

	current := map[string][]string{}
	for _, o := range offenders {
		lv := []string{o.ns, o.name}
		current[o.ns+"/"+o.name] = lv
		wave10ImagePullBackoffPods.WithLabelValues(lv...).Set(1)
	}
	wave10ReconcileGauges(checkNameImagePullStorm,
		wave10ImagePullBackoffPods, current)
	if len(namespaces) >= 2 {
		outage = true
	}
	if outage {
		wave10RegistryPullOutage.Set(1)
	} else {
		wave10RegistryPullOutage.Set(0)
	}
	if len(offenders) == 0 {
		return probeResult{pass: true}
	}
	sort.Slice(offenders, func(i, j int) bool {
		if offenders[i].ns != offenders[j].ns {
			return offenders[i].ns < offenders[j].ns
		}
		return offenders[i].name < offenders[j].name
	})
	var summary []string
	for i, o := range offenders {
		if i >= 10 {
			summary = append(summary, "...")
			break
		}
		summary = append(summary, fmt.Sprintf("%s/%s:%s", o.ns, o.name, o.reason))
	}
	detail := "workload_image_pull_backoff"
	if outage {
		detail = "cluster_registry_pull_outage"
	}
	// offenders counts container-level waiting states — report the
	// distinct pod count instead.
	podSet := map[string]bool{}
	for _, o := range offenders {
		podSet[o.ns+"/"+o.name] = true
	}
	log.Info("image pull storm detected", "detail", detail,
		"namespaces", len(namespaces), "pods", len(podSet))
	return probeResult{why: fmt.Sprintf(
		"%s: %d pod(s) across %d namespace(s) waiting >%s: %s",
		detail, len(podSet), len(namespaces), imagePullMinAge,
		strings.Join(summary, ", "))}
}
