// cluster_health_probes.go — in-process port of the five kuberhealthy
// "passive" HealthChecks that used to run as periodic checker Pods in
// the kuberhealthy namespace (infrastructure/base/kuberhealthy/checks/
// in passiontech-fluxcd). The sixth check in that dir,
// cronjob-checker, is deliberately NOT ported — cronjob-catchup
// already sweeps CronJobs cluster-wide.
//
// A sixth in-process check rides along on the same sweep:
// kcm-workqueue-watchdog (C6) detects a kube-controller-manager whose
// leader Lease still renews while its object controllers stop
// reconciling — a "gray" failure a dead-KCM check cannot see. It is
// not a ported HealthCheck but reuses the same probe plumbing,
// reporting FAIL on its own kuberhealthy_check series plus the
// dedicated node_automation_kcm_workqueue_frozen{reason} gauge.
//
// Three more self-healing checks ride the same plumbing:
//   - operator-workqueue-watchdog (W5.8) generalizes the C6 shape to
//     third-party operators — cilium/scylla/dragonfly/flux controllers
//     holding a renewing Lease while their target CRs stay
//     unreconciled past a stuck threshold. On top of the
//     node_automation_operator_workqueue_frozen{operator,reason}
//     gauge it AUTO-HEALS: outside a maintenance window the stuck
//     leader pod is deleted (1h cooldown, persisted on the Lease) to
//     force re-election.
//   - stateful-masterless-services (W6.2) flags a master-role
//     Service (role/redis-role/app.kubernetes.io/role ∈
//     {master,primary,leader}) backed by a ready StatefulSet whose
//     EndpointSlices report 0 Ready endpoints for >=3m — past 5m a
//     Dragonfly STS additionally triggers a dragonfly-operator
//     leader delete (30m cooldown) to force re-election.
//   - rabbitmq-suspended-listener (W6.4) deletes RabbitMQ pods stuck
//     >=10m in the suspended-listener wedge (Running, every container
//     started but never Ready — port 5672 refused) once all peer
//     replicas are Ready, so quorum survives the pod kill.
//
// Metric contract: results go out on the SAME series kuberhealthy
// exported — kuberhealthy_check{check,namespace,status} and
// kuberhealthy_check_seconds_since_success{check,namespace} — under
// the original HealthCheck names and the literal "kuberhealthy"
// namespace label, so the KuberhealthyCheckFailed /
// KuberhealthyCheckStale PrometheusRule alerts keep firing with zero
// PromQL or dashboard changes.
//
// Error accounting: a check FAIL is the product — it is reported via
// metrics and logged, never as a run error. Only apiserver/client
// failures count against the queue's run-error counters (IncError,
// same pattern as cronjob-catchup's dedupe List). A cancelled sweep
// context (SIGTERM mid-cycle) aborts the run silently — it is a
// shutdown, not a health signal, so no FAIL series and no run error
// are emitted for it.
package clusterhealthprobes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const clusterHealthQueue = "cluster-health-probes"

// Check names — the exact HealthCheck metadata.name values the
// replaced kuberhealthy checks carried; they are the `check` label
// values alerts and dashboards key on. kcm-workqueue-watchdog is the
// exception: not a ported HealthCheck, it is the C6 watchdog — it
// still reports on the same series under its own check name so the
// generic FAIL alerting path covers it too.
const (
	checkNameDNS           = "dns-status-internal"
	checkNameHTTPContent   = "http-content-check"
	checkNamePodRestarts   = "pod-restarts"
	checkNamePodStatus     = "pod-status-check"
	checkNameResourceQuota = "resource-quota-check"
	checkNameKCMWorkqueue  = "kcm-workqueue-watchdog"
	// W5.8/W6.2/W6.4 — the self-healing checks riding the same
	// plumbing; like the KCM watchdog they are not ported
	// HealthChecks but report under their own check names so the
	// generic FAIL alerting path covers them.
	checkNameOperatorWorkqueue  = "operator-workqueue-watchdog"
	checkNameStatefulMasterless = "stateful-masterless-services"
	checkNameRabbitMQSuspended  = "rabbitmq-suspended-listener"
)

// C6 watchdog knobs — the KCM leader Lease name and the
// node_automation_kcm_workqueue_frozen{reason} label values.
const (
	kcmLeaseName         = "kube-controller-manager"
	kcmReasonDesiredZero = "daemonset_desired_zero"
	kcmReasonStaleGen    = "stale_observed_generation"
)

// W5.8 — operator-workqueue-watchdog knobs.
const (
	// operatorLeaseMaxAge bounds "still renewing": operator
	// leader-election renews every ~2s inside a ~15s duration, so a
	// renewTime older than 2m means the holder is GONE — a dead
	// operator, not a frozen one (pod-status checks cover that
	// failure class).
	operatorLeaseMaxAge = 2 * time.Minute
	// operatorHealCooldown bounds leader-pod deletes to one per
	// operator per hour — the wider of the in-RAM ledger and the
	// persisted node.ops/last-operator-heal stamp on the Lease
	// (same wider-of-both shape as the helmrelease-unlocker).
	operatorHealCooldown = time.Hour
	// operatorHealAnno persists the last heal moment on the
	// operator's leader-election Lease — the restart-proof half of
	// the cooldown.
	operatorHealAnno = "node.ops/last-operator-heal"
	// ciliumStuckMinAge is the stuck window for the gateway-API
	// resources cilium-operator reconciles.
	ciliumStuckMinAge = 10 * time.Minute
	// operatorStuckMinAge is the default stuck window for the other
	// watched operators.
	operatorStuckMinAge = 20 * time.Minute
	// opReasonStaleGWStatus is the cilium signature: a gateway-API
	// object whose status.parents is empty/absent or whose
	// observedGeneration lags — the gateway controller never
	// attached it.
	opReasonStaleGWStatus = "stale_gateway_status"
)

// W6.2 — stateful-masterless-services knobs.
const (
	// masterlessZeroMinAge: a master-role Service must report 0
	// Ready endpoints this long before the gauge fires.
	masterlessZeroMinAge = 3 * time.Minute
	// masterlessHealMinAge: the zero-endpoint streak must reach this
	// before the dragonfly-operator leader gets bounced (5m —
	// longer than the gauge so a flap doesn't kill the operator).
	masterlessHealMinAge  = 5 * time.Minute
	dragonflyHealCooldown = 30 * time.Minute
	// dragonflyOperatorNS/PodPrefix locate the operator pods the
	// heal deletes to force re-election.
	dragonflyOperatorNS        = "dragonfly-operator-system"
	dragonflyOperatorPodPrefix = "dragonfly-operator-controller-manager"
	// dragonflyHealAnno persists the last heal moment on the STS —
	// the restart-proof half of the cooldown.
	dragonflyHealAnno = "node.ops/last-dragonfly-operator-heal"
)

// W6.4 — rabbitmq-suspended-listener knobs.
const (
	rabbitComponentLabel  = "app.kubernetes.io/component=rabbitmq"
	rabbitSuspendedMinAge = 10 * time.Minute
	rabbitHealCooldown    = 30 * time.Minute
)

// healthListPageSize bounds the cluster-wide EndpointSlice list the
// masterless check pages through — same pagination posture as the
// webhook guard's census.
const healthListPageSize = 500

// healthProbeConfig carries the HEALTH_* env knobs the checker Pods
// read (HOSTNAME/TARGET_URL/MAX_FAILURES_ALLOWED/...), re-homed under
// a HEALTH_ prefix. Defaults match the live check manifests.
type healthProbeConfig struct {
	dnsHostnames        []string      // HEALTH_DNS_HOSTNAMES
	checkTimeout        time.Duration // HEALTH_CHECK_TIMEOUT
	httpURL             string        // HEALTH_HTTP_CONTENT_URL
	httpExpectedContent string        // HEALTH_HTTP_EXPECTED_CONTENT
	podCheckNamespace   string        // HEALTH_POD_CHECK_NAMESPACE
	maxPodRestarts      int32         // HEALTH_MAX_POD_RESTARTS
	podSkipDuration     time.Duration // HEALTH_POD_SKIP_DURATION
	quotaThreshold      float64       // HEALTH_RESOURCE_QUOTA_THRESHOLD
	kcmLeaseMaxAge      time.Duration // HEALTH_KCM_LEASE_MAX_AGE
	kcmFreezeMinAge     time.Duration // HEALTH_KCM_FREEZE_MIN_AGE
}

func healthEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// healthEnvDuration parses a duration env knob, warning + defaulting
// on two failure shapes: unparseable values (typos, unit-less numbers)
// and non-positive durations — a 0s/negative check timeout would make
// every probe fail instantly, and a 0s interval would panic the
// periodic ticker registration downstream.
func healthEnvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env duration — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	if d <= 0 {
		logf.Log.WithName(clusterHealthQueue).Info(
			"non-positive env duration — using default", "key", key,
			"value", v, "default", def)
		return def
	}
	return d
}

// healthEnvInt parses an integer env knob, warning + defaulting on
// unparseable values and negatives — e.g. HEALTH_MAX_POD_RESTARTS=-1
// would flag every container as over-limit.
func healthEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env int — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	if n < 0 {
		logf.Log.WithName(clusterHealthQueue).Info(
			"negative env int — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	return n
}

// healthEnvFloat parses a float env knob, warning + defaulting on
// unparseable values (a garbage threshold string must not silently
// collapse to the default without an operator-visible note).
func healthEnvFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		// Non-positive thresholds are never meaningful (a <=0
		// quota threshold flags EVERYTHING); >1 is kept as the
		// operator's documented "disable this check" escape.
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env float — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	return f
}

// healthProbeConfigFromEnv resolves the check knobs once at Setup.
// The live manifests are the ground truth for the defaults (e.g.
// http-content-check TARGET_URL is the prometheus /-/healthy
// endpoint, not alertmanager).
func healthProbeConfigFromEnv() healthProbeConfig {
	// Second hostname is a ClusterIP Service (DNS record exists
	// regardless of backend pod readiness) — a headless service like
	// alertmanager-operated NXDOMAINs whenever its single pod is
	// recreating, which would flap the DNS check during every
	// alertmanager rollout despite CoreDNS being fine.
	hosts := strings.Split(healthEnv("HEALTH_DNS_HOSTNAMES",
		"kubernetes.default.svc.cluster.local,"+
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local"), ",")
	trimmed := hosts[:0]
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			trimmed = append(trimmed, h)
		}
	}
	return healthProbeConfig{
		dnsHostnames:        trimmed,
		checkTimeout:        healthEnvDuration("HEALTH_CHECK_TIMEOUT", 30*time.Second),
		httpURL:             healthEnv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
		httpExpectedContent: healthEnv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
		podCheckNamespace:   healthEnv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
		maxPodRestarts:      int32(healthEnvInt("HEALTH_MAX_POD_RESTARTS", 10)),
		podSkipDuration:     healthEnvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
		quotaThreshold:      healthEnvFloat("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
		// KCM leader-election defaults are LeaseDuration 15s,
		// RenewDeadline 10s, RetryPeriod ~2s, so a live holder's
		// renewTime is never more than a few seconds old. 30s — 2×
		// the lease duration — bounds "still renewing" with margin
		// for apiserver latency; anything older means the holder is
		// gone (a dead KCM, not a frozen one).
		kcmLeaseMaxAge: healthEnvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
		// A freeze signature must persist this long before the gauge
		// fires — a healthy reconcile legitimately lags a spec write
		// by a sync period or two.
		kcmFreezeMinAge: healthEnvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
	}
}

// probeResult is one check's verdict. pass=false + infra=nil is an
// observed health failure (the metric's FAIL=1); infra!=nil is a
// client/apiserver error — the check is still marked FAIL (it did not
// succeed) but the error also counts against the queue run errors.
type probeResult struct {
	pass  bool
	why   string
	infra error
}

type clusterHealthProber struct {
	cs kubernetes.Interface
	// dyn reads the CRD types the W5.8 stuck signatures scan
	// (gateway-api, scylladb, dragonflydb, flux) and the autopilot
	// Plan inside the maintenance mutex — no typed clients exist.
	dyn dynamic.Interface
	cfg healthProbeConfig
	// lookupHost is the DNS seam (tests inject a fake; production uses
	// the default resolver — in-cluster CoreDNS via /etc/resolv.conf).
	lookupHost func(ctx context.Context, host string) ([]string, error)
	httpClient *http.Client
	now        func() time.Time

	// lastPass tracks the last OK per check name for the
	// seconds_since_success gauge — seeded to boot time so a check
	// that never passed still reports a growing staleness, matching
	// kuberhealthy (which counts from check creation).
	mu       sync.Mutex
	lastPass map[string]time.Time

	// C6 watchdog state (under mu):
	//   - kcmFirstSeen: signature key "<reason>/<kind>/<name>" → the
	//     first sweep that observed it; a signature must persist
	//     kcmFreezeMinAge before the gauge fires. Pruned when the
	//     signature resolves — a later stall re-arms the window.
	//   - kcmFrozenReasons: reason labels currently held at 1, so a
	//     resolved signature flips its series back to 0 instead of
	//     leaking a stale 1 forever.
	kcmFirstSeen     map[string]time.Time
	kcmFrozenReasons map[string]bool

	// W5.8 watchdog state (under mu):
	//   - opFirstSeen: "operator/<gvr>/<ns>/<name>" → first sweep
	//     that saw the stuck signature; it must persist the
	//     operator's stuckMinAge before the gauge fires. Pruned when
	//     the object reconciles — a later stall re-arms the window.
	//   - opFrozen: "operator/reason" currently held at 1, so a
	//     resolved signature flips the series back to 0.
	//   - opHealed: operator → last leader-pod delete — the in-RAM
	//     half of the 1h heal cooldown (the Lease annotation is the
	//     durable half).
	opFirstSeen map[string]time.Time
	opFrozen    map[string]bool
	opHealed    map[string]time.Time

	// W6.2 watchdog state (under mu):
	//   - stsZeroSince: "ns/svc/sts" → first sweep the master-role
	//     Service showed 0 Ready endpoints.
	//   - stsZeroEmitted: series ledger for
	//     StatefulServiceZeroEndpoints — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1 (same hygiene as the
	//     webhook guard's brokenEmitted).
	//   - drHealed: operator pod "ns/name" → last delete — the
	//     in-RAM half of the 30m dragonfly heal cooldown (the STS
	//     annotation stamp is the durable half).
	stsZeroSince   map[string]time.Time
	stsZeroEmitted map[string]bool
	drHealed       map[string]time.Time

	// W6.4 watchdog state (under mu):
	//   - rbSuspendedSince: "ns/pod/uid" → first sweep the pod
	//     showed the suspended-listener signature (uid in the key
	//     keeps a same-named replacement from inheriting the streak).
	//   - rbHealed: "ns/pod" → last delete — the 30m heal cooldown.
	rbSuspendedSince map[string]time.Time
	rbHealed         map[string]time.Time
}

func newClusterHealthProber(cs kubernetes.Interface, dyn dynamic.Interface, cfg healthProbeConfig) *clusterHealthProber {
	boot := time.Now()
	return &clusterHealthProber{
		cs:         cs,
		dyn:        dyn,
		cfg:        cfg,
		lookupHost: (&net.Resolver{}).LookupHost,
		httpClient: &http.Client{},
		now:        time.Now,
		lastPass: map[string]time.Time{
			checkNameDNS:                boot,
			checkNameHTTPContent:        boot,
			checkNamePodRestarts:        boot,
			checkNamePodStatus:          boot,
			checkNameResourceQuota:      boot,
			checkNameKCMWorkqueue:       boot,
			checkNameOperatorWorkqueue:  boot,
			checkNameStatefulMasterless: boot,
			checkNameRabbitMQSuspended:  boot,
		},
		kcmFirstSeen:     map[string]time.Time{},
		kcmFrozenReasons: map[string]bool{},
		opFirstSeen:      map[string]time.Time{},
		opFrozen:         map[string]bool{},
		opHealed:         map[string]time.Time{},
		stsZeroSince:     map[string]time.Time{},
		stsZeroEmitted:   map[string]bool{},
		drHealed:         map[string]time.Time{},
		rbSuspendedSince: map[string]time.Time{},
		rbHealed:         map[string]time.Time{},
	}
}

// Setup registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the gate lives in
// CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false" opts
// out); disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern. dyn feeds the CRD scans inside the
// self-healing checks (W5.8/W6.2) — wired like every other
// dynamic-client module.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(clusterHealthQueue).Info("disabled — module not registered")
		return nil
	}
	p := newClusterHealthProber(cs, dyn, healthProbeConfigFromEnv())
	interval := healthEnvDuration("CLUSTER_HEALTH_PROBES_INTERVAL", 5*time.Minute)
	// Surface the resolved HEALTH_* knobs once at registration so an
	// operator can tell from the logs which targets/thresholds the
	// checks run with (an unparseable env value silently falls back
	// to the default — the effective value is what matters here).
	logf.Log.WithName(clusterHealthQueue).Info("registered",
		"interval", interval, "dnsHostnames", p.cfg.dnsHostnames,
		"checkTimeout", p.cfg.checkTimeout, "httpURL", p.cfg.httpURL,
		"httpExpectedContent", p.cfg.httpExpectedContent,
		"podCheckNamespace", p.cfg.podCheckNamespace,
		"maxPodRestarts", p.cfg.maxPodRestarts,
		"podSkipDuration", p.cfg.podSkipDuration,
		"quotaThreshold", p.cfg.quotaThreshold,
		"kcmLeaseMaxAge", p.cfg.kcmLeaseMaxAge,
		"kcmFreezeMinAge", p.cfg.kcmFreezeMinAge)
	return shared.AddPeriodic(mgr, clusterHealthQueue, interval, p.run)
}

func (p *clusterHealthProber) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	checks := []struct {
		name  string
		probe func(ctx context.Context) probeResult
	}{
		{checkNameDNS, p.probeDNS},
		{checkNameHTTPContent, p.probeHTTPContent},
		{checkNamePodRestarts, p.probePodRestarts},
		{checkNamePodStatus, p.probePodStatus},
		{checkNameResourceQuota, p.probeResourceQuota},
		{checkNameKCMWorkqueue, p.checkKCMWorkqueue},
		{checkNameOperatorWorkqueue, p.checkOperatorWorkqueues},
		{checkNameStatefulMasterless, p.checkStatefulMasterlessServices},
		{checkNameRabbitMQSuspended, p.checkRabbitMQSuspendedPods},
	}
	for _, c := range checks {
		res := c.probe(ctx)
		// A cancelled sweep context (SIGTERM during rollout/shutdown)
		// is not a health signal: emitting FAIL=1 or a run error now
		// would leave fake series behind on the dying pod. Bail out
		// silently — the surviving leader's next cycle reports.
		if ctx.Err() != nil {
			return nil
		}
		p.report(c.name, res.pass)
		// A check FAIL is the product — it is reported via metrics and
		// logged, never as a run error. Only apiserver/client failures
		// count against the queue's run-error counters.
		if res.infra != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(res.infra, "health check probe errored — marked FAIL",
				"check", c.name)
		} else if !res.pass {
			log.Info("health check FAIL", "check", c.name, "reason", res.why)
		}
	}
	return nil
}

// report updates the kuberhealthy-compatible series for one check.
func (p *clusterHealthProber) report(name string, ok bool) {
	p.mu.Lock()
	now := p.now()
	if ok {
		p.lastPass[name] = now
	}
	since := now.Sub(p.lastPass[name]).Seconds()
	p.mu.Unlock()
	metrics.ObserveHealthCheck(name, ok, since)
}

// probeDNS ports dns-resolution-check: every configured hostname must
// resolve. Per-check timeout comes from HEALTH_CHECK_TIMEOUT (the
// checker pod's TIMEOUT_DURATION was 30s).
func (p *clusterHealthProber) probeDNS(ctx context.Context) probeResult {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.checkTimeout)
	defer cancel()
	for _, host := range p.cfg.dnsHostnames {
		if _, err := p.lookupHost(ctx, host); err != nil {
			return probeResult{why: fmt.Sprintf("lookup %s: %v", host, err)}
		}
	}
	return probeResult{pass: true}
}

// probeHTTPContent ports http-content-check: GET must return 200 and
// a body containing the expected string (live check: prometheus
// /-/healthy answers "Prometheus Server is Healthy.", expected
// substring "Healthy").
func (p *clusterHealthProber) probeHTTPContent(ctx context.Context) probeResult {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.checkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.httpURL, nil)
	if err != nil {
		return probeResult{why: fmt.Sprintf("build request: %v", err)}
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return probeResult{why: fmt.Sprintf("GET %s: %v", p.cfg.httpURL, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return probeResult{why: fmt.Sprintf("GET %s: status %d, want 200",
			p.cfg.httpURL, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return probeResult{why: fmt.Sprintf("read body: %v", err)}
	}
	if !strings.Contains(string(body), p.cfg.httpExpectedContent) {
		return probeResult{why: fmt.Sprintf("body missing %q",
			p.cfg.httpExpectedContent)}
	}
	return probeResult{pass: true}
}

// probePodRestarts ports pod-restarts-check: FAIL when any container
// status — app, init or ephemeral — in the target namespace has
// RestartCount over the limit (live check: kube-system, 10).
func (p *clusterHealthProber) probePodRestarts(ctx context.Context) probeResult {
	pods, err := p.cs.CoreV1().Pods(p.cfg.podCheckNamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods in %s: %w",
			p.cfg.podCheckNamespace, err)}
	}
	var offenders []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, statuses := range [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
			pod.Status.EphemeralContainerStatuses,
		} {
			for _, s := range statuses {
				if s.RestartCount > p.cfg.maxPodRestarts {
					offenders = append(offenders,
						fmt.Sprintf("%s/%s=%d", pod.Name, s.Name, s.RestartCount))
				}
			}
		}
	}
	if len(offenders) > 0 {
		return probeResult{why: fmt.Sprintf("restarts>%d: %s",
			p.cfg.maxPodRestarts, strings.Join(offenders, ", "))}
	}
	return probeResult{pass: true}
}

// probePodStatus ports pod-status-check: pods younger than
// SKIP_DURATION are ignored (fresh pods legitimately sit Pending while
// images pull); any older pod whose Phase is not Running or Succeeded
// is a FAIL (Failed/Unknown/stuck Pending).
func (p *clusterHealthProber) probePodStatus(ctx context.Context) probeResult {
	pods, err := p.cs.CoreV1().Pods(p.cfg.podCheckNamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods in %s: %w",
			p.cfg.podCheckNamespace, err)}
	}
	var bad []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if p.now().Sub(pod.CreationTimestamp.Time) < p.cfg.podSkipDuration {
			continue // too young — still allowed to be Pending
		}
		if pod.Status.Phase != corev1.PodRunning &&
			pod.Status.Phase != corev1.PodSucceeded {
			bad = append(bad, fmt.Sprintf("%s=%s", pod.Name, pod.Status.Phase))
		}
	}
	if len(bad) > 0 {
		return probeResult{why: fmt.Sprintf("non-Running pods in %s: %s",
			p.cfg.podCheckNamespace, strings.Join(bad, ", "))}
	}
	return probeResult{pass: true}
}

// probeResourceQuota ports resource-quota-check: FAIL when any quota
// resource's used/hard ratio exceeds the threshold (live check:
// THRESHOLD=0.9 — strictly greater, so exactly-at-threshold passes).
// A resource absent from Status.Used counts as 0.
func (p *clusterHealthProber) probeResourceQuota(ctx context.Context) probeResult {
	quotas, err := p.cs.CoreV1().ResourceQuotas(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list resourcequotas: %w", err)}
	}
	var over []string
	for i := range quotas.Items {
		q := &quotas.Items[i]
		for name, hard := range q.Status.Hard {
			used, ok := q.Status.Used[name]
			if !ok {
				continue // no usage recorded — 0/hard is a pass
			}
			// hard=0 + used>0 divides to +Inf -> over; 0/0 is NaN
			// which compares false -> pass. Only `>` fails: exactly
			// at threshold is still a pass.
			ratio := used.AsApproximateFloat64() / hard.AsApproximateFloat64()
			if ratio > p.cfg.quotaThreshold {
				over = append(over, fmt.Sprintf("%s/%s %s=%s/%s",
					q.Namespace, q.Name, name, used.String(), hard.String()))
			}
		}
	}
	if len(over) > 0 {
		return probeResult{why: fmt.Sprintf("quota used/hard>%.2g: %s",
			p.cfg.quotaThreshold, strings.Join(over, ", "))}
	}
	return probeResult{pass: true}
}

// ---------------------------------------------------------------------------
// kcm-workqueue-watchdog (C6)
// ---------------------------------------------------------------------------

// checkKCMWorkqueue detects a kube-controller-manager workqueue
// freeze: the leader still renews its coordination.k8s.io Lease but
// the object controllers stop reconciling — a "gray" failure where
// /healthz and the leader lock stay green while cluster objects go
// stale (the incident class behind this watchdog).
//
// Preconditions, quiet on miss — the frozen-but-leader case is the
// ONLY thing this check flags:
//   - at least one Ready Node (the storm gate: with no Ready node a
//     desiredNumberScheduled==0 reading is ambiguous, and a dead
//     cluster is covered by other checks);
//   - the kube-system/kube-controller-manager Lease is still renewing
//     (renewTime no older than kcmLeaseMaxAge — KCM leader-election
//     renews every ~2s inside a 15s LeaseDuration). A stale or absent
//     Lease means the holder is GONE: a dead KCM is a different
//     failure pod-status/dead-node checks already cover, and flagging
//     it here would double-alert the wrong diagnosis.
//
// Freeze signatures (kube-system objects), each required to persist
// continuously for kcmFreezeMinAge via a per-object first-seen map:
//   - daemonset_desired_zero: a DaemonSet reports
//     status.desiredNumberScheduled==0 while pods are still
//     scheduled/ready — the DS controller stopped recomputing desired
//     from live nodes. desired==0 with zero pods anywhere is a
//     legitimately-empty selector, not a freeze, so it is excluded.
//   - stale_observed_generation: a Deployment or DaemonSet whose
//     status.observedGeneration lags metadata.generation — its
//     controller never processed the last spec write.
//
// On freeze the dedicated gauge
// node_automation_kcm_workqueue_frozen{reason} goes to 1; it flips
// back to 0 when the signature resolves (or when the preconditions
// stop holding — resetKCMWorkqueue re-arms tracking from scratch).
func (p *clusterHealthProber) checkKCMWorkqueue(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	ready := false
	for i := range nodes {
		if shared.NodeReady(&nodes[i]) {
			ready = true
			break
		}
	}
	if !ready {
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	}

	lease, err := p.cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Get(ctx, kcmLeaseName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// No leader Lease at all — no elected KCM to judge.
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	case err != nil:
		return probeResult{infra: fmt.Errorf("get lease %s/%s: %w",
			metav1.NamespaceSystem, kcmLeaseName, err)}
	case lease.Spec.RenewTime == nil ||
		now.Sub(lease.Spec.RenewTime.Time) > p.cfg.kcmLeaseMaxAge:
		// Stale renewTime = the holder is gone — a dead KCM, not a
		// frozen one. Stay quiet.
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	}

	dss, err := p.cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list daemonsets in %s: %w",
			metav1.NamespaceSystem, err)}
	}
	deps, err := p.cs.AppsV1().Deployments(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list deployments in %s: %w",
			metav1.NamespaceSystem, err)}
	}

	// Candidate signatures keyed "<reason>/<kind>/<name>" so each
	// object's persistence window is tracked independently.
	sigs := map[string]string{}
	for i := range dss.Items {
		ds := &dss.Items[i]
		if ds.Status.DesiredNumberScheduled == 0 &&
			(ds.Status.CurrentNumberScheduled+
				ds.Status.UpdatedNumberScheduled+
				ds.Status.NumberReady+
				ds.Status.NumberMisscheduled) > 0 {
			sigs[kcmReasonDesiredZero+"/daemonset/"+ds.Name] = kcmReasonDesiredZero
		}
		if ds.Status.ObservedGeneration < ds.Generation {
			sigs[kcmReasonStaleGen+"/daemonset/"+ds.Name] = kcmReasonStaleGen
		}
	}
	for i := range deps.Items {
		dep := &deps.Items[i]
		if dep.Status.ObservedGeneration < dep.Generation {
			sigs[kcmReasonStaleGen+"/deployment/"+dep.Name] = kcmReasonStaleGen
		}
	}

	p.mu.Lock()
	frozen := map[string]bool{}
	for sig, reason := range sigs {
		if _, ok := p.kcmFirstSeen[sig]; !ok {
			p.kcmFirstSeen[sig] = now
			log.Info("KCM freeze signature — tracking first-seen",
				"signature", sig)
			continue
		}
		if now.Sub(p.kcmFirstSeen[sig]) >= p.cfg.kcmFreezeMinAge {
			frozen[reason] = true
		}
	}
	for sig := range p.kcmFirstSeen {
		if _, ok := sigs[sig]; !ok {
			delete(p.kcmFirstSeen, sig)
		}
	}
	for reason := range p.kcmFrozenReasons {
		if !frozen[reason] {
			metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
			delete(p.kcmFrozenReasons, reason)
		}
	}
	for reason := range frozen {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(1)
		p.kcmFrozenReasons[reason] = true
	}
	p.mu.Unlock()

	if len(frozen) == 0 {
		return probeResult{pass: true}
	}
	reasons := make([]string, 0, len(frozen))
	for r := range frozen {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return probeResult{why: fmt.Sprintf(
		"KCM lease renews but kube-system objects unreconciled >=%s: %s",
		p.cfg.kcmFreezeMinAge, strings.Join(reasons, ", "))}
}

// resetKCMWorkqueue clears freeze tracking and drops any held gauge —
// called when the frozen-but-leader diagnosis cannot apply (no Ready
// nodes, absent/stale KCM Lease) so a signature that flaps around a
// precondition edge re-arms its persistence window from scratch.
func (p *clusterHealthProber) resetKCMWorkqueue() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.kcmFirstSeen)
	for reason := range p.kcmFrozenReasons {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
		delete(p.kcmFrozenReasons, reason)
	}
}

// ---------------------------------------------------------------------------
// operator-workqueue-watchdog (W5.8) — lease-holding zombie detector
// + auto-healer.
// ---------------------------------------------------------------------------

// opStuckResource binds a watched CRD GVR to its stall signature: the
// reason label reported on OperatorWorkqueueFrozen and the predicate
// deciding whether one object counts as unreconciled.
type opStuckResource struct {
	gvr    schema.GroupVersionResource
	reason string
	stuck  func(o *unstructured.Unstructured) bool
}

// operatorTarget is one watched operator: the leader-election Lease
// proving liveness, the pod label selector resolving the holder to a
// pod when holderIdentity parsing fails, the stuck persistence window
// and the CRD resources it is responsible for reconciling.
type operatorTarget struct {
	name        string
	leaseNS     string
	leaseName   string
	podSelector string
	stuckMinAge time.Duration
	resources   []opStuckResource
}

// staleObservedGeneration is the canonical "controller never saw the
// last spec write" signature: status.observedGeneration lags
// metadata.generation. A missing observedGeneration reads as 0 — an
// object never touched by its controller is the strongest stuck
// signal there is (generation >= 1 for any real object).
func staleObservedGeneration(o *unstructured.Unstructured) bool {
	og, _, _ := unstructured.NestedInt64(o.Object, "status", "observedGeneration")
	return og < o.GetGeneration()
}

// fluxUnsuspendedStaleGen is staleObservedGeneration with the flux
// parking brake honored: a spec.suspend=true object is deliberately
// not reconciled — suspended work is parked, not stuck.
func fluxUnsuspendedStaleGen(o *unstructured.Unstructured) bool {
	if suspended, _, _ := unstructured.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false
	}
	return staleObservedGeneration(o)
}

// gatewayStatusStuck is the cilium-operator signature on the
// gateway-API route resources its gateway controller reconciles: an
// object reporting no status.parents (the controller attaches a
// parent status when it programs the route) or a lagging
// observedGeneration.
func gatewayStatusStuck(o *unstructured.Unstructured) bool {
	if staleObservedGeneration(o) {
		return true
	}
	parents, found, _ := unstructured.NestedSlice(o.Object, "status", "parents")
	return !found || len(parents) == 0
}

// gatewayObjectStuck is the same signature for the Gateway kind
// itself: Gateways carry status.listeners, not status.parents — the
// route predicate would flag every healthy Gateway forever. A
// programmed Gateway reports one status.listeners entry per
// spec.listeners entry; a spec with listeners but an empty/absent
// status.listeners means the controller never programmed it.
func gatewayObjectStuck(o *unstructured.Unstructured) bool {
	if staleObservedGeneration(o) {
		return true
	}
	spec, found, _ := unstructured.NestedSlice(o.Object, "spec", "listeners")
	if !found || len(spec) == 0 {
		return false
	}
	status, found, _ := unstructured.NestedSlice(o.Object, "status", "listeners")
	return !found || len(status) == 0
}

// gwv1 is the gateway.networking.k8s.io/v1 group shared by the three
// resources the cilium signature scans.
func gwv1(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: resource}
}

var operatorTargets = []operatorTarget{
	{
		name:        "cilium-operator",
		leaseNS:     "kube-system",
		leaseName:   "cilium-operator-resource-lock",
		podSelector: "io.cilium/app=operator",
		stuckMinAge: ciliumStuckMinAge,
		resources: []opStuckResource{
			{gvr: gwv1("gateways"), reason: opReasonStaleGWStatus, stuck: gatewayObjectStuck},
			{gvr: gwv1("httproutes"), reason: opReasonStaleGWStatus, stuck: gatewayStatusStuck},
			{gvr: gwv1("grpcroutes"), reason: opReasonStaleGWStatus, stuck: gatewayStatusStuck},
		},
	},
	{
		name:        "scylla-operator",
		leaseNS:     "scylla-operator",
		leaseName:   "scylla-operator-lock",
		podSelector: "app.kubernetes.io/name=scylla-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "dragonfly-operator",
		leaseNS:     dragonflyOperatorNS,
		leaseName:   "7898635c.dragonflydb.io",
		podSelector: "control-plane=controller-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "dragonflydb.io", Version: "v1alpha1", Resource: "dragonflies"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "helm-controller",
		leaseNS:     "flux-system",
		leaseName:   "helm-controller-leader-election",
		podSelector: "app=helm-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	{
		name:        "kustomize-controller",
		leaseNS:     "flux-system",
		leaseName:   "kustomize-controller-leader-election",
		podSelector: "app=kustomize-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"},
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
}

// checkOperatorWorkqueues detects a lease-holding zombie operator:
// the leader still renews its coordination.k8s.io Lease while its
// target CRs sit unreconciled — the C6 gray-failure shape, but for
// the third-party operators whose stuck queues the flux/gitops stack
// depends on. Quiet on miss in the same cases as the KCM watchdog:
// no Lease or a stale renewTime means the holder is gone (a dead
// operator is a different failure pod-status checks already cover).
//
// Dual mechanism per stuck operator:
//
//	a) AUTO-HEAL — past the stuck window and outside maintenance,
//	   healOperatorLeader resolves the holderIdentity to the leader
//	   pod and deletes it (1h cooldown, persisted on the Lease),
//	   forcing re-election onto a fresh replica.
//	b) ALERTING — OperatorWorkqueueFrozen{operator,reason}=1 stays
//	   set while the CRs remain unreconciled, so a PrometheusRule
//	   fires if healing did not unstick the queue.
func (p *clusterHealthProber) checkOperatorWorkqueues(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — operator workqueue check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.opFirstSeen == nil {
		p.opFirstSeen = map[string]time.Time{}
	}
	if p.opFrozen == nil {
		p.opFrozen = map[string]bool{}
	}
	if p.opHealed == nil {
		p.opHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	frozen := map[string]string{} // "operator/reason" → reason, for the why line
	var firstErr error
	for _, op := range operatorTargets {
		lease, err := p.cs.CoordinationV1().Leases(op.leaseNS).
			Get(ctx, op.leaseName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			// No leader Lease — no elected operator to judge.
			p.resetOperator(op.name)
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("get lease %s/%s (%s): %w",
					op.leaseNS, op.leaseName, op.name, err)
			}
			continue
		case lease.Spec.RenewTime == nil ||
			now.Sub(lease.Spec.RenewTime.Time) > operatorLeaseMaxAge:
			// Stale renewTime = the holder is gone — a dead
			// operator, not a frozen one. Stay quiet.
			p.resetOperator(op.name)
			continue
		}

		// Collect this operator's live stuck signatures — keyed
		// "operator/<gvr>/<ns>/<name>" so each object's persistence
		// window is tracked independently.
		live := map[string]bool{}
		reasonsFrozen := map[string]bool{}
		evalFailed := false
		for _, res := range op.resources {
			list, err := p.dyn.Resource(res.gvr).List(ctx, metav1.ListOptions{})
			switch {
			case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
				continue // CRD not installed on this cluster
			case err != nil:
				evalFailed = true
				if firstErr == nil {
					firstErr = fmt.Errorf("list %s (%s): %w",
						res.gvr.Resource, op.name, err)
				}
				continue
			}
			for i := range list.Items {
				o := &list.Items[i]
				if !res.stuck(o) {
					continue
				}
				key := op.name + "/" + res.gvr.Resource + "/" +
					o.GetNamespace() + "/" + o.GetName()
				live[key] = true
				p.mu.Lock()
				first, ok := p.opFirstSeen[key]
				if !ok {
					p.opFirstSeen[key] = now
				}
				p.mu.Unlock()
				if !ok {
					log.Info("operator stuck signature — tracking first-seen",
						"operator", op.name, "resource", res.gvr.Resource,
						"object", o.GetNamespace()+"/"+o.GetName())
					continue
				}
				if now.Sub(first) >= op.stuckMinAge {
					reasonsFrozen[res.reason] = true
				}
			}
		}
		if evalFailed {
			// An incomplete scan must not prune first-seen nor
			// clear held series — leave this operator's state as-is.
			continue
		}

		p.mu.Lock()
		for k := range p.opFirstSeen {
			if strings.HasPrefix(k, op.name+"/") && !live[k] {
				delete(p.opFirstSeen, k)
			}
		}
		for k := range p.opFrozen {
			if !strings.HasPrefix(k, op.name+"/") {
				continue
			}
			if reasonsFrozen[strings.TrimPrefix(k, op.name+"/")] {
				continue
			}
			metrics.OperatorWorkqueueFrozen.WithLabelValues(
				op.name, strings.TrimPrefix(k, op.name+"/")).Set(0)
			delete(p.opFrozen, k)
		}
		for r := range reasonsFrozen {
			metrics.OperatorWorkqueueFrozen.WithLabelValues(op.name, r).Set(1)
			p.opFrozen[op.name+"/"+r] = true
			frozen[op.name+"/"+r] = r
		}
		p.mu.Unlock()

		if len(reasonsFrozen) > 0 {
			reasons := make([]string, 0, len(reasonsFrozen))
			for r := range reasonsFrozen {
				reasons = append(reasons, r)
			}
			sort.Strings(reasons)
			p.healOperatorLeader(ctx, log, op, lease, reasons, now)
		}
	}

	if len(frozen) == 0 {
		if firstErr != nil {
			return probeResult{infra: firstErr}
		}
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(frozen))
	for k := range frozen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{infra: firstErr, why: fmt.Sprintf(
		"operator lease renews but target CRs unreconciled: %s",
		strings.Join(keys, ", "))}
}

// resetOperator clears one operator's tracking and flips its held
// frozen series back to 0 — called when the frozen-but-leader
// diagnosis cannot apply (absent/stale Lease) so a signature that
// flaps around a precondition edge re-arms from scratch.
func (p *clusterHealthProber) resetOperator(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.opFirstSeen {
		if strings.HasPrefix(k, name+"/") {
			delete(p.opFirstSeen, k)
		}
	}
	for k := range p.opFrozen {
		if !strings.HasPrefix(k, name+"/") {
			continue
		}
		metrics.OperatorWorkqueueFrozen.WithLabelValues(
			name, strings.TrimPrefix(k, name+"/")).Set(0)
		delete(p.opFrozen, k)
	}
}

// healOperatorLeader deletes the stuck operator's leader pod to force
// re-election — the same unsticking nudge a manual
// `kubectl delete pod` applies. Gates, in order: the 1h cooldown
// (wider of in-RAM ledger and the persisted Lease stamp), the
// maintenance mutex (never kill a leader mid-drain/upgrade), and a
// resolvable leader pod (holderIdentity "<pod>_<uuid>" first, then
// the label selector in the Lease's namespace). Every guard refusal
// is quiet — the frozen gauge + FAIL series already carry the alert.
func (p *clusterHealthProber) healOperatorLeader(ctx context.Context, log logr.Logger,
	op operatorTarget, lease *coordinationv1.Lease, reasons []string, now time.Time) {

	p.mu.Lock()
	last, ok := p.opHealed[op.name]
	p.mu.Unlock()
	if ok && now.Sub(last) < operatorHealCooldown {
		log.Info("skip heal: operator inside cooldown", "operator", op.name,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	if ts := lease.Annotations[operatorHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < operatorHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"operator", op.name,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	// Maintenance mutex — "cannot verify" fails closed like every
	// other caller: an unverifiable drain state defers the heal.
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"operator", op.name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"operator", op.name, "why", why)
		return
	}

	pods, err := p.leaderPods(ctx, op, lease)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: leader pod resolution failed — heal deferred",
			"operator", op.name, "error", err)
		return
	}
	if len(pods) == 0 {
		log.Info("no leader pod resolvable for stuck operator — heal deferred",
			"operator", op.name)
		return
	}

	deleted := false
	for i := range pods {
		pod := &pods[i]
		// UID precondition closes the list→delete TOCTOU: a
		// same-named replacement pod is not ours to reap.
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stuck operator leader delete failed",
				"pod", pod.Namespace+"/"+pod.Name, "operator", op.name)
			continue
		}
		deleted = true
		log.Info("DELETE: stuck operator leader pod — forcing re-election",
			"operator", op.name, "pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		return
	}
	for _, r := range reasons {
		metrics.OperatorWorkqueueHealsTotal.WithLabelValues(op.name, r).Inc()
	}
	p.mu.Lock()
	p.opHealed[op.name] = now
	p.mu.Unlock()
	// Persist the stamp on the Lease — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			operatorHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal heal stamp", "operator", op.name)
		return
	}
	if _, err := p.cs.CoordinationV1().Leases(lease.Namespace).Patch(ctx, lease.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "persist heal stamp failed", "operator", op.name)
	}
}

// leaderPods resolves the operator's leader pod: holderIdentity is
// "<pod-name>_<uuid>" on client-go leader-election — the name prefix
// is tried first, then the verbatim identity (custom electors may
// not suffix); the operator's pod label selector inside the Lease's
// own namespace is the fallback when neither resolves.
func (p *clusterHealthProber) leaderPods(ctx context.Context, op operatorTarget,
	lease *coordinationv1.Lease) ([]corev1.Pod, error) {
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if holder != "" {
		candidates := []string{holder}
		if i := strings.LastIndex(holder, "_"); i > 0 {
			candidates = append([]string{holder[:i]}, candidates...)
		}
		for _, name := range candidates {
			pod, err := p.cs.CoreV1().Pods(lease.Namespace).
				Get(ctx, name, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				continue
			case err != nil:
				return nil, fmt.Errorf("get leader pod %s/%s: %w",
					lease.Namespace, name, err)
			default:
				return []corev1.Pod{*pod}, nil
			}
		}
	}
	pods, err := p.cs.CoreV1().Pods(lease.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: op.podSelector})
	if err != nil {
		return nil, fmt.Errorf("list operator pods in %s (selector %q): %w",
			lease.Namespace, op.podSelector, err)
	}
	return pods.Items, nil
}

// ---------------------------------------------------------------------------
// stateful-masterless-services (W6.2) — masterless service guard +
// dragonfly auto-heal.
// ---------------------------------------------------------------------------

// masterlessRoleKeys are the label keys marking a Service that routes
// only to the master/primary of a stateful set — 0 Ready endpoints on
// it means the workload is leaderless.
var masterlessRoleKeys = []string{"role", "redis-role", "app.kubernetes.io/role"}

// masterlessRoleValues are the role values identifying the master
// side of a replicated stateful service.
var masterlessRoleValues = []string{"master", "primary", "leader"}

// masterRoleService reports whether svc carries a master-role key —
// in its selector (selects only the leader pods) or its own labels
// (the Service is labeled as the master endpoint).
func masterRoleService(svc *corev1.Service) bool {
	for _, k := range masterlessRoleKeys {
		if v := svc.Spec.Selector[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	for _, k := range masterlessRoleKeys {
		if v := svc.Labels[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	return false
}

// selectorMatchesSTS reports whether the Service routes to the
// StatefulSet's pods: every NON-role key in svc.Spec.Selector must
// appear in the STS pod-template labels. Role keys are stripped —
// operators write role=master/replica onto the POD at runtime, never
// into the template, so a literal subset match would never fire for
// exactly the services this check exists to watch (dragonfly/redis
// master services). A selector that carries nothing but role keys
// cannot be attributed to one STS — it matches every workload, so it
// is excluded.
func selectorMatchesSTS(svc *corev1.Service, podLabels map[string]string) bool {
	nonRole := map[string]string{}
	for k, v := range svc.Spec.Selector {
		if slices.Contains(masterlessRoleKeys, k) {
			continue
		}
		nonRole[k] = v
	}
	if len(nonRole) == 0 {
		return false
	}
	return labels.SelectorFromSet(nonRole).Matches(labels.Set(podLabels))
}

// masterSvc pairs a master-role Service with the ready StatefulSet
// whose pod labels its selector matches.
type masterSvc struct {
	ns, svc string
	sts     *appsv1.StatefulSet
}

// dragonflyOwned reports whether the StatefulSet is managed by the
// dragonfly-operator — via app.kubernetes.io/part-of=dragonfly or
// app.kubernetes.io/created-by=dragonfly-operator on the STS metadata
// or its pod template.
func dragonflyOwned(sts *appsv1.StatefulSet) bool {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		if lbls["app.kubernetes.io/part-of"] == "dragonfly" ||
			lbls["app.kubernetes.io/created-by"] == "dragonfly-operator" {
			return true
		}
	}
	return false
}

// checkStatefulMasterlessServices detects a masterless stateful
// service: a non-headless Service routing to a ready StatefulSet's
// pods under a master-role key whose EndpointSlices report 0 Ready
// endpoints — the STS is alive but clients have no master to reach
// (the operator that assigns the role wedged).
//
// Past masterlessZeroMinAge the gauge
// node_automation_stateful_service_zero_endpoints{ns,svc,sts} goes to
// 1 and the check FAILs; past masterlessHealMinAge a Dragonfly-owned
// STS additionally triggers a dragonfly-operator leader delete (30m
// cooldown) — a wedged operator is the common cause of a missing
// master label/election.
func (p *clusterHealthProber) checkStatefulMasterlessServices(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.stsZeroSince == nil {
		p.stsZeroSince = map[string]time.Time{}
	}
	if p.stsZeroEmitted == nil {
		p.stsZeroEmitted = map[string]bool{}
	}
	if p.drHealed == nil {
		p.drHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	stsList, err := p.cs.AppsV1().StatefulSets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	svcList, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list services: %w", err)}
	}
	// Ready-endpoint census per ns/service — same source as the
	// webhook guard (paged, service-name label binding, nil ready
	// counts as ready). A list error skips the whole check: "0
	// ready" is indistinguishable from "no data".
	ready := map[string]int{}
	sliceOpts := metav1.ListOptions{Limit: healthListPageSize}
	for {
		sliceList, err := p.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
			List(ctx, sliceOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
		}
		for _, s := range sliceList.Items {
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				continue
			}
			key := s.Namespace + "/" + svc
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready[key]++
				}
			}
		}
		if sliceList.Continue == "" {
			break
		}
		sliceOpts.Continue = sliceList.Continue
	}

	// Candidates: a ready STS paired with a master-role Service
	// routing to its pods.
	var candidates []masterSvc
	for i := range stsList.Items {
		sts := &stsList.Items[i]
		if sts.Status.ReadyReplicas == 0 {
			continue
		}
		for j := range svcList.Items {
			svc := &svcList.Items[j]
			if svc.Namespace != sts.Namespace ||
				svc.Spec.ClusterIP == "" ||
				svc.Spec.ClusterIP == corev1.ClusterIPNone {
				continue // headless services are deliberately per-pod
			}
			if !masterRoleService(svc) ||
				!selectorMatchesSTS(svc, sts.Spec.Template.Labels) {
				continue
			}
			candidates = append(candidates,
				masterSvc{ns: svc.Namespace, svc: svc.Name, sts: sts})
		}
	}

	seen := map[string]bool{}    // tuples observed at 0 ready this sweep
	emitted := map[string]bool{} // tuples past the gauge window
	var due []masterSvc          // past the heal window
	for _, c := range candidates {
		key := c.ns + "/" + c.svc + "/" + c.sts.Name
		if ready[c.ns+"/"+c.svc] > 0 {
			continue // master reachable — drop any streak
		}
		seen[key] = true
		p.mu.Lock()
		first, ok := p.stsZeroSince[key]
		if !ok {
			p.stsZeroSince[key] = now
		}
		p.mu.Unlock()
		if !ok {
			log.Info("master-role service at 0 ready endpoints — tracking first-seen",
				"service", c.ns+"/"+c.svc, "statefulset", c.sts.Name)
			continue
		}
		if now.Sub(first) < masterlessZeroMinAge {
			continue
		}
		emitted[key] = true
		metrics.StatefulServiceZeroEndpoints.
			WithLabelValues(c.ns, c.svc, c.sts.Name).Set(1)
		if now.Sub(first) >= masterlessHealMinAge {
			due = append(due, c)
		}
	}

	p.mu.Lock()
	for k := range p.stsZeroSince {
		if !seen[k] {
			delete(p.stsZeroSince, k)
		}
	}
	for k := range p.stsZeroEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.StatefulServiceZeroEndpoints.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
		delete(p.stsZeroEmitted, k)
	}
	maps.Copy(p.stsZeroEmitted, emitted)
	p.mu.Unlock()

	// Dragonfly auto-heal — a masterless dragonfly past the heal
	// window bounces the operator leader to force re-election.
	for _, c := range due {
		if !dragonflyOwned(c.sts) {
			continue
		}
		p.healDragonflyOperator(ctx, log, c, now)
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: %s",
		masterlessZeroMinAge, strings.Join(keys, ", "))}
}

// healDragonflyOperator deletes the dragonfly-operator controller
// pod(s) — the same re-election nudge the operator watchdog applies,
// keyed on its own 30m cooldown so the leader is never churned. The
// cooldown is the wider of the in-RAM ledger and the
// node.ops/last-dragonfly-operator-heal stamp persisted on the STS
// that triggered it (survives operator restarts).
func (p *clusterHealthProber) healDragonflyOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {
	if ts := sig.sts.Annotations[dragonflyHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < dragonflyHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	pods, err := p.cs.CoreV1().Pods(dragonflyOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list dragonfly-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, dragonflyOperatorPodPrefix) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		p.mu.Lock()
		last, ok := p.drHealed[key]
		p.mu.Unlock()
		if ok && now.Sub(last) < dragonflyHealCooldown {
			log.Info("skip heal: dragonfly operator inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "dragonfly operator delete failed", "pod", key)
			continue
		}
		p.mu.Lock()
		p.drHealed[key] = now
		p.mu.Unlock()
		deleted = true
		log.Info("DELETE: dragonfly operator pod — masterless service, forcing re-election",
			"pod", key, "service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Name)
	}
	if !deleted {
		return
	}
	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			dragonflyHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal dragonfly heal stamp", "statefulset", sig.sts.Name)
		return
	}
	if _, err := p.cs.AppsV1().StatefulSets(sig.sts.Namespace).Patch(ctx,
		sig.sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "persist dragonfly heal stamp failed",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name)
	}
}

// ---------------------------------------------------------------------------
// rabbitmq-suspended-listener (W6.4) — suspended listener healer.
// ---------------------------------------------------------------------------

// rabbitSuspended reports the suspended-listener signature: the pod
// is Running and every container Started (kubelet launched them) but
// none ever went Ready — the rabbit listener sits on the
// ranch:suspended branch refusing port 5672 while the pod looks
// "almost healthy" to every coarse check.
func rabbitSuspended(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Started == nil || !*s.Started || s.Ready {
			return false
		}
	}
	return true
}

// rabbitQuorumSafe verifies deleting the suspended pod cannot break
// the cluster quorum: the pod must be owned by a StatefulSet whose
// every OTHER replica is Ready — a peer that is itself suspended or
// down means the delete could take the cluster below quorum, so the
// heal stands down and the FAIL series keeps alerting instead.
func (p *clusterHealthProber) rabbitQuorumSafe(ctx context.Context, pod *corev1.Pod) (bool, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "StatefulSet" {
		return false, nil // cannot verify peers — do not touch
	}
	sts, err := p.cs.AppsV1().StatefulSets(pod.Namespace).
		Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get statefulset %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("statefulset selector %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	peers, err := p.cs.CoreV1().Pods(pod.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return false, fmt.Errorf("list peer pods of %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	for i := range peers.Items {
		peer := &peers.Items[i]
		if peer.UID == pod.UID {
			continue
		}
		if !shared.PodReadyCond(peer) {
			return false, nil
		}
	}
	return true, nil
}

// checkRabbitMQSuspendedPods heals the RabbitMQ suspended-listener
// wedge: a pod whose containers all started but never went Ready is
// partitioned from its own cluster while holding a peer slot. Stuck
// >=10m AND all other replicas Ready (quorum survives) → delete the
// pod so the StatefulSet controller brings up a clean replica; the
// RabbitMQSuspendedHealsTotal counter records each heal.
func (p *clusterHealthProber) checkRabbitMQSuspendedPods(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.rbSuspendedSince == nil {
		p.rbSuspendedSince = map[string]time.Time{}
	}
	if p.rbHealed == nil {
		p.rbHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: rabbitComponentLabel})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list rabbitmq pods: %w", err)}
	}

	live := map[string]bool{} // "ns/pod/uid" suspended signatures this sweep
	var due []corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !rabbitSuspended(pod) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
		live[key] = true
		p.mu.Lock()
		first, ok := p.rbSuspendedSince[key]
		if !ok {
			p.rbSuspendedSince[key] = now
		}
		p.mu.Unlock()
		if !ok {
			log.Info("rabbitmq suspended-listener signature — tracking first-seen",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		if now.Sub(first) >= rabbitSuspendedMinAge {
			due = append(due, *pod)
		}
	}
	p.mu.Lock()
	for k := range p.rbSuspendedSince {
		if !live[k] {
			delete(p.rbSuspendedSince, k)
		}
	}
	p.mu.Unlock()

	for i := range due {
		pod := &due[i]
		key := pod.Namespace + "/" + pod.Name
		p.mu.Lock()
		last, ok := p.rbHealed[key]
		p.mu.Unlock()
		if ok && now.Sub(last) < rabbitHealCooldown {
			log.Info("skip heal: rabbitmq pod inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		safe, err := p.rabbitQuorumSafe(ctx, pod)
		if err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: quorum check failed — heal deferred",
				"pod", key, "error", err)
			continue
		}
		if !safe {
			log.Info("quorum unsafe — suspended rabbitmq pod kept (peers not all Ready)",
				"pod", key)
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "suspended rabbitmq pod delete failed", "pod", key)
			continue
		}
		p.mu.Lock()
		p.rbHealed[key] = now
		p.mu.Unlock()
		metrics.RabbitMQSuspendedHealsTotal.
			WithLabelValues(pod.Namespace, pod.Name).Inc()
		log.Info("DELETE: suspended-listener rabbitmq pod — quorum verified",
			"pod", key)
	}

	if len(due) == 0 {
		return probeResult{pass: true}
	}
	names := make([]string, 0, len(due))
	for i := range due {
		names = append(names, due[i].Namespace+"/"+due[i].Name)
	}
	sort.Strings(names)
	return probeResult{why: fmt.Sprintf(
		"rabbitmq pods running suspended >=%s: %s",
		rabbitSuspendedMinAge, strings.Join(names, ", "))}
}
