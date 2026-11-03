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
package health

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
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
)

// C6 watchdog knobs — the KCM leader Lease name and the
// node_automation_kcm_workqueue_frozen{reason} label values.
const (
	kcmLeaseName         = "kube-controller-manager"
	kcmReasonDesiredZero = "daemonset_desired_zero"
	kcmReasonStaleGen    = "stale_observed_generation"
)

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

func healthEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func healthEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func healthEnvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
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
	cs  kubernetes.Interface
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
}

func newClusterHealthProber(cs kubernetes.Interface, cfg healthProbeConfig) *clusterHealthProber {
	boot := time.Now()
	return &clusterHealthProber{
		cs:         cs,
		cfg:        cfg,
		lookupHost: (&net.Resolver{}).LookupHost,
		httpClient: &http.Client{},
		now:        time.Now,
		lastPass: map[string]time.Time{
			checkNameDNS:           boot,
			checkNameHTTPContent:   boot,
			checkNamePodRestarts:   boot,
			checkNamePodStatus:     boot,
			checkNameResourceQuota: boot,
			checkNameKCMWorkqueue:  boot,
		},
		kcmFirstSeen:     map[string]time.Time{},
		kcmFrozenReasons: map[string]bool{},
	}
}

// SetupClusterHealthProber registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the gate lives in
// CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false" opts
// out); disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern.
func SetupClusterHealthProber(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(clusterHealthQueue).Info("disabled — module not registered")
		return nil
	}
	p := newClusterHealthProber(cs, healthProbeConfigFromEnv())
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
