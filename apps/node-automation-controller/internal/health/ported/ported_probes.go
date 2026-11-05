package ported

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Check names — the exact HealthCheck metadata.name values the
// replaced kuberhealthy checks carried; they are the `check` label
// values alerts and dashboards key on.
const (
	CheckNameDNS           = "dns-status-internal"
	CheckNameHTTPContent   = "http-content-check"
	CheckNamePodRestarts   = "pod-restarts"
	CheckNamePodStatus     = "pod-status-check"
	CheckNameResourceQuota = "resource-quota-check"
)

// The five ported kuberhealthy checks — stateless probes that read
// only Deps; each gets its own struct so the registry shape stays
// uniform with the stateful watchdog checks.
type dnsStatusCheck struct{ *probefw.Deps }

type httpContentCheck struct{ *probefw.Deps }

type podRestartsCheck struct{ *probefw.Deps }

type podStatusCheck struct{ *probefw.Deps }

type resourceQuotaCheck struct{ *probefw.Deps }

// The ported-check constructors — every check exposes a
// NewXxxCheck(d *probefw.Deps) probefw.Check factory so the checkDefs registry
// can stay data-driven; these five carry no per-check state.
func NewDNSStatusCheck(d *probefw.Deps) probefw.Check     { return &dnsStatusCheck{Deps: d} }
func NewHTTPContentCheck(d *probefw.Deps) probefw.Check   { return &httpContentCheck{Deps: d} }
func NewPodRestartsCheck(d *probefw.Deps) probefw.Check   { return &podRestartsCheck{Deps: d} }
func NewPodStatusCheck(d *probefw.Deps) probefw.Check     { return &podStatusCheck{Deps: d} }
func NewResourceQuotaCheck(d *probefw.Deps) probefw.Check { return &resourceQuotaCheck{Deps: d} }

// probeDNS ports dns-resolution-check: every configured hostname must
// resolve. Per-check timeout comes from HEALTH_CHECK_TIMEOUT (the
// checker pod's TIMEOUT_DURATION was 30s).
func (p *dnsStatusCheck) Run(ctx context.Context) probefw.Result {
	ctx, cancel := context.WithTimeout(ctx, p.Cfg.Timeouts.Check)
	defer cancel()
	for _, host := range p.Cfg.DNS.Hostnames {
		if _, err := p.LookupHost(ctx, host); err != nil {
			return probefw.Result{Why: fmt.Sprintf("lookup %s: %v", host, err)}
		}
	}
	return probefw.Result{Pass: true}
}

// probeHTTPContent ports http-content-check: GET must return 200 and
// a body containing the expected string (live check: prometheus
// /-/healthy answers "Prometheus Server is Healthy.", expected
// substring "Healthy").
func (p *httpContentCheck) Run(ctx context.Context) probefw.Result {
	ctx, cancel := context.WithTimeout(ctx, p.Cfg.Timeouts.Check)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Cfg.HTTPContent.URL, nil)
	if err != nil {
		return probefw.Result{Why: fmt.Sprintf("build request: %v", err)}
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return probefw.Result{Why: fmt.Sprintf("GET %s: %v", p.Cfg.HTTPContent.URL, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return probefw.Result{Why: fmt.Sprintf("GET %s: status %d, want 200",
			p.Cfg.HTTPContent.URL, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return probefw.Result{Why: fmt.Sprintf("read body: %v", err)}
	}
	if !strings.Contains(string(body), p.Cfg.HTTPContent.Expected) {
		return probefw.Result{Why: fmt.Sprintf("body missing %q",
			p.Cfg.HTTPContent.Expected)}
	}
	return probefw.Result{Pass: true}
}

// probePodRestarts ports pod-restarts-check: FAIL when any container
// status — app, init or ephemeral — in the target namespace has
// RestartCount over the limit (live check: kube-system, 10) AND the
// restarts are still live signal (W10-FIX5): a container that crossed
// the threshold weeks ago and has been stable since must not hold the
// check red forever — RestartCount is monotonic, so the raw count
// alone can never recover.
func (p *podRestartsCheck) Run(ctx context.Context) probefw.Result {
	pods, err := p.CS.CoreV1().Pods(p.Cfg.Pods.Namespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods in %s: %w",
			p.Cfg.Pods.Namespace, err)}
	}
	now := p.Now()
	var offenders []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, statuses := range [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
			pod.Status.EphemeralContainerStatuses,
		} {
			for _, s := range statuses {
				if s.RestartCount > p.Cfg.Pods.MaxRestarts &&
					restartRecentlyActive(s, now) {
					offenders = append(offenders,
						fmt.Sprintf("%s/%s=%d", pod.Name, s.Name, s.RestartCount))
				}
			}
		}
	}
	if len(offenders) > 0 {
		return probefw.Result{Why: fmt.Sprintf("restarts>%d: %s",
			p.Cfg.Pods.MaxRestarts, strings.Join(offenders, ", "))}
	}
	return probefw.Result{Pass: true}
}

// podRestartRecentWindow bounds how far back the last termination may
// sit before an over-threshold RestartCount reads as historical rather
// than live (W10-FIX5).
const podRestartRecentWindow = 24 * time.Hour

// restartRecentlyActive reports whether an over-threshold restart
// count still represents an ACTIVE failure: the last termination
// finished inside podRestartRecentWindow, or the container is
// currently Waiting (CrashLoopBackOff and friends — the kubelet only
// reports Waiting while the restart loop is live). A container that
// crossed the threshold and has run clean since reports neither and
// is ignored.
func restartRecentlyActive(s corev1.ContainerStatus, now time.Time) bool {
	if t := s.LastTerminationState.Terminated; t != nil &&
		!t.FinishedAt.IsZero() &&
		now.Sub(t.FinishedAt.Time) < podRestartRecentWindow {
		return true
	}
	return s.State.Waiting != nil
}

// probePodStatus ports pod-status-check: pods younger than
// SKIP_DURATION are ignored (fresh pods legitimately sit Pending while
// images pull); any older pod whose Phase is not Running or Succeeded
// is a FAIL (Failed/Unknown/stuck Pending).
func (p *podStatusCheck) Run(ctx context.Context) probefw.Result {
	pods, err := p.CS.CoreV1().Pods(p.Cfg.Pods.Namespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods in %s: %w",
			p.Cfg.Pods.Namespace, err)}
	}
	var bad []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if p.Now().Sub(pod.CreationTimestamp.Time) < p.Cfg.Pods.SkipDuration {
			continue // too young — still allowed to be Pending
		}
		if pod.Status.Phase != corev1.PodRunning &&
			pod.Status.Phase != corev1.PodSucceeded {
			bad = append(bad, fmt.Sprintf("%s=%s", pod.Name, pod.Status.Phase))
		}
	}
	if len(bad) > 0 {
		return probefw.Result{Why: fmt.Sprintf("non-Running pods in %s: %s",
			p.Cfg.Pods.Namespace, strings.Join(bad, ", "))}
	}
	return probefw.Result{Pass: true}
}

// probeResourceQuota ports resource-quota-check: FAIL when any quota
// resource's used/hard ratio exceeds the threshold (live check:
// THRESHOLD=0.9 — strictly greater, so exactly-at-threshold passes).
// A resource absent from Status.Used counts as 0.
func (p *resourceQuotaCheck) Run(ctx context.Context) probefw.Result {
	quotas, err := p.CS.CoreV1().ResourceQuotas(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list resourcequotas: %w", err)}
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
			if ratio > p.Cfg.Quota.Threshold {
				over = append(over, fmt.Sprintf("%s/%s %s=%s/%s",
					q.Namespace, q.Name, name, used.String(), hard.String()))
			}
		}
	}
	if len(over) > 0 {
		return probefw.Result{Why: fmt.Sprintf("quota used/hard>%.2g: %s",
			p.Cfg.Quota.Threshold, strings.Join(over, ", "))}
	}
	return probefw.Result{Pass: true}
}
