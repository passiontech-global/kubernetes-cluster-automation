// coredns_upstream.go — the coredns-upstream check (W10-NM5):
// per-pod CoreDNS/node-local-dns upstream healthcheck failures or
// SERVFAIL ratio from Prometheus; an isolated failing pod is
// deleted while siblings stay healthy, with a pod-readiness
// fallback when Prometheus is unreachable.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// coreDNSUpstreamCheck is the CoreDNS upstream-failure watchdog with
// the readiness-fallback heal.
type coreDNSUpstreamCheck struct{ *deps }

const (
	checkNameCoreDNSUpstream = "coredns-upstream"

	// W10-NM5 — coredns-upstream knobs.
	coreDNSUpstreamHealCool = 30 * time.Minute
	coreDNSFallbackMinAge   = 10 * time.Minute
)

var (
	// W10-NM5 — per-pod DNS upstream failure signal.
	coreDNSUpstreamFailingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_coredns_upstream_failing",
		Help: "1 while the coredns/node-local-dns pod reports isolated upstream failures — W10-NM5.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		coreDNSUpstreamFailingGauge)
}

// isDNSPod reports whether the pod is a CoreDNS or
// node-local-dns member — by name prefix or the k8s-app label the
// upstream charts stamp.
func isDNSPod(pod *corev1.Pod) bool {
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
func (p *coreDNSUpstreamCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	healthSeries, errH := p.promInstantQuery(ctx,
		`sum by (pod) (rate(coredns_ForwardHealthcheckFailureCount_total[5m])) > 0.5`)
	servfailSeries, errS := p.promInstantQuery(ctx,
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
		return p.corednsReadinessFallback(ctx, log, now)
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
		if !isDNSPod(pod) {
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
		if name := promLabelValue(s, "pod", "pod_name"); name != "" {
			record(name, s.metric["namespace"],
				fmt.Sprintf("healthcheck_failures=%.2f", s.value))
		}
	}
	for _, s := range servfailSeries {
		if name := promLabelValue(s, "pod", "pod_name"); name != "" {
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
			coreDNSUpstreamFailingGauge.WithLabelValues(lv...).Set(1)
		}
		// Isolated-failure heal: a healthy Ready sibling in the same
		// namespace means this is per-pod wedge, not a fleet outage.
		if pod != nil && hasHealthySibling(pod, dnsByNS[ns], flagged) {
			p.deletePodHeal(ctx, log, checkNameCoreDNSUpstream,
				ns+"/"+name, pod, coreDNSUpstreamHealCool, now)
		}
	}
	p.reconcileEmittedGauges(checkNameCoreDNSUpstream,
		coreDNSUpstreamFailingGauge, current)

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

// hasHealthySibling reports whether another dns pod in the same
// namespace is Running+Ready and NOT itself flagged — the "isolated
// failure" precondition for the pod-delete heal.
func hasHealthySibling(pod *corev1.Pod, siblings []*corev1.Pod,
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

// corednsReadinessFallback is the Prometheus-unreachable path: the same
// isolated-failure shape detected from pod readiness — a dns pod
// unready >=10m while a sibling stays Ready.
func (p *coreDNSUpstreamCheck) corednsReadinessFallback(ctx context.Context,
	log logr.Logger, now time.Time) probeResult {

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	dnsByNS := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if isDNSPod(pod) {
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
			since, unready := podUnreadySince(pod)
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
		pod := podFromList(pods.Items, ns, name)
		if pod == nil {
			continue
		}
		lv := []string{ns, name}
		current[key] = lv
		coreDNSUpstreamFailingGauge.WithLabelValues(lv...).Set(1)
		if hasHealthySibling(pod, dnsByNS[ns], flagged) {
			p.deletePodHeal(ctx, log, checkNameCoreDNSUpstream,
				ns+"/"+name, pod, coreDNSUpstreamHealCool, now)
		}
		findings = append(findings, key+"("+detail+")")
	}
	sort.Strings(findings)
	p.reconcileEmittedGauges(checkNameCoreDNSUpstream,
		coreDNSUpstreamFailingGauge, current)
	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "coredns/node-local-dns unready pods (prometheus fallback): " +
		strings.Join(findings, ", ")}
}

// podFromList resolves ns/name inside an already-fetched pod
// list — kept tiny to avoid a second cluster-wide List in the
// fallback path.
func podFromList(items []corev1.Pod, ns, name string) *corev1.Pod {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}
