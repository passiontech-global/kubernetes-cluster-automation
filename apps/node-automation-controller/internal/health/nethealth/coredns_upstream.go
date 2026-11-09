// coredns_upstream.go — the coredns-upstream check (coredns-upstream):
// per-pod CoreDNS/node-local-dns upstream healthcheck failures or
// SERVFAIL ratio from Prometheus; an isolated failing pod is
// deleted while siblings stay healthy, with a pod-readiness
// fallback when Prometheus is unreachable.
package nethealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// coreDNSUpstreamCheck is the CoreDNS upstream-failure watchdog with
// the readiness-fallback heal.
type coreDNSUpstreamCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// newCoreDNSUpstreamCheck builds the coredns-upstream check — its only state
// is the emitted-gauge ledger; heal cooldowns ride the shared
// Deps.Heals set via deletePodHeal.
func NewCoreDNSUpstreamCheck(d *probefw.Deps) probefw.Check {
	return &coreDNSUpstreamCheck{Deps: d}
}

const (
	CheckNameCoreDNSUpstream = "coredns-upstream"

	// coredns-upstream — coredns-upstream knobs.
	coreDNSUpstreamHealCool = 30 * time.Minute
	coreDNSFallbackMinAge   = 10 * time.Minute
)

var (
	// coredns-upstream — per-pod DNS upstream failure signal.
	coreDNSUpstreamFailingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_coredns_upstream_failing",
		Help: "1 while the coredns/node-local-dns pod reports isolated upstream failures — coredns-upstream.",
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
func (p *coreDNSUpstreamCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	healthSeries, errH := p.PromQuery(ctx,
		`sum by (pod) (rate(coredns_ForwardHealthcheckFailureCount_total[5m])) > 0.5`)
	servfailSeries, errS := p.PromQuery(ctx,
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
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	dnsByName := map[string]*corev1.Pod{}
	dnsByNS := map[string][]*corev1.Pod{}
	for i := range pods {
		pod := &pods[i]
		if !isDNSPod(pod) {
			continue
		}
		// Keyed ns/name: bare pod names collide across namespaces and
		// a cross-ns collision would silently drop the flag below.
		dnsByName[pod.Namespace+"/"+pod.Name] = pod
		dnsByNS[pod.Namespace] = append(dnsByNS[pod.Namespace], pod)
	}

	flagged := map[string]string{} // "ns/name" -> reason detail
	record := func(podName, nsHint, detail string) {
		ns := nsHint
		// Census (keyed ns/name) wins over the series label only when
		// the series' own namespace agrees — otherwise fall back to
		// the label, then empty.
		if nsHint != "" && dnsByName[nsHint+"/"+podName] != nil {
			ns = nsHint
		}
		if ns == "" {
			ns = "unknown"
		}
		flagged[ns+"/"+podName] = detail
	}
	for _, s := range healthSeries {
		if name := s.Label("pod", "pod_name"); name != "" {
			record(name, s.Metric["namespace"],
				fmt.Sprintf("healthcheck_failures=%.2f", s.Value))
		}
	}
	for _, s := range servfailSeries {
		if name := s.Label("pod", "pod_name"); name != "" {
			record(name, s.Metric["namespace"],
				fmt.Sprintf("servfail_ratio=%.2f", s.Value))
		}
	}

	var rep probefw.SweepReport
	healed := false // one pod delete per cycle — see below
	flaggedKeys := make([]string, 0, len(flagged))
	for key := range flagged {
		flaggedKeys = append(flaggedKeys, key)
	}
	sort.Strings(flaggedKeys) // deterministic pick for the one-per-cycle heal
	for _, key := range flaggedKeys {
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod := dnsByName[ns+"/"+name]
		if pod != nil {
			rep.Flag(coreDNSUpstreamFailingGauge, key, []string{ns, name})
			rep.Find(key + "(" + flagged[key] + ")")
		}
		// Isolated-failure heal: a healthy Ready sibling in the same
		// namespace means this is per-pod wedge, not a fleet outage.
		// At most ONE pod is deleted per cycle — a sweep flagging
		// several members at once (upstream flap, rollout) must not
		// halve the DNS fleet in a single pass. The cooldown keys on
		// the pod's controller so a recreated pod that wedges again
		// still honors the window; the ledger stamp going from
		// missing/stale to `now` is how a DELIVERED delete reads
		// (DeletePodHeal swallows cooldown/mutex/delete failures).
		if pod != nil && !healed && hasHealthySibling(pod, dnsByNS[ns], flagged) {
			target := kube.PodControllerKey(pod)
			hk := probefw.SelfHealKey(CheckNameCoreDNSUpstream, target)
			before, _ := p.Heals.Last(hk)
			p.DeletePodHeal(ctx, log, CheckNameCoreDNSUpstream,
				target, pod, coreDNSUpstreamHealCool, now)
			if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
				healed = true
			}
		}
	}
	return rep.Result(&p.emitted, coreDNSUpstreamFailingGauge.DeleteLabelValues,
		"coredns/node-local-dns upstream failures: ", ", ")
}

// hasHealthySibling reports whether another dns pod in the same
// namespace is Running+Ready and NOT itself flagged — the "isolated
// failure" precondition for the pod-delete heal. PodRunningReady
// already discounts deleting pods (a terminating sibling cannot
// absorb traffic).
func hasHealthySibling(pod *corev1.Pod, siblings []*corev1.Pod,
	flagged map[string]string) bool {
	for _, s := range siblings {
		if s.Name == pod.Name {
			continue
		}
		if _, bad := flagged[s.Namespace+"/"+s.Name]; bad {
			continue
		}
		if probefw.PodRunningReady(s) {
			return true
		}
	}
	return false
}

// corednsReadinessFallback is the Prometheus-unreachable path: the same
// isolated-failure shape detected from pod readiness — a dns pod
// unready >=10m while a sibling stays Ready.
func (p *coreDNSUpstreamCheck) corednsReadinessFallback(ctx context.Context,
	log logr.Logger, now time.Time) probefw.Result {

	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	dnsByNS := map[string][]*corev1.Pod{}
	for i := range pods {
		pod := &pods[i]
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
			since, unready := probefw.PodUnreadySince(pod)
			if !unready || now.Sub(since) < coreDNSFallbackMinAge {
				continue
			}
			flagged[ns+"/"+pod.Name] = "unready>10m(readiness-fallback)"
		}
	}

	var rep probefw.SweepReport
	healed := false // same one-delete-per-cycle bound as the PromQL path
	flaggedKeys := make([]string, 0, len(flagged))
	for key := range flagged {
		flaggedKeys = append(flaggedKeys, key)
	}
	sort.Strings(flaggedKeys) // deterministic pick for the one-per-cycle heal
	for _, key := range flaggedKeys {
		detail := flagged[key]
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod := probefw.PodFromList(pods, ns, name)
		if pod == nil {
			continue
		}
		lv := []string{ns, name}
		rep.Flag(coreDNSUpstreamFailingGauge, key, lv)
		if !healed && hasHealthySibling(pod, dnsByNS[ns], flagged) {
			target := kube.PodControllerKey(pod)
			hk := probefw.SelfHealKey(CheckNameCoreDNSUpstream, target)
			before, _ := p.Heals.Last(hk)
			p.DeletePodHeal(ctx, log, CheckNameCoreDNSUpstream,
				target, pod, coreDNSUpstreamHealCool, now)
			if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
				healed = true
			}
		}
		rep.Find(key + "(" + detail + ")")
	}
	return rep.Result(&p.emitted, coreDNSUpstreamFailingGauge.DeleteLabelValues,
		"coredns/node-local-dns unready pods (prometheus fallback): ", ", ")
}
