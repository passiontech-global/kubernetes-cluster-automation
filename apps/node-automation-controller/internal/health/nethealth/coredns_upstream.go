// coredns_upstream.go — the coredns-upstream check (coredns-upstream):
// per-pod CoreDNS/node-local-dns upstream healthcheck failures or
// SERVFAIL ratio from Prometheus; an isolated failing pod is
// deleted while siblings stay healthy, with a pod-readiness
// fallback when Prometheus is unreachable.
package nethealth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// coreDNSUpstreamCheck is the CoreDNS upstream-failure watchdog with
// the readiness-fallback heal.
type coreDNSUpstreamCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// seen is the PromQL-path first-seen ledger — an upstream
	// failure signature must persist coreDNSUpstreamMinAge before
	// the isolated-failure heal fires, same posture the readiness
	// fallback gets from its 10m unready window.
	seen state.FirstSeenLedger
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
	// coreDNSUpstreamMinAge is the PromQL-path persistence window —
	// a single-sweep upstream blip must not delete a DNS pod.
	coreDNSUpstreamMinAge = 10 * time.Minute
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
// (coredns_proxy_healthcheck_failures_total{proxy_name="forward"} or
// legacy coredns_forward_healthcheck_failures_total rate >0.5/s over
// 5m) or a SERVFAIL ratio >15%. When a SINGLE dns pod fails while a
// sibling in the same namespace stays healthy, the pod is deleted
// (30m cooldown) — an upstream socket/conntrack wedge is per-pod
// state a restart clears. Both queries failing is inconclusive and
// falls back to the pod-readiness signature (unready >10m with a
// healthy sibling) rather than false-FAILing on a Prometheus outage.
func (p *coreDNSUpstreamCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	// sum by (namespace, pod) — NOT sum by (pod): bare pod names
	// collide across namespaces (two clusters' kube-system/coredns-*
	// aside, node-local-dns DaemonSets exist per-node but named
	// identically across namespaces is the real case), and an
	// aggregation that drops `namespace` both merges the colliding
	// series into one value AND leaves s.Metric["namespace"] empty —
	// the record() below then flags "unknown/<name>" and the heal
	// resolves the wrong namespace's pod.
	healthSeries, errH := p.PromQuery(ctx,
		`(sum by (namespace, pod) (rate(coredns_proxy_healthcheck_failures_total{proxy_name="forward"}[5m])) or `+
			`sum by (namespace, pod) (rate(coredns_forward_healthcheck_failures_total[5m]))) > 0.5`)
	servfailSeries, errS := p.PromQuery(ctx,
		`sum by (namespace, pod) (rate(coredns_dns_responses_total{rcode="SERVFAIL"}[5m]))`+
			` / clamp_min(sum by (namespace, pod) (rate(coredns_dns_responses_total[5m])), 1) > 0.15`)
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
	slices.Sort(flaggedKeys) // deterministic pick for the one-per-cycle heal
	for _, key := range flaggedKeys {
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod := dnsByName[ns+"/"+name]
		if pod == nil {
			continue // census has no such pod — nothing to flag or heal
		}
		rep.Flag(coreDNSUpstreamFailingGauge, key, []string{ns, name})
		rep.Find(key + "(" + flagged[key] + ")")
		// Observe the persistence window for EVERY flagged pod,
		// before any heal gating. Go's && short-circuits: putting
		// Persisted last meant a second flagged pod (healed==true)
		// or a pod temporarily without a healthy sibling never
		// advanced its first-seen stamp, so a 10m signature had to
		// start over every time the heal was deferred.
		persisted := probefw.Persisted(&p.seen, key, now,
			coreDNSUpstreamMinAge, log)
		// Isolated-failure heal: a healthy Ready sibling in the same
		// namespace means this is per-pod wedge, not a fleet outage.
		// At most ONE pod is deleted per cycle — a sweep flagging
		// several members at once (upstream flap, rollout) must not
		// halve the DNS fleet in a single pass. The cooldown keys on
		// the pod's controller so a recreated pod that wedges again
		// still honors the window; the ledger stamp going from
		// missing/stale to `now` is how a DELIVERED delete reads
		// (DeletePodHeal swallows cooldown/mutex/delete failures).
		if persisted && !healed && hasHealthySibling(pod, dnsByNS[ns], flagged) {
			target := kube.PodControllerKey(pod)
			// node-local-dns is a DaemonSet: one agent per node,
			// and the controller key is SHARED by every node's
			// pod. Keying only on it puts the whole DaemonSet in a
			// 30m cooldown after one node's agent is bounced. Add
			// the node as the real failure domain; the scoped
			// dispatcher also runs the node-local maintenance
			// gate for DaemonSet-owned pods.
			if ctrl := metav1.GetControllerOf(pod); ctrl != nil &&
				ctrl.Kind == "DaemonSet" {
				target = target + "/" + pod.Spec.NodeName
			}
			hk := probefw.SelfHealKey(CheckNameCoreDNSUpstream, target)
			before, _ := p.Heals.Last(hk)
			p.DeletePodHealScoped(ctx, log, CheckNameCoreDNSUpstream,
				target, pod, coreDNSUpstreamHealCool, now)
			if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
				healed = true
			}
		}
	}
	// Drop first-seen entries whose signature cleared — "persisted"
	// means continuously flagged, so a clean sweep re-arms the
	// window. A degraded query family cannot prove quiet: skip the
	// prune entirely so a Prometheus flap cannot reset persistence
	// for pods the failed query alone was flagging.
	if errH == nil && errS == nil {
		p.seen.Prune(func(k string) bool { _, ok := flagged[k]; return ok })
	} else {
		// Carry held series the surviving query did not re-flag —
		// otherwise reconcile deletes gauges the failed family
		// alone was backing. Find accompanies every Carry: a held
		// series is still a live finding, and without it the check
		// would report Pass while the gauge stays 1.
		for k, lv := range p.emitted.Last() {
			if _, ok := flagged[k]; !ok {
				rep.Carry(k, lv)
				rep.Find(k)
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
	// The sibling must be a replica of the SAME controller — a
	// Ready node-local-dns pod is no proof a wedged coredns member
	// can be replaced safely, and two standalone dns pods share no
	// controller key at all.
	want := kube.PodControllerKey(pod)
	for _, s := range siblings {
		if s.Name == pod.Name {
			continue
		}
		if kube.PodControllerKey(s) != want {
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
			// An unscheduled DaemonSet pod (Pending, no node yet)
			// has no failure domain to key a per-node cooldown on;
			// its target would end in "/" and the bounce would be
			// pointless — the scheduler has not even placed it.
			if pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil ||
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
	slices.Sort(flaggedKeys) // deterministic pick for the one-per-cycle heal
	for _, key := range flaggedKeys {
		detail := flagged[key]
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		pod, err := p.Pod(ctx, ns, name)
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("lookup pod %s/%s: %w", ns, name, err)}
		}
		if pod == nil {
			continue
		}
		lv := []string{ns, name}
		rep.Flag(coreDNSUpstreamFailingGauge, key, lv)
		if !healed && hasHealthySibling(pod, dnsByNS[ns], flagged) {
			target := kube.PodControllerKey(pod)
			// node-local-dns is a DaemonSet: every node's agent
			// shares one controller key. Keying the cooldown on it
			// alone would park the WHOLE DaemonSet for 30m after
			// one node's agent is bounced; the node is the real
			// failure domain here (same split as the PromQL path).
			if ctrl := metav1.GetControllerOf(pod); ctrl != nil &&
				ctrl.Kind == "DaemonSet" {
				target += "/" + pod.Spec.NodeName
			}
			hk := probefw.SelfHealKey(CheckNameCoreDNSUpstream, target)
			before, _ := p.Heals.Last(hk)
			p.DeletePodHealScoped(ctx, log, CheckNameCoreDNSUpstream,
				target, pod, coreDNSUpstreamHealCool, now)
			if stamp, ok := p.Heals.Last(hk); ok && stamp.After(before) {
				healed = true
			}
		}
		rep.Find(key + "(" + detail + ")")
	}
	// Prometheus was unreachable — the readiness scan can only
	// re-flag the unready subset. Carry every held series it did
	// not re-flag, or reconcile would read the outage as recovery
	// and prune live alerts (same contract as the degraded-family
	// carry above).
	for k, lv := range p.emitted.Last() {
		if _, ok := flagged[k]; !ok {
			rep.Carry(k, lv)
			rep.Find(k)
		}
	}
	return rep.Result(&p.emitted, coreDNSUpstreamFailingGauge.DeleteLabelValues,
		"coredns/node-local-dns unready pods (prometheus fallback): ", ", ")
}
