// linkerd_h2_stream_guard.go — the linkerd-h2-stream-guard check:
// meshed pods whose linkerd-proxy log shows an HTTP/2 stream storm
// (ENHANCE_YOUR_CALM / ping flood / concurrency-limit rejections) or
// an mTLS identity stall (leaf-certificate expiry / issuance loop)
// get deleted once a Ready sibling can absorb the traffic — an
// HTTP/1.1-ready probe can't see a wedged h2 stream table, and a
// proxy whose identity cert expired keeps serving "running" while
// every new connection fails TLS validation.
//
// W12-NM3 adds the outbound failure-accrual lockout: a client proxy
// whose balancer holds endpoints for a Service but NONE in
// state="ready" (outbound_http_balancer_endpoints) is circuit-broken
// long after the destination recovered — detected via Prometheus,
// cross-checked against live EndpointSlices so a genuine
// zero-endpoint outage is not misread as a wedge, and healed by the
// same Ready-sibling-gated pod delete. The sweep also reports
// linkerd-proxy OOM kills on
// node_automation_linkerd_proxy_oomkilled.
package nethealth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/go-logr/logr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// linkerdH2StreamGuardCheck is the linkerd HTTP/2 stream-storm and
// mTLS identity-stall watchdog — one proxy-log tail feeds both
// signature families.
type linkerdH2StreamGuardCheck struct {
	*probefw.Deps

	// emitted is the storm-gauge ledger and identityEmitted the
	// identity-gauge ledger — a tuple that stops being reported gets
	// DeleteLabelValues'd rather than leaking a stale 1 (zero value
	// usable; the serial sweep needs no lock).
	emitted         state.GaugeLedger[string]
	identityEmitted state.GaugeLedger[string]
	// W12-NM3 — balancerEmitted/oomEmitted are the emitted-gauge
	// ledgers for the outbound-balancer wedge and proxy-OOMKilled
	// gauges; balancerSeen tracks each wedged
	// "ns/pod/target_addr" tuple's first sighting for the >=10m
	// persistence window (in-RAM only — an operator restart costing
	// one re-armed window is the safe direction; the window gates a
	// pod delete but the pod itself is the delete target, so a
	// persisted stamp would die with it anyway).
	balancerEmitted state.GaugeLedger[string]
	oomEmitted      state.GaugeLedger[string]
	balancerSeen    state.FirstSeenLedger
}

// NewLinkerdH2StreamGuardCheck builds the h2 guard — its only state
// is the emitted-gauge ledgers; pod-delete cooldowns ride the shared
// Deps.Heals set.
func NewLinkerdH2StreamGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdH2StreamGuardCheck{Deps: d}
}

const (
	CheckNameLinkerdH2StreamGuard = "linkerd-h2-stream-guard"

	// linkerd-h2-stream-guard knobs.
	linkerdH2PodMinAge  = 5 * time.Minute
	linkerdH2HealCool   = 30 * time.Minute
	linkerdH2LogTimeout = 8 * time.Second
	linkerdH2TailLines  = int64(200)
	linkerdH2LogMaxByte = int64(256 * 1024)

	// W12-NM3 — a balancer with no ready endpoint must hold that
	// shape this long before it counts as failure-accrual lockout
	// rather than ordinary failover churn.
	linkerdBalancerWedgeMinAge = 10 * time.Minute
)

// linkerdH2StormMarkers are the proxy-log signatures of an HTTP/2
// connection whose stream table went pathological — a stalled h2
// stream keeps the pod Ready (readiness probes ride HTTP/1.1) while
// multiplexed traffic wedges behind it.
var linkerdH2StormMarkers = []string{
	"enhance_your_calm",
	"too_many_pings",
	"in-flight requests exceeded concurrency limit",
}

// linkerdIdentityStallMarkers are the proxy-log signatures of an
// mTLS identity whose leaf certificate lapsed or whose issuance
// loop wedged — the proxy keeps running (and the pod stays Ready)
// but every new connection fails certificate validation, so the
// only cure is recreating the pod for a fresh leaf cert. Spellings
// cover both linkerd's Rust Debug rendering ("CertificateExpired",
// "InvalidCertificate(Expired)") and the certifier client errors
// (matched case-insensitively per line, like the storm markers).
var linkerdIdentityStallMarkers = []string{
	"certificateexpired",
	"certificate_expired",
	"invalidcertificate(expired)",
	// W12-NM3 — the not-yet-valid leaf (issued-at skew) and the
	// unknown-issuer (trust-root rotation skew) spellings stall the
	// identity exactly like an expiry: every new connection fails
	// validation while the pod stays Ready.
	"invalidcertificate(notvalidyet)",
	"unknownissuer",
	"failed to certify identity",
}

var (
	// Pods whose linkerd-proxy reports an HTTP/2 stream storm.
	linkerdH2StreamStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_h2_stream_stalled",
		Help: "1 while the meshed pod's linkerd-proxy log shows an HTTP/2 stream-storm signature.",
	}, []string{"namespace", "pod"})

	// Pods whose linkerd-proxy reports an expired/stalled mTLS
	// identity leaf certificate — the pod is recreated so the proxy
	// is issued a fresh one.
	linkerdProxyIdentityStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_proxy_identity_stalled",
		Help: "1 while the meshed pod's linkerd-proxy log shows an mTLS identity leaf-certificate expiry or issuance-loop signature.",
	}, []string{"namespace", "pod"})

	// W12-NM3 — pods whose linkerd-proxy keeps endpoints for a
	// target but ZERO in state="ready" past the persistence window,
	// while the destination Service still has Ready endpoints: the
	// client-side failure-accrual / dead-channel lockout.
	linkerdOutboundBalancerWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_outbound_balancer_wedged",
		Help: "1 while the meshed pod's outbound balancer holds endpoints for a target but none in state=ready for >=10m with the destination healthy.",
	}, []string{"namespace", "pod"})

	// W12-NM3 — pods whose linkerd-proxy container last terminated
	// on OOMKilled: an OOM'd proxy loses its connection table and
	// balancer state on restart, the silent wedge seed.
	linkerdProxyOOMKilledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_proxy_oomkilled",
		Help: "1 while the meshed pod's linkerd-proxy container last terminated with Reason=OOMKilled.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdH2StreamStalledGauge,
		linkerdProxyIdentityStalledGauge,
		linkerdOutboundBalancerWedgedGauge,
		linkerdProxyOOMKilledGauge)
}

// linkerdH2LogSignals fetches the linkerd-proxy container's log tail
// once and reports which signature families it carries — the storm
// and identity-stall scans share the single bounded fetch
// (linkerdH2LogTimeout / linkerdH2LogMaxByte, same posture as the
// scylla gossip probe) so a flagged pod costs one apiserver read.
// The match closure only COLLECTS; it returns true early solely
// when both families are already proven, so PodLogTail can stop
// scanning. A fetch failure is inconclusive, not healthy.
func (p *linkerdH2StreamGuardCheck) linkerdH2LogSignals(ctx context.Context,
	pod *corev1.Pod) (storm, identity bool, err error) {

	_, err = probefw.PodLogTail(ctx, p.CS, pod, linkerdProxyContainer,
		linkerdH2TailLines, linkerdH2LogMaxByte, linkerdH2LogTimeout,
		func(line string) bool {
			l := strings.ToLower(line)
			for _, marker := range linkerdH2StormMarkers {
				if strings.Contains(l, marker) {
					storm = true
					break
				}
			}
			for _, marker := range linkerdIdentityStallMarkers {
				if strings.Contains(l, marker) {
					identity = true
					break
				}
			}
			return storm && identity
		})
	return storm, identity, err
}

// checkLinkerdH2StreamGuard scans Running meshed pods older than 5m
// for proxy-log failure signatures. A storming pod is deleted only
// while a Ready sibling under the same controller exists — replacing
// the pod rebuilds the proxy's stream table; without a sibling the
// outage is workload-level and a delete would blackhole the service
// entirely. An identity-stalled pod (expired leaf cert / wedged
// issuance loop) rides the same safe-evict path — the maintenance
// mutex via DeletePodHeal→heal.AllowedV and the 30m cooldown — gated
// on readyByOwner[ref.UID] >= 2 so at least one genuinely separate
// Ready replica survives the eviction; the replacement pod is issued
// a fresh leaf certificate.
func (p *linkerdH2StreamGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	// Ready siblings per controller UID — the heal's "someone can
	// absorb the traffic" proof.
	readyByOwner := probefw.ReadyByOwner(pods.Items)

	var rep, identityRep, oomRep, balancerRep probefw.SweepReport
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < linkerdH2PodMinAge ||
			!kube.PodSpecHasContainer(&pod.Spec, linkerdProxyContainer) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		lv := []string{pod.Namespace, pod.Name}
		// W12-NM3 — an OOM-killed linkerd-proxy loses its whole
		// connection table and balancer state on restart: report
		// the restart shape even when the replacement is already
		// serving (it is the silent wedge seed, and the restart
		// count alone never attributes the kill).
		if linkerdProxyOOMKilled(pod) {
			oomRep.Flag(linkerdProxyOOMKilledGauge, key, lv)
			rep.Find(key + "(linkerd-proxy OOMKilled)")
		}
		storm, identity, err := p.linkerdH2LogSignals(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken pod-log path must
			// not silently read as "no signature".
			log.Info("WARN: linkerd-proxy log fetch failed — log signatures inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", err)
			continue
		}
		if !storm && !identity {
			continue
		}
		ref := metav1.GetControllerOf(pod)
		if storm {
			rep.Flag(linkerdH2StreamStalledGauge, key, lv)
			rep.Find(key)
			if ref == nil {
				log.Info("skip heal: unowned pod — no sibling can absorb traffic",
					"pod", key)
			} else if probefw.ReadySiblings(readyByOwner, pod) < 1 {
				// The storming pod itself counts toward its owner's
				// Ready total when it is Ready — a h2 wedge does not
				// break the HTTP/1.1 probe. ReadySiblings subtracts
				// self so the guard requires a GENUINELY separate
				// sibling.
				log.Info("skip heal: no Ready sibling replica — delete would blackhole the workload",
					"pod", key)
			} else {
				p.DeletePodHeal(ctx, log, CheckNameLinkerdH2StreamGuard,
					key, pod, linkerdH2HealCool, now)
			}
		}
		if identity {
			identityRep.Flag(linkerdProxyIdentityStalledGauge, key, lv)
			if !storm {
				rep.Find(key)
			}
			// The safe-evict gate needs TWO Ready pods under the
			// same controller: the stalled pod may still report
			// Ready (a leaf-cert lapse does not break the HTTP/1.1
			// probe), so >=2 guarantees a genuinely separate replica
			// absorbs the traffic while the replacement is issued a
			// fresh leaf cert. Same 30m cooldown key as the storm
			// path — one delete heals both signatures.
			if ref == nil {
				log.Info("skip identity heal: unowned pod — no sibling can absorb traffic",
					"pod", key)
			} else if readyByOwner[ref.UID] < 2 {
				log.Info("skip identity heal: fewer than 2 Ready pods under the controller — evict would blackhole the workload",
					"pod", key)
			} else {
				p.DeletePodHeal(ctx, log, CheckNameLinkerdH2StreamGuard,
					key, pod, linkerdH2HealCool, now)
			}
		}
	}
	rep.Close(&p.emitted, linkerdH2StreamStalledGauge.DeleteLabelValues)
	identityRep.Close(&p.identityEmitted, linkerdProxyIdentityStalledGauge.DeleteLabelValues)
	oomRep.Close(&p.oomEmitted, linkerdProxyOOMKilledGauge.DeleteLabelValues)

	// W12-NM3 — outbound balancer lockout: the client-side proxies
	// whose failure-accrual kept a target dead after it recovered.
	p.scanOutboundBalancers(ctx, log, now, pods.Items, readyByOwner,
		&rep, &balancerRep)
	balancerRep.Close(&p.balancerEmitted,
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues)

	return rep.Verdict(
		"meshed pods with a linkerd-proxy failure signature (h2 stream storm / identity cert stall / OOM kill / outbound balancer wedge): ", ", ")
}

// ---------------------------------------------------------------------------
// W12-NM3 — outbound balancer lockout & proxy OOM detection
// ---------------------------------------------------------------------------

// linkerdProxyOOMKilled reports whether the pod's linkerd-proxy
// container last terminated on OOMKilled — the wedge seed: an OOM'd
// proxy restarts with an empty connection table and re-learns its
// balancer view, which is exactly how a client-side dead-channel
// lockout starts.
func linkerdProxyOOMKilled(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name != linkerdProxyContainer {
			continue
		}
		t := cs.LastTerminationState.Terminated
		return t != nil && t.Reason == "OOMKilled"
	}
	return false
}

// linkerdTargetService parses a linkerd target_addr label back to the
// Service it fronts — svc.ns.svc.cluster.local[:port] or the short
// svc.ns.svc[:port] shape — so the wedge candidate can be
// cross-checked against the live EndpointSlices. Unresolvable
// targets (IP literals, external authorities) report ok=false — the
// wedge cannot be disproven and stands.
func linkerdTargetService(targetAddr string) (ns, name string, ok bool) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr // port-less or unparseable — try as-is
	}
	// DNS-1123 names carry no dots, so the first two labels are
	// always <name>.<ns> on the standard cluster suffixes.
	parts := strings.Split(host, ".")
	if len(parts) == 5 && parts[2] == "svc" &&
		parts[3] == "cluster" && parts[4] == "local" {
		return parts[1], parts[0], true
	}
	if len(parts) == 3 && parts[2] == "svc" {
		return parts[1], parts[0], true
	}
	return "", "", false
}

// readyEndpointsByService counts Ready endpoints per "ns/svc" across
// the live EndpointSlices — the wedge cross-check's ground truth.
// Ready==nil counts as ready (the same convention every slice census
// in this package uses). A list failure returns nil so callers can
// tell "census unverifiable" from "genuinely zero endpoints".
func (p *linkerdH2StreamGuardCheck) readyEndpointsByService(
	ctx context.Context) (map[string]int, error) {

	ready := map[string]int{}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.EndpointSlices(p.CS, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						continue
					}
					if len(ep.Addresses) > 0 {
						ready[s.Namespace+"/"+svc]++
					}
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return ready, nil
}

// scanOutboundBalancers implements the W12-NM3 outbound
// failure-accrual lockout detection: a meshed client pod whose
// linkerd-proxy holds balancer endpoints for a target but reports
// ZERO in state="ready" is circuit-broken — the destination
// recovered, the client never did. The signal must persist
// linkerdBalancerWedgeMinAge (probefw.Persisted on the in-RAM
// balancerSeen ledger) and is cross-checked against live
// EndpointSlices: a target Service that genuinely has 0 ready
// endpoints cluster-wide is a real outage the proxy is reporting
// honestly — bouncing it heals nothing. Confirmed wedges emit
// node_automation_linkerd_outbound_balancer_wedged and get the same
// Ready-sibling-gated DeletePodHeal as the storm path (shared 30m
// cooldown key).
func (p *linkerdH2StreamGuardCheck) scanOutboundBalancers(
	ctx context.Context, log logr.Logger, now time.Time,
	pods []corev1.Pod, readyByOwner map[types.UID]int,
	rep, balancerRep *probefw.SweepReport) {

	// The balancer series only exists where a Prometheus endpoint
	// resolves — same "no endpoint configured, skip" gate the other
	// metrics-backed signals use (PromQuery would resolve-and-fail
	// the same way, this just skips the noise).
	if _, err := p.PromEndpoint(); err != nil {
		return
	}

	// "total > 0 AND ready == 0" per (namespace, pod, target_addr)
	// is diffed client-side across two instant queries: the literal
	// `> 0 and == 0` single query never matches — the
	// sum(...{state="ready"}) side produces an EMPTY vector for the
	// wedged tuple, and PromQL's `and` intersects it away.
	totals, err := p.PromQuery(ctx,
		`sum by (namespace, pod, target_addr) (outbound_http_balancer_endpoints)`)
	if err != nil {
		log.Info("WARN: linkerd balancer endpoints query failed — wedge signal skipped",
			"error", err)
		return
	}
	readySeries, err := p.PromQuery(ctx,
		`sum by (namespace, pod, target_addr) (outbound_http_balancer_endpoints{state="ready"})`)
	if err != nil {
		log.Info("WARN: linkerd balancer ready-endpoints query failed — wedge signal skipped",
			"error", err)
		return
	}
	readyByTarget := map[string]float64{}
	for _, s := range readySeries {
		readyByTarget[s.Label("namespace")+"/"+s.Label("pod")+
			"/"+s.Label("target_addr")] = s.Value
	}
	podByKey := map[string]*corev1.Pod{}
	for i := range pods {
		podByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}

	// The EndpointSlice cross-check census is lazy — one
	// cluster-wide read happens only when a wedge candidate needs
	// disambiguating from a genuine outage.
	var svcReady map[string]int
	svcReadyOK, svcReadyLoaded := false, false
	serviceReadyEndpoints := func(ns, svc string) (int, bool) {
		if !svcReadyLoaded {
			svcReadyLoaded = true
			svcReady, err = p.readyEndpointsByService(ctx)
			if err != nil {
				// Can't tell — a failed census must not skip every
				// candidate (can't disprove the wedge), but must not
				// fail the sweep either.
				log.Info("WARN: endpointslices list failed — balancer-wedge cross-check disabled",
					"error", err)
			} else {
				svcReadyOK = true
			}
		}
		return svcReady[ns+"/"+svc], svcReadyOK
	}

	keep := map[string]bool{}
	for _, s := range totals {
		ns, podName, target := s.Label("namespace"), s.Label("pod"),
			s.Label("target_addr")
		if ns == "" || podName == "" || s.Value <= 0 {
			continue
		}
		if readyByTarget[ns+"/"+podName+"/"+target] > 0 {
			continue // balancer still has a live endpoint — healthy
		}
		key := ns + "/" + podName + "/" + target
		keep[key] = true
		if svcNS, svcName, ok := linkerdTargetService(target); ok {
			if n, censusOK := serviceReadyEndpoints(svcNS, svcName); censusOK && n == 0 {
				// The target Service genuinely has zero ready
				// endpoints cluster-wide — a real outage, not a
				// wedge. The proxy is reporting honestly.
				continue
			}
		}
		if !probefw.Persisted(&p.balancerSeen, key, now,
			linkerdBalancerWedgeMinAge, log) {
			continue
		}
		podKey := ns + "/" + podName
		lv := []string{ns, podName}
		balancerRep.Flag(linkerdOutboundBalancerWedgedGauge, key, lv)
		rep.Find(podKey + "(outbound balancer wedged: " + target + ")")
		pod := podByKey[podKey]
		switch {
		case pod == nil || pod.DeletionTimestamp != nil:
			// Gone or going — nothing to bounce; the replacement
			// proxy rebuilds its balancer view anyway.
		case probefw.ReadySiblings(readyByOwner, pod) < 1:
			log.Info("skip balancer-wedge heal: no Ready sibling replica — delete would blackhole the workload",
				"pod", podKey)
		default:
			p.DeletePodHeal(ctx, log, CheckNameLinkerdH2StreamGuard,
				podKey, pod, linkerdH2HealCool, now)
		}
	}
	p.balancerSeen.Prune(func(k string) bool { return keep[k] })
}
