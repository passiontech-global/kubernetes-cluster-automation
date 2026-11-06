// linkerd_h2_stream_guard.go — the linkerd-h2-stream-guard check:
// meshed pods whose linkerd-proxy log shows an HTTP/2 stream storm
// (ENHANCE_YOUR_CALM / ping flood / concurrency-limit rejections) or
// an mTLS identity stall (leaf-certificate expiry / issuance loop)
// get deleted once a Ready sibling can absorb the traffic — an
// HTTP/1.1-ready probe can't see a wedged h2 stream table, and a
// proxy whose identity cert expired keeps serving "running" while
// every new connection fails TLS validation.
package nethealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

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
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdH2StreamStalledGauge,
		linkerdProxyIdentityStalledGauge)
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

	current := map[string][]string{}
	identityCurrent := map[string][]string{}
	var findings []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < linkerdH2PodMinAge ||
			!kube.PodSpecHasContainer(&pod.Spec, linkerdProxyContainer) {
			continue
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
		key := pod.Namespace + "/" + pod.Name
		ref := metav1.GetControllerOf(pod)
		if storm {
			lv := []string{pod.Namespace, pod.Name}
			current[key] = lv
			linkerdH2StreamStalledGauge.WithLabelValues(lv...).Set(1)
			findings = append(findings, key)
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
			lv := []string{pod.Namespace, pod.Name}
			identityCurrent[key] = lv
			linkerdProxyIdentityStalledGauge.WithLabelValues(lv...).Set(1)
			if !storm {
				findings = append(findings, key)
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
	sort.Strings(findings)
	p.emitted.Reconcile(current, linkerdH2StreamStalledGauge.DeleteLabelValues)
	p.identityEmitted.Reconcile(identityCurrent, linkerdProxyIdentityStalledGauge.DeleteLabelValues)
	if len(findings) == 0 {
		return probefw.Result{Pass: true}
	}
	return probefw.Result{Why: "meshed pods with a linkerd-proxy failure signature (h2 stream storm / identity cert stall): " +
		strings.Join(findings, ", ")}
}
