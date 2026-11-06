// linkerd_h2_stream_guard.go — the linkerd-h2-stream-guard check:
// meshed pods whose linkerd-proxy log shows an HTTP/2 stream storm
// (ENHANCE_YOUR_CALM / ping flood / concurrency-limit rejections)
// get deleted once a Ready sibling can absorb the traffic — an
// HTTP/1.1-ready probe can't see a wedged h2 stream table.
package nethealth

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// linkerdH2StreamGuardCheck is the linkerd HTTP/2 stream-storm
// watchdog.
type linkerdH2StreamGuardCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewLinkerdH2StreamGuardCheck builds the h2 guard — its only state
// is the emitted-gauge ledger; pod-delete cooldowns ride the shared
// Deps.Heals set.
func NewLinkerdH2StreamGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdH2StreamGuardCheck{Deps: d}
}

const (
	CheckNameLinkerdH2StreamGuard = "linkerd-h2-stream-guard"

	// linkerd-h2-stream-guard knobs.
	linkerdH2PodMinAge  = 5 * time.Minute
	linkerdH2HealCool   = 30 * time.Minute
	linkerdH2TailLines  = int64(200)
	linkerdH2LogMaxByte = 256 * 1024
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

var (
	// Pods whose linkerd-proxy reports an HTTP/2 stream storm.
	linkerdH2StreamStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_h2_stream_stalled",
		Help: "1 while the meshed pod's linkerd-proxy log shows an HTTP/2 stream-storm signature.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdH2StreamStalledGauge)
}

// linkerdH2LogStorm fetches the linkerd-proxy container's log tail
// and reports whether any line carries a storm signature. Bounded to
// 8s / linkerdH2LogMaxByte — the same posture as the scylla gossip
// probe; a fetch failure is inconclusive, not healthy.
func (p *linkerdH2StreamGuardCheck) linkerdH2LogStorm(ctx context.Context,
	pod *corev1.Pod) (bool, error) {

	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tail := linkerdH2TailLines
	stream, err := p.CS.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Container: linkerdProxyContainer,
			TailLines: &tail,
		}).Stream(lctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, linkerdH2LogMaxByte))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.ToLower(line)
		for _, marker := range linkerdH2StormMarkers {
			if strings.Contains(l, marker) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkLinkerdH2StreamGuard scans Running meshed pods older than 5m
// for proxy-log HTTP/2 storm signatures. A storming pod is deleted
// only while a Ready sibling under the same controller exists —
// replacing the pod rebuilds the proxy's stream table; without a
// sibling the outage is workload-level and a delete would blackhole
// the service entirely.
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
	readyByOwner := map[types.UID]int{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			!kube.PodReadyCond(pod) {
			continue
		}
		if ref := metav1.GetControllerOf(pod); ref != nil {
			readyByOwner[ref.UID]++
		}
	}

	current := map[string][]string{}
	var findings []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < linkerdH2PodMinAge ||
			!kube.PodSpecHasContainer(&pod.Spec, linkerdProxyContainer) {
			continue
		}
		storm, err := p.linkerdH2LogStorm(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken pod-log path must
			// not silently read as "no storm".
			log.Info("WARN: linkerd-proxy log fetch failed — storm signature inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", err)
			continue
		}
		if !storm {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		lv := []string{pod.Namespace, pod.Name}
		current[key] = lv
		linkerdH2StreamStalledGauge.WithLabelValues(lv...).Set(1)
		findings = append(findings, key)

		ref := metav1.GetControllerOf(pod)
		if ref == nil {
			log.Info("skip heal: unowned pod — no sibling can absorb traffic",
				"pod", key)
			continue
		}
		// The storming pod itself counts toward its owner's Ready
		// total when it is Ready — a h2 wedge does not break the
		// HTTP/1.1 probe. Subtract self so the guard requires a
		// GENUINELY separate sibling.
		siblings := readyByOwner[ref.UID]
		if kube.PodReadyCond(pod) {
			siblings--
		}
		if siblings < 1 {
			log.Info("skip heal: no Ready sibling replica — delete would blackhole the workload",
				"pod", key)
			continue
		}
		p.DeletePodHeal(ctx, log, CheckNameLinkerdH2StreamGuard,
			key, pod, linkerdH2HealCool, now)
	}
	sort.Strings(findings)
	p.emitted.Reconcile(current, linkerdH2StreamStalledGauge.DeleteLabelValues)
	if len(findings) == 0 {
		return probefw.Result{Pass: true}
	}
	return probefw.Result{Why: "meshed pods with an HTTP/2 stream storm in the proxy log: " +
		strings.Join(findings, ", ")}
}
