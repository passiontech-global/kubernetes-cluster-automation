// argocd_agent_spin.go — the argocd-agent-spin check (argocd-agent-spin): the
// argocd-agent-agent pods stuck in a gRPC dead-stream reconnect
// hot-loop. When the agent's stream to the remote ArgoCD dies
// without a clean close, the client spins: Recv returns an error
// instantly, the agent reconnects, the new stream dies the same way
// — a 100%-CPU loop that serves no events. A pod restart forces a
// fresh connection setup and breaks the loop.
//
// Detection uses two independent channels, either one alone spins
// the heal:
//   - (a) Prometheus: per-pod container CPU rate over 15m above
//     argocdAgentSpinCPU — the hot loop burns a full core while a
//     healthy idle agent sits near zero;
//   - (b) log tail: >= argocdAgentSpinMinLogErrors repeated stream
//     error lines in the last argocdAgentSpinLogTailLines with NO
//     successful-reconnect line AFTER the last error — errors the
//     agent already recovered from are history, not a live loop.
//
// The signature must persist across the FirstSeenLedger window (one
// spin cycle between two sweeps re-arms; a sustained loop deletes
// the pod on a per-pod cooldown, riding the shared heal gate —
// maintenance mutex + heal budget fail closed).
package gitops

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// argoCDAgentSpinCheck is the argocd-agent reconnect hot-loop
// detector with the pod-delete heal.
type argoCDAgentSpinCheck struct {
	*probefw.Deps

	// seen tracks each spinning pod's first-seen sweep — the
	// persistence clock gating the delete (in-RAM: the pod that
	// restarts under the heal starts a fresh window, exactly the
	// re-arm the check needs).
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]
	// logScanAt is the per-pod last-log-scan clock — the freshness
	// gate requires at least one error line whose kubelet timestamp
	// post-dates the pod's previous scan, so a SinceSeconds window
	// overlapping across sweeps cannot re-flag an error that already
	// stopped (and possibly self-healed) minutes ago.
	logScanAt map[string]time.Time
}

// NewArgoCDAgentSpinCheck builds the argocd-agent-spin check — its state is the
// seen/emitted ledgers (zero value usable); the delete cooldown
// rides the shared Deps.Heals set.
func NewArgoCDAgentSpinCheck(d *probefw.Deps) probefw.Check {
	return &argoCDAgentSpinCheck{Deps: d}
}

const (
	CheckNameArgoCDAgentSpin = "argocd-agent-spin"

	// argocd-agent-spin — argocd-agent-spin knobs. The agent install lives in
	// the argocd namespace with the argocd-agent-agent- name prefix
	// (argocd-agent upstream's default naming).
	argocdAgentNS      = "argocd"
	argocdAgentPrefix  = "argocd-agent-agent-"
	argocdAgentMinAge  = 10 * time.Minute
	argocdAgentWindow  = 10 * time.Minute
	argocdAgentCool    = 30 * time.Minute
	argocdAgentCPU     = 0.5
	argocdAgentTail    = 250
	argocdAgentLogCap  = 1 << 20
	argocdAgentMinErrs = 15
)

// argocdAgentSpinErrMarkers are the repeated stream-error fragments
// the dead-stream loop stamps per Recv round; the count is the
// spin's log-side signal.
var argocdAgentSpinErrMarkers = []string{
	"stream.recv",
	"error receiving event from stream",
	"error receiving from stream",
	"codes.unknown",
	"transport is closing",
}

// argocdAgentReconnectMarkers are the successful-reconnect fragments:
// any such line AFTER the last stream error proves the agent already
// recovered from the errors in the tail — no live loop.
var argocdAgentReconnectMarkers = []string{
	// "connected" is a substring of "(dis)connected" — the scan
	// excludes lines also containing "disconnect" so a teardown
	// line never reads as a successful reconnect.
	"connected",
	"connection established",
	"stream established",
	"reconnected",
}

var (
	// argocd-agent-spin — spinning argocd-agent-agent pods.
	argocdAgentSpinGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_argocd_agent_spin",
		Help: "1 while an argocd-agent-agent pod shows the gRPC dead-stream reconnect hot-loop (CPU or log channel) — argocd-agent-spin.",
	}, []string{"namespace", "pod", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		argocdAgentSpinGauge)
}

// argocdAgentCPUQuery is the hot-loop's Prometheus channel: per-pod
// container CPU rate in the argocd namespace, POD pseudo-container
// and empty names excluded like every cAdvisor consumer.
const argocdAgentCPUQuery = `sum by (pod) (rate(container_cpu_usage_seconds_total{` +
	`namespace="argocd",pod=~"argocd-agent-agent-.*",container!~"POD|"}[15m]))`

// Run audits the argocd-agent-agent pods: Running, >= argocdAgentMinAge
// old, spinning per the CPU channel OR the log channel. The
// signature must persist across argocdAgentWindow before the pod
// delete fires; detection alone emits the gauge every sweep. A
// missing/unresolvable Prometheus endpoint or a failed log read
// downgrades THAT channel to unavailable, not clean — the other
// channel still decides; with BOTH channels unavailable the sweep is
// inconclusive and the pod's first-seen entry carries through the
// keep-set (the Prune contract: never wipe a clock the sweep could
// not re-evaluate).
func (p *argoCDAgentSpinCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	pods, err := p.PodsMatching(ctx, argocdAgentNS, "")
	if err != nil {
		return probefw.Result{Infra: err}
	}
	// The CPU channel's instant query runs ONCE per sweep — querying
	// inside the pod loop would stamp N identical PromQL evaluations
	// for the same series set.
	series, cpuErr := p.PromQuery(ctx, argocdAgentCPUQuery)
	cpuOK := cpuErr == nil
	if cpuErr != nil {
		log.Info("WARN: argocd-agent spin — cpu channel unavailable",
			"error", cpuErr)
	}
	var rep probefw.SweepReport
	live := map[string]bool{}
	// scanLive tracks every pod that passed the candidacy filters —
	// NOT just the ones the log channel read. A pod whose CPU
	// channel answered never paid a log fetch this sweep, but it is
	// still a live candidate: dropping its scan boundary would make
	// the NEXT log read bootstrap fresh and re-flag error lines the
	// overlapping 15m tail already counted.
	scanLive := map[string]bool{}
	for i := range pods {
		pod := pods[i]
		if !strings.HasPrefix(pod.Name, argocdAgentPrefix) ||
			pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if !kube.AgeAtLeast(pod.CreationTimestamp.Time, now, argocdAgentMinAge) {
			continue // a fresh pod has no spin history worth reading
		}
		key := pod.Namespace + "/" + pod.Name
		scanLive[key] = true
		reason := ""
		logOK := true
		if p.cpuSpin(series, pod) {
			reason = "cpu"
		} else if spin, lerr := p.logSpin(ctx, log, pod, key, now); lerr != nil {
			logOK = false // fetch failed — inconclusive, not clean
		} else if spin {
			reason = "logs"
		}
		if !cpuOK && !logOK {
			// Both channels unevaluable this sweep — inconclusive,
			// not clean. Carry the key through the keep-set so the
			// Prune below cannot wipe the first-seen clock the sweep
			// could not re-evaluate (a flaky-evidence spin would
			// otherwise never reach argocdAgentWindow), and carry the
			// pod's held gauge series so the sweep-end reconcile does
			// not read "can't tell" as "resolved" (same contract the
			// ksm-wedge scan runs).
			log.Info("WARN: argocd-agent spin — cpu + log channels both unavailable, spin unverifiable",
				"pod", key)
			live[key] = true
			for k, lv := range p.emitted.Last() {
				if strings.HasPrefix(k, key+"/") {
					rep.Carry(k, lv)
					// A carried series IS an active warning — record
					// the finding too, or Result.Pass reports true
					// while a spin alert stays live.
					rep.Find("argocd-agent spin " + key +
						" (carried — evidence channels unavailable)")
				}
			}
			continue
		}
		if reason == "" {
			continue
		}
		live[key] = true
		first, seenBefore := p.seen.Observe(key, now)
		// The emitted series key carries the reason so a channel flap
		// prunes the stale series instead of leaking two live ones.
		rep.Emit(argocdAgentSpinGauge, key+"/"+reason,
			[]string{pod.Namespace, pod.Name, reason},
			"argocd-agent spin "+key+" ("+reason+")")
		if !seenBefore || now.Sub(first) < argocdAgentWindow {
			continue // first sighting — the window decides next sweep
		}
		// Cooldown keys on the pod's controller, not the pod name —
		// a Deployment recreates the agent pod under a fresh random
		// suffix, and a "ns/pod" key would let the replacement pod
		// bypass the 30m delete cooldown on its very first spin.
		p.DeletePodHeal(ctx, log, CheckNameArgoCDAgentSpin,
			"agent/"+kube.PodControllerKey(pod), pod, argocdAgentCool, now)
	}
	p.seen.Prune(func(k string) bool { return live[k] })
	// The log-scan clock only tracks pods still in the candidate
	// set — a pod whose CPU channel answered keeps its boundary at
	// the last real log read, and entries for pods that left
	// candidacy entirely (renamed, deleted, too fresh) are dropped
	// so a re-entering pod bootstraps against its own last scan.
	for k := range p.logScanAt {
		if !scanLive[k] {
			delete(p.logScanAt, k)
		}
	}
	return rep.Result(&p.emitted, argocdAgentSpinGauge.DeleteLabelValues,
		"argocd-agent spin pods: ", ", ")
}

// cpuSpin is channel (a): the per-pod 15m CPU rate from the sweep's
// single instant-query result. A failed query (series nil, logged at
// WARN by Run) is inconclusive, not clean — the same posture the
// metrics-backed nethealth checks document.
func (p *argoCDAgentSpinCheck) cpuSpin(
	series []promq.Sample, pod *corev1.Pod) bool {

	for _, s := range series {
		if s.Label("pod") == pod.Name && s.Value > argocdAgentCPU {
			return true
		}
	}
	return false
}

// logSpin is channel (b): the last argocdAgentTail log lines scanned
// for the repeated stream-error signature with no successful
// reconnect after the LAST error — errors the agent already
// recovered from are history, not a live loop. A failed log read
// returns the error — inconclusive, never clean (the caller keeps
// the pod's first-seen entry through sweeps it could not evaluate);
// the spin needs its OWN scan because the verdict is count- and
// order-sensitive, which the first-match PodLogTail helper cannot
// express.
func (p *argoCDAgentSpinCheck) logSpin(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, key string, now time.Time) (bool, error) {

	text, err := kube.ReadPodLogText(ctx, p.CS, pod, kube.PodLogOpts{
		TailLines:    argocdAgentTail,
		SinceSeconds: 900,
		MaxBytes:     argocdAgentLogCap,
		Timeout:      30 * time.Second,
		Timestamps:   true,
	})
	if err != nil {
		log.Info("WARN: argocd-agent spin — log channel unavailable",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return false, err
	}
	// The scan boundary advances on every SUCCESSFUL fetch — a
	// failed read must not push it forward (the next good scan
	// would then skip lines written during the outage).
	if p.logScanAt == nil {
		p.logScanAt = map[string]time.Time{}
	}
	prevScan, scanned := p.logScanAt[key]
	// freshOnly makes the scanner count ONLY error lines newer than
	// this pod's previous scan — the 15m tail overlaps across
	// sweeps, so counting the whole window would double-count an
	// incident that already stopped. The boundary itself advances
	// in the KUBELET's clock domain: streamNewest is the newest
	// stamp on any line read; `now` (controller clock) is only the
	// fallback for a stream with no parseable timestamp at all.
	errs, recovered, newestErr, streamNewest := scanAgentSpinLines(
		strings.NewReader(text), prevScan, scanned)
	if streamNewest.IsZero() {
		p.logScanAt[key] = now
	} else {
		p.logScanAt[key] = streamNewest
	}
	if errs < argocdAgentMinErrs || recovered {
		return false, nil
	}
	// Freshness gate: newestErr is the newest stamp among the
	// COUNTED (fresh) error lines — zero means the counted errors
	// carried no parseable stamp, which counts as fresh (fail
	// toward alerting, never toward silence).
	if scanned && !newestErr.IsZero() && !newestErr.After(prevScan) {
		return false, nil
	}
	return true, nil
}

// scanAgentSpinLines counts stream-error lines, reports whether a
// successful-reconnect line appears AFTER the last error line, and
// returns two clocks: newestErrTS is the newest kubelet timestamp
// among the COUNTED error lines (zero when none carried a stamp —
// the caller's freshness gate counts that as fresh), and
// streamNewestTS is the newest stamp on ANY line read — the scan
// boundary the caller stores, kept in the kubelet's clock domain.
// When freshOnly is set (a previous scan boundary exists), only
// error lines stamped AFTER freshAfter count toward errs and
// newestErrTS — the bounded tail overlaps across sweeps, so
// counting the whole window would double-count an incident that
// already stopped. Error lines with no parseable stamp count as
// fresh (fail toward alerting). The reconnect check still scans
// the whole window: a recovery anywhere after the last error —
// stale or fresh — ends the spin.
func scanAgentSpinLines(lines io.Reader, freshAfter time.Time,
	freshOnly bool) (errs int, recoveredAfter bool, newestErrTS, streamNewestTS time.Time) {
	lastErr, lastOK := -1, -1
	// bufio.Scanner's default 64KiB token cap would silently end the
	// scan on one oversized log line and undercount the spin
	// signature — lift it to the same budget as the stream cap.
	sc := bufio.NewScanner(lines)
	sc.Buffer(make([]byte, 0, 64*1024), argocdAgentLogCap)
	i := 0
	for sc.Scan() {
		raw := sc.Text()
		ts, hasTS := kube.PodLogLineTS(raw)
		if hasTS && ts.After(streamNewestTS) {
			streamNewestTS = ts
		}
		// Case-fold once per line: marker casing in agent logs varies
		// across versions, and a missed reconnect marker reads a
		// recovered agent as still spinning.
		line := strings.ToLower(raw)
		for _, m := range argocdAgentSpinErrMarkers {
			if strings.Contains(line, m) {
				if !freshOnly || !hasTS || ts.After(freshAfter) {
					errs++
					if hasTS && ts.After(newestErrTS) {
						newestErrTS = ts
					}
				}
				lastErr = i
				break
			}
		}
		for _, m := range argocdAgentReconnectMarkers {
			// "connected" also matches "(dis)connected" — a
			// teardown/disconnect line is never a reconnect. The
			// plain "disconnect" substring check cannot see the
			// parenthesized spelling (the ')' breaks it), so
			// exclude that shape explicitly.
			if strings.Contains(line, m) &&
				!strings.Contains(line, "disconnect") &&
				!strings.Contains(line, "(dis)connected") {
				lastOK = i
				break
			}
		}
		i++
	}
	return errs, lastOK > lastErr, newestErrTS, streamNewestTS
}
