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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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
	"stream.Recv",
	"Error receiving event from stream",
	"Error receiving from stream",
	"codes.Unknown",
	"transport is closing",
}

// argocdAgentReconnectMarkers are the successful-reconnect fragments:
// any such line AFTER the last stream error proves the agent already
// recovered from the errors in the tail — no live loop.
var argocdAgentReconnectMarkers = []string{
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
// channel still decides.
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
	if cpuErr != nil {
		log.Info("WARN: argocd-agent spin — cpu channel unavailable",
			"error", cpuErr)
	}
	var rep probefw.SweepReport
	live := map[string]bool{}
	for i := range pods {
		pod := pods[i]
		if !strings.HasPrefix(pod.Name, argocdAgentPrefix) ||
			pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if now.Sub(pod.CreationTimestamp.Time) < argocdAgentMinAge {
			continue // a fresh pod has no spin history worth reading
		}
		reason := ""
		if p.cpuSpin(series, pod) {
			reason = "cpu"
		} else if p.logSpin(ctx, log, pod) {
			reason = "logs"
		}
		if reason == "" {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
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
// recovered from are history, not a live loop. A failed log read is
// inconclusive (false, WARN) per the shared PodLogTail posture; the
// spin needs its OWN scan because the verdict is count- and
// order-sensitive, which the first-match PodLogTail helper cannot
// express.
func (p *argoCDAgentSpinCheck) logSpin(ctx context.Context,
	log logr.Logger, pod *corev1.Pod) bool {

	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tail := int64(argocdAgentTail)
	stream, err := p.CS.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Container: probefw.ResolveDefaultContainer(pod, ""),
			TailLines: &tail,
		}).Stream(lctx)
	if err != nil {
		log.Info("WARN: argocd-agent spin — log channel unavailable",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
		return false
	}
	defer func() { _ = stream.Close() }()
	errs, recovered := scanAgentSpinLines(
		io.LimitReader(stream, argocdAgentLogCap))
	if errs >= argocdAgentMinErrs && !recovered {
		return true
	}
	return false
}

// scanAgentSpinLines counts stream-error lines and reports whether a
// successful-reconnect line appears AFTER the last error line — the
// pure predicate unit tests pin directly.
func scanAgentSpinLines(lines io.Reader) (errs int, recoveredAfter bool) {
	lastErr, lastOK := -1, -1
	// bufio.Scanner's default 64KiB token cap would silently end the
	// scan on one oversized log line and undercount the spin
	// signature — lift it to the same budget as the stream cap.
	sc := bufio.NewScanner(lines)
	sc.Buffer(make([]byte, 0, 64*1024), argocdAgentLogCap)
	i := 0
	for sc.Scan() {
		line := sc.Text()
		for _, m := range argocdAgentSpinErrMarkers {
			if strings.Contains(line, m) {
				errs++
				lastErr = i
				break
			}
		}
		for _, m := range argocdAgentReconnectMarkers {
			if strings.Contains(line, m) {
				lastOK = i
				break
			}
		}
		i++
	}
	return errs, lastOK > lastErr
}
