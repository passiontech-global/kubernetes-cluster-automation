// sync_audit.go — the cf-gateway-sync-error check of the cf-tunnel
// proxy watchdog: a bounded log-tail audit of the
// cloudflare-tunnel-gateway-controller mirroring sync failures to
// node_automation_cftunnel_gateway_sync_error (split out of
// cftunnel_proxy_watchdog.go — see its header for the module
// contract).
package cftunnelproxywatchdog

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// node_automation_cftunnel_gateway_sync_error is 1 while the last
// cfTunnelSyncErrClearAfter window saw a sync-error signature in the
// controller's log tail, 0 otherwise (set once the first sweep
// detects it — see auditControllerSyncErrors).
var cftunnelGatewaySyncErrorGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cftunnel_gateway_sync_error",
	Help: "1 while the cloudflare-tunnel-gateway-controller log tail (5m window) carries a tunnel-config sync error (failed to update tunnel configuration, 429, authentication error) — cf-gateway-sync-error.",
}, []string{"namespace"})

func init() {
	ctrlmetrics.Registry.MustRegister(cftunnelGatewaySyncErrorGauge)
}

// ---------------------------------------------------------------------------
// cf-gateway-sync-error — cloudflare-tunnel-gateway-controller sync-error audit.
// ---------------------------------------------------------------------------

// auditControllerSyncErrors reads a bounded log tail of every
// cloudflare-tunnel-gateway-controller pod and mirrors the finding to
// node_automation_cftunnel_gateway_sync_error. The gauge sets to 1 on
// the first sweep that sees a signature and only resets to 0 once a
// sweep with a clean tail lands at least cfTunnelSyncErrClearAfter
// after the last errored one — so a single clean sweep sandwiched
// between error sweeps cannot clear a live desync, and an errored or
// empty log read (controller pod restarting) never clears it either.
// Observational only: failures log, they never abort the sweep.
func (w *cfTunnelProxyWatchdog) auditControllerSyncErrors(ctx context.Context) {
	log := logf.FromContext(ctx)
	now := w.now.Now()
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: cfTunnelGatewayCtrlSelector,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(w.cs, w.namespace))
	if err != nil {
		metrics.IncError(w.queue)
		log.Info("WARN: gateway controller pod list failed — sync-error audit skipped",
			"namespace", w.namespace, "error", err.Error())
		return
	}
	errSeen := false
	readOK := false
	readFailed := false
	for i := range pods {
		logs, rerr := w.controllerLogTail(ctx, &pods[i])
		if rerr != nil {
			// A failed read leaves that replica's evidence
			// unverifiable — with 2 replicas a clean read on the
			// other must NOT clear the gauge (the crash-loop shape
			// is exactly when one tail is unreadable).
			readFailed = true
			log.Info("WARN: gateway controller log tail read failed",
				"pod", pods[i].Name, "error", rerr.Error())
			continue
		}
		if strings.TrimSpace(logs) == "" {
			// Empty tail (fresh pod, quiet window) is inconclusive —
			// no clean evidence, so it never clears either.
			continue
		}
		readOK = true
		if controllerSyncErrors(logs) {
			errSeen = true
			break
		}
	}
	if errSeen {
		if w.syncErrLast == nil {
			w.syncErrLast = map[string]time.Time{}
		}
		w.syncErrLast[w.namespace] = now
		cftunnelGatewaySyncErrorGauge.WithLabelValues(w.namespace).Set(1)
		log.Info("gateway controller sync error detected",
			"namespace", w.namespace, "pods", len(pods))
		return
	}
	stamp, ok := w.syncErrLast[w.namespace]
	if ok && readOK && !readFailed && now.Sub(stamp) >= cfTunnelSyncErrClearAfter {
		cftunnelGatewaySyncErrorGauge.WithLabelValues(w.namespace).Set(0)
		delete(w.syncErrLast, w.namespace)
		log.Info("gateway controller sync error cleared",
			"namespace", w.namespace)
	}
}

// controllerLogTail is the bounded GetLogs tail of one controller
// pod: SinceSeconds=300, TailLines=200, byte-capped.
func (w *cfTunnelProxyWatchdog) controllerLogTail(ctx context.Context,
	p *corev1.Pod) (string, error) {
	lctx, cancel := context.WithTimeout(ctx, cfTunnelSyncErrLogTimeout)
	defer cancel()
	since := cfTunnelSyncErrSinceSeconds
	tail := cfTunnelSyncErrTailLines
	stream, err := w.cs.CoreV1().Pods(p.Namespace).GetLogs(p.Name,
		&corev1.PodLogOptions{
			SinceSeconds: &since,
			TailLines:    &tail,
		}).Stream(lctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, cfTunnelSyncErrLogMaxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// controllerSyncErrors matches the observed Cloudflare API sync
// failure signatures in the controller's log (case-insensitive).
func controllerSyncErrors(logs string) bool {
	l := strings.ToLower(logs)
	return strings.Contains(l, "failed to update tunnel configuration") ||
		strings.Contains(l, "429 too many requests") ||
		strings.Contains(l, "authentication error")
}
