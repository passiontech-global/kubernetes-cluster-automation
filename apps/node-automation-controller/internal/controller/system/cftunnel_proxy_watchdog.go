// cftunnel_proxy_watchdog.go — port of the
// cloudflare-tunnel-proxy-config-watchdog CronJob (infrastructure/
// base/helm/helm-releases/cloudflare-tunnel-gateway-controller/
// proxy-config-watchdog.yaml in passiontech-fluxcd).
//
// Self-heals two dead-but-observed failure modes of the proxy
// gateway (2026-09-30):
//
//  1. A fresh proxy pod sits Running but /readyz reports "no config
//     loaded" forever: the controller's endpoint-reconciler pushes
//     config on EndpointSlice events and the new pod's event is
//     occasionally missed -> it never receives config -> never Ready
//     -> the rollout never finishes. Fix: re-annotate the headless
//     EndpointSlice, which emits an event -> the reconciler resyncs
//     and pushes config to every endpoint (incl. notReady ones, via
//     publishNotReadyAddresses). Harmless during normal pod startup,
//     so no age filter — same as the shell.
//
//  2. The Deployment carries a stale Progressing/ProgressDeadlineExceeded
//     condition from a previous failed rollout: every later helm
//     upgrade dies "failed early due to stalled resources" and the
//     rollback fails too — permanent deadlock. Fix: remove the
//     condition via a status JSONPatch; the controller re-sets it
//     itself if the rollout is genuinely still stalled.
//
// namespace is configurable because the helm release's namespace
// differs per cluster (base default: cloudflare-tunnel-system).
package system

import (
	"context"
	"fmt"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	cfTunnelWatchdogQueue     = "cf-tunnel-proxy-watchdog"
	cfTunnelProxyDeployName   = "cloudflare-tunnel-gateway-controller-proxy"
	cfTunnelProxyPodSelector  = "app.kubernetes.io/component=proxy,app.kubernetes.io/instance=cloudflare-tunnel-gateway-controller"
	cfTunnelProxySliceService = "cloudflare-tunnel-gateway-controller-proxy-headless"
	cfTunnelResyncAnno        = "watchdog.passiontech.dev/force-resync"
)

type cfTunnelProxyWatchdog struct {
	cs        kubernetes.Interface
	namespace string
}

// SetupCFTunnelProxyWatchdog registers the periodic sweep — only on
// clusters running the cloudflare-tunnel-gateway-controller release
// (enabled=false skips registration entirely).
func SetupCFTunnelProxyWatchdog(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool, namespace string, interval time.Duration) error {
	if !enabled {
		return nil
	}
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: namespace}
	return shared.AddPeriodic(mgr, cfTunnelWatchdogQueue, interval, w.run)
}

func (w *cfTunnelProxyWatchdog) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	resynced, err := w.resyncUnreadyProxies(ctx)
	if err != nil {
		return err
	}
	cleared, err := w.clearStaleStall(ctx)
	if err != nil {
		return err
	}
	log.Info("sweep done", "resyncedSlices", resynced, "stallCleared", cleared)
	return nil
}

// resyncUnreadyProxies is check 1: any Running proxy pod whose Ready
// condition isn't True forces a resync event on every EndpointSlice
// of the headless proxy Service. Returns how many slices got the
// resync annotation (0 when every proxy pod is already ready).
func (w *cfTunnelProxyWatchdog) resyncUnreadyProxies(ctx context.Context) (int, error) {
	log := logf.FromContext(ctx)
	pods, err := w.cs.CoreV1().Pods(w.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: cfTunnelProxyPodSelector,
	})
	if err != nil {
		return 0, fmt.Errorf("list proxy pods in %s: %w", w.namespace, err)
	}
	notReady := 0
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning &&
			!podReady(&pods.Items[i]) {
			notReady++
		}
	}
	if notReady == 0 {
		log.Info("all proxy pods ready", "namespace", w.namespace)
		return 0, nil
	}
	epsList, err := w.cs.DiscoveryV1().EndpointSlices(w.namespace).List(ctx,
		metav1.ListOptions{
			LabelSelector: discoveryv1.LabelServiceName + "=" + cfTunnelProxySliceService,
		})
	if err != nil {
		return 0, fmt.Errorf("list proxy endpointslices in %s: %w", w.namespace, err)
	}
	// kubectl annotate --overwrite: merge patch sets/replaces the key.
	patch := []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{%q:"%d"}}}`,
		cfTunnelResyncAnno, time.Now().Unix()))
	for i := range epsList.Items {
		if _, err := w.cs.DiscoveryV1().EndpointSlices(w.namespace).Patch(ctx,
			epsList.Items[i].Name, types.MergePatchType,
			patch, metav1.PatchOptions{}); err != nil {
			return 0, fmt.Errorf("resync patch endpointslice/%s: %w",
				epsList.Items[i].Name, err)
		}
	}
	log.Info("ACTION: forced proxy config resync",
		"namespace", w.namespace, "notReadyPods", notReady,
		"slices", len(epsList.Items))
	return len(epsList.Items), nil
}

// clearStaleStall is check 2: drop a lingering
// Progressing/ProgressDeadlineExceeded status condition so helm can
// upgrade again. Missing deployment = cluster without the release —
// quiet no-op (the shell's `2>/dev/null || true`). Reports whether a
// condition was removed.
func (w *cfTunnelProxyWatchdog) clearStaleStall(ctx context.Context) (bool, error) {
	log := logf.FromContext(ctx)
	d, err := w.cs.AppsV1().Deployments(w.namespace).
		Get(ctx, cfTunnelProxyDeployName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get deployment %s/%s: %w",
			w.namespace, cfTunnelProxyDeployName, err)
	}
	idx := -1
	for i, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing &&
			c.Reason == "ProgressDeadlineExceeded" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	patch := []byte(fmt.Sprintf(
		`[{"op":"remove","path":"/status/conditions/%d"}]`, idx))
	if _, err := w.cs.AppsV1().Deployments(w.namespace).Patch(ctx,
		cfTunnelProxyDeployName, types.JSONPatchType, patch,
		metav1.PatchOptions{}, "status"); err != nil {
		return false, fmt.Errorf("patch deployment %s/%s status: %w",
			w.namespace, cfTunnelProxyDeployName, err)
	}
	log.Info("CLEAR: removed stale ProgressDeadlineExceeded condition — "+
		"helm can upgrade again",
		"deployment", w.namespace+"/"+cfTunnelProxyDeployName)
	return true, nil
}

// podReady reports whether the pod's Ready condition is True — a
// missing condition counts as not ready.
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
