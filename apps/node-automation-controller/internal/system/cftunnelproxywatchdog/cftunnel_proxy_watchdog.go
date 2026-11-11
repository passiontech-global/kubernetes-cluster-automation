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
// Two later additions ride the same sweep from sibling files:
// cloudflared-wedge-heal restarts provably wedged cloudflared
// connectors (cloudflared_wedge.go) and cf-gateway-sync-error
// mirrors the gateway controller's sync failures to a gauge
// (sync_audit.go).
//
// namespace is configurable because the helm release's namespace
// differs per cluster (base default: cloudflare-tunnel-system).
package cftunnelproxywatchdog

import (
	"context"
	"fmt"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	cfTunnelProxyDeployName   = "cloudflare-tunnel-gateway-controller-proxy"
	cfTunnelProxyPodSelector  = "app.kubernetes.io/component=proxy,app.kubernetes.io/instance=cloudflare-tunnel-gateway-controller"
	cfTunnelProxySliceService = "cloudflare-tunnel-gateway-controller-proxy-headless"
	cfTunnelResyncAnno        = kube.AnnoWatchdogForceResync

	// cloudflared-wedge-heal — cloudflared wedge healer. The proxy gateway's pods
	// are cloudflared connectors; the ingress controller release
	// (cloudflare-tunnel-ingress-controller ns) runs the same binary
	// under a different label scheme. A connector stuck on a fatal
	// startup error or a dead edge-connection loop reports
	// Ready=False forever and config resyncs cannot revive it —
	// only a pod restart can.
	cfTunnelConnectorNS       = "cloudflare-tunnel-ingress-controller"
	cfTunnelConnectorSelector = "app=controlled-cloudflared-connector"
	// A pod must hold Ready=False this long before its logs are even
	// read — protects normal rollout startup churn.
	cfTunnelUnreadyMinAge = 5 * time.Minute
	// Forced config resyncs are paced like the heal cooldown: the
	// resync annotation VALUE must churn to emit an event, but doing
	// that on every 5m sweep while a pod sits unready is an
	// event storm on the EndpointSlice — at most one forced resync
	// per 10m; gated sweeps only log the unready count.
	cfTunnelResyncCooldown = 10 * time.Minute
	// Per-pod delete cooldown: the Deployment's own backoff plus this
	// guard keeps a crash-looping connector from being deleted every
	// sweep.
	cfTunnelHealCooldown      = 10 * time.Minute
	cfTunnelMaxHealsPerTarget = 2
	// cfTunnelHealAnno is the durable half of that cooldown, stamped
	// on the pod's owning ReplicaSet (RFC3339 via heal.StampPersisted)
	// so it survives operator restarts where the in-RAM lastHeal
	// ledger cannot. The ReplicaSet — not a shared Deployment — is the
	// object that maps 1:1 to the ledger key (kube.PodControllerKey)
	// and dies with its workload, so stamps can neither collide
	// between controllers nor accumulate on decommissioned releases.
	cfTunnelHealAnno     = "passiontech.dev/last-cloudflared-heal"
	cfTunnelLogTailLines = 200
	cfTunnelLogMaxBytes  = 256 << 10
	cfTunnelLogTimeout   = 8 * time.Second

	// cf-gateway-sync-error — gateway controller sync-error audit. The controller
	// logs "failed to update tunnel configuration" (Cloudflare API
	// rejected the Route push), "429 Too Many Requests" (API rate
	// limit — a desync is accumulating silently), or an
	// "authentication error" (dead API token). The watchdog's 5m
	// sweep reads a bounded log tail and mirrors the finding to the
	// gauge; a clean tail for a full clear-window resets it.
	cfTunnelGatewayCtrlSelector = "app.kubernetes.io/name=cloudflare-tunnel-gateway-controller"
	cfTunnelSyncErrSinceSeconds = int64(300)
	cfTunnelSyncErrTailLines    = int64(200)
	cfTunnelSyncErrClearAfter   = 5 * time.Minute
	cfTunnelSyncErrLogTimeout   = 8 * time.Second
	cfTunnelSyncErrLogMaxBytes  = 256 << 10
)

type cfTunnelProxyWatchdog struct {
	cs kubernetes.Interface
	// dyn feeds the maintenance mutex's autopilot-Plan signal — the
	// cloudflared pod deletes defer while a drain or k0s upgrade is
	// in flight. Nil (literal test fixtures) leaves the gate
	// unarmed — the standard unarmed-seam convention.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and the registration log
	// come from one place.
	queue     string
	namespace string
	// lastHeal is kube.PodControllerKey -> last delete time; bounds
	// restart churn on a workload that wedges again immediately after
	// recreation. Keyed by the pod's CONTROLLER (ReplicaSet), not the
	// pod name: a recreated pod carries a fresh name suffix, so a
	// pod-name cooldown never suppressed the re-heal — the replacement
	// was deleted every sweep until the wedge cleared. The in-RAM half
	// is widened by cfTunnelHealAnno on the owning ReplicaSet
	// (healCooledDown/stampHealPersisted) so the cooldown survives an
	// operator restart.
	lastHeal state.CooldownSet
	// lastResync paces check 1: service -> last forced-resync sweep.
	// One sweep per cfTunnelResyncCooldown stamps the headless
	// EndpointSlices; the sweeps in between only log the unready
	// count. Keyed on the (single) headless proxy Service so a second
	// service inherits its own pacing for free.
	lastResync state.CooldownSet
	// verdict memoizes the maintenance-mutex evaluation so the
	// sweep pays one evaluation per TTL window.
	verdict kube.Verdict
	// now is a test seam for cooldown/age checks.
	now shared.Clock
	// syncErrLast is the namespace -> sweep time of the last log tail
	// that carried a sync-error signature (cf-gateway-sync-error). The gauge stays
	// 1 until a sweep reads a clean tail at least
	// cfTunnelSyncErrClearAfter after the last errored one — a single
	// clean sweep between error sweeps would flap the series.
	// state.CooldownSet is the shared last-stamp ledger — the
	// hand-rolled map it replaced did exactly its Stamp/CooledDown/
	// Forget job.
	syncErrLast state.CooldownSet
}

// Setup registers the periodic sweep — only on
// clusters running the cloudflare-tunnel-gateway-controller release
// (enabled=false skips registration entirely).
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg watchdogConfig) error {
		logf.Log.WithName(d.Name).Info("registered",
			"namespace", cfg.namespace, "interval", cfg.interval)
		w := &cfTunnelProxyWatchdog{cs: d.CS, dyn: d.Dyn, queue: d.Name, namespace: cfg.namespace}
		return shared.AddPeriodic(d.Mgr, w.queue, cfg.interval, w.run)
	})
}

// watchdogConfig is the module's env-resolved knob set.
type watchdogConfig struct {
	namespace string
	interval  time.Duration
}

// configFromEnv resolves the CF_TUNNEL_WATCHDOG_* knobs.
// SetupWithConfig runs it before the Deps.Disabled gate — see
// corednspatcher: invalid knob values must warn even when the module
// is disabled (CF_TUNNEL_WATCHDOG_ENABLED=false, resolved by
// setupModules into Deps.Disabled).
func configFromEnv() watchdogConfig {
	return watchdogConfig{
		namespace: envx.Getenv("CF_TUNNEL_WATCHDOG_NAMESPACE", "cloudflare-tunnel-system"),
		interval:  envx.GetenvDuration("CF_TUNNEL_WATCHDOG_INTERVAL", 5*time.Minute),
	}
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
	// cloudflared-wedge-heal — third check: wedged cloudflared connectors need a
	// pod restart, not a config resync. Runs after the resync pass
	// so freshly-configured pods get their grace window first.
	healed, err := w.healCloudflaredWedges(ctx)
	if err != nil {
		return err
	}
	// cf-gateway-sync-error — the sync-error audit is observational (gauge only, no
	// heal), so its failures never abort the sweep; the function
	// logs them itself.
	w.auditControllerSyncErrors(ctx)
	log.Info("sweep done", "resyncedSlices", resynced, "stallCleared", cleared,
		"wedgesHealed", healed)
	return nil
}

// resyncUnreadyProxies is check 1: any Running proxy pod whose Ready
// condition isn't True forces a resync event on every EndpointSlice
// of the headless proxy Service. Returns how many slices got the
// resync annotation (0 when every proxy pod is already ready).
func (w *cfTunnelProxyWatchdog) resyncUnreadyProxies(ctx context.Context) (int, error) {
	log := logf.FromContext(ctx)
	now := w.now.Now()
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: cfTunnelProxyPodSelector,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(w.cs, w.namespace))
	if err != nil {
		return 0, fmt.Errorf("list proxy pods in %s: %w", w.namespace, err)
	}
	var unready []string
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning &&
			!kube.PodReadyCond(&pods[i]) {
			unready = append(unready, pods[i].Name)
		}
	}
	if len(unready) == 0 {
		log.Info("all proxy pods ready", "namespace", w.namespace)
		return 0, nil
	}
	// Sweep pacing: at most one forced resync per cooldown window.
	// The stamp VALUE below must churn to emit the EndpointSlice
	// event — but with the gate holding, consecutive stamps are >=
	// the cooldown apart, so the churn stays real while the event
	// rate stays bounded. Gated sweeps still log so an unready pod
	// never disappears from the ops view.
	w.lastResync.PruneExpired(now, cfTunnelResyncCooldown)
	if w.lastResync.CooledDown(cfTunnelProxySliceService, cfTunnelResyncCooldown, now) {
		log.Info("resync inside cooldown — unready pods counted only",
			"namespace", w.namespace, "notReadyPods", len(unready), "pods", unready)
		return 0, nil
	}
	// Paged like every sweep list — the headless Service usually owns
	// a handful of slices, but the selector-scoped List still gets
	// the shared 500-per-page bound.
	epsItems, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + cfTunnelProxySliceService,
		Limit:         kube.DefaultListPageSize,
	}, kube.EndpointSlices(w.cs, w.namespace))
	if err != nil {
		return 0, fmt.Errorf("list proxy endpointslices in %s: %w", w.namespace, err)
	}
	// kubectl annotate --overwrite: merge patch sets/replaces the key.
	// The stamp stays unix — the VALUE churn is the resync signal
	// (each gated sweep stamps >= the cooldown apart, so consecutive
	// values always differ and the EndpointSlice emits its event).
	patch, err := kube.MergePatchAnnos(map[string]any{
		cfTunnelResyncAnno: strconv.FormatInt(now.Unix(), 10),
	})
	if err != nil {
		return 0, fmt.Errorf("marshal resync patch: %w", err)
	}
	for i := range epsItems {
		if _, err := w.cs.DiscoveryV1().EndpointSlices(w.namespace).Patch(ctx,
			epsItems[i].Name, types.MergePatchType,
			patch, metav1.PatchOptions{}); err != nil {
			return 0, fmt.Errorf("resync patch endpointslice/%s: %w",
				epsItems[i].Name, err)
		}
	}
	// Delivered-only: the pacing stamp lands after every slice took
	// the annotation — a failed patch loop returns above and the
	// next sweep retries ungated.
	w.lastResync.Stamp(cfTunnelProxySliceService, now)
	log.Info("ACTION: forced proxy config resync",
		"namespace", w.namespace, "notReadyPods", len(unready),
		"pods", unready, "slices", len(epsItems))
	return len(epsItems), nil
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
	// TOCTOU: the deployment controller rewrites .status.conditions
	// constantly, so idx can point at a DIFFERENT condition by the
	// time this patch lands — an unguarded remove could then delete
	// e.g. a fresh Available=False. The test op makes the remove
	// conditional on the slot still holding the stale
	// ProgressDeadlineExceeded; the API server rejects the whole
	// patch with Invalid when the precondition misses. That rejection
	// is the EXPECTED raced outcome, not a sweep failure: this
	// function returns (false, nil) for it so run() proceeds to
	// healCloudflaredWedges/audit and the periodic loop doesn't
	// IncError — the next sweep re-reads and retries anyway. Real
	// patch failures (conn refused, RBAC) still propagate.
	patch := []byte(fmt.Sprintf(
		`[{"op":"test","path":"/status/conditions/%d/reason","value":"ProgressDeadlineExceeded"},`+
			`{"op":"remove","path":"/status/conditions/%d"}]`, idx, idx))
	if _, err := w.cs.AppsV1().Deployments(w.namespace).Patch(ctx,
		cfTunnelProxyDeployName, types.JSONPatchType, patch,
		metav1.PatchOptions{}, "status"); err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsConflict(err) {
			log.Info("stale-stall clear raced with the deployment "+
				"controller — retrying next sweep",
				"deployment", w.namespace+"/"+cfTunnelProxyDeployName)
			return false, nil
		}
		return false, fmt.Errorf("patch deployment %s/%s status: %w",
			w.namespace, cfTunnelProxyDeployName, err)
	}
	log.Info("CLEAR: removed stale ProgressDeadlineExceeded condition — "+
		"helm can upgrade again",
		"deployment", w.namespace+"/"+cfTunnelProxyDeployName)
	return true, nil
}
