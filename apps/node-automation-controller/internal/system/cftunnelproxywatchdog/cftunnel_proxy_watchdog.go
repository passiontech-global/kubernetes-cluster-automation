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
package cftunnelproxywatchdog

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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

	// W10-NM2 — cloudflared wedge healer. The proxy gateway's pods
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

	// W16-CI2 — gateway controller sync-error audit. The controller
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

// node_automation_cftunnel_gateway_sync_error is 1 while the last
// cfTunnelSyncErrClearAfter window saw a sync-error signature in the
// controller's log tail, 0 otherwise (set once the first sweep
// detects it — see auditControllerSyncErrors).
var cftunnelGatewaySyncErrorGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cftunnel_gateway_sync_error",
	Help: "1 while the cloudflare-tunnel-gateway-controller log tail (5m window) carries a tunnel-config sync error (failed to update tunnel configuration, 429, authentication error) — W16-CI2.",
}, []string{"namespace"})

func init() {
	ctrlmetrics.Registry.MustRegister(cftunnelGatewaySyncErrorGauge)
}

// cfTunnelConnectorTarget is one label-selected pod population that
// runs cloudflared and can wedge the same way.
type cfTunnelConnectorTarget struct {
	namespace string
	selector  string
}

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
	// syncErrLast is namespace -> sweep time of the last log tail
	// that carried a sync-error signature (W16-CI2). The gauge stays
	// 1 until a sweep reads a clean tail at least
	// cfTunnelSyncErrClearAfter after the last errored one — a single
	// clean sweep between error sweeps would flap the series.
	syncErrLast map[string]time.Time
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
	// W10-NM2 — third check: wedged cloudflared connectors need a
	// pod restart, not a config resync. Runs after the resync pass
	// so freshly-configured pods get their grace window first.
	healed, err := w.healCloudflaredWedges(ctx)
	if err != nil {
		return err
	}
	// W16-CI2 — the sync-error audit is observational (gauge only, no
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
	epsList, err := w.cs.DiscoveryV1().EndpointSlices(w.namespace).List(ctx,
		metav1.ListOptions{
			LabelSelector: discoveryv1.LabelServiceName + "=" + cfTunnelProxySliceService,
		})
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
	for i := range epsList.Items {
		if _, err := w.cs.DiscoveryV1().EndpointSlices(w.namespace).Patch(ctx,
			epsList.Items[i].Name, types.MergePatchType,
			patch, metav1.PatchOptions{}); err != nil {
			return 0, fmt.Errorf("resync patch endpointslice/%s: %w",
				epsList.Items[i].Name, err)
		}
	}
	// Delivered-only: the pacing stamp lands after every slice took
	// the annotation — a failed patch loop returns above and the
	// next sweep retries ungated.
	w.lastResync.Stamp(cfTunnelProxySliceService, now)
	log.Info("ACTION: forced proxy config resync",
		"namespace", w.namespace, "notReadyPods", len(unready),
		"pods", unready, "slices", len(epsList.Items))
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
	// TOCTOU: the deployment controller rewrites .status.conditions
	// constantly, so idx can point at a DIFFERENT condition by the
	// time this patch lands — an unguarded remove could then delete
	// e.g. a fresh Available=False. The test op makes the remove
	// conditional on the slot still holding the stale
	// ProgressDeadlineExceeded; a mismatch just fails the patch
	// (harmless — the next sweep re-reads and retries).
	patch := []byte(fmt.Sprintf(
		`[{"op":"test","path":"/status/conditions/%d/reason","value":"ProgressDeadlineExceeded"},`+
			`{"op":"remove","path":"/status/conditions/%d"}]`, idx, idx))
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

// ---------------------------------------------------------------------------
// W10-NM2 — wedged cloudflared connector healer.
// ---------------------------------------------------------------------------

// connectorTargets is the full population of cloudflared pods the
// healer watches: the gateway proxy Deployment AND the ingress
// controller release, which uses a different namespace + label
// scheme for the same binary.
func (w *cfTunnelProxyWatchdog) connectorTargets() []cfTunnelConnectorTarget {
	return []cfTunnelConnectorTarget{
		{namespace: w.namespace, selector: cfTunnelProxyPodSelector},
		{namespace: cfTunnelConnectorNS, selector: cfTunnelConnectorSelector},
	}
}

// healCloudflaredWedges is check 3: delete cloudflared pods that are
// provably wedged — fatal startup errors in the log tail, or an
// edge-connection error loop — plus the readyCount==0 deadlock fix:
// when EVERY running replica of a target is unready >= 5m, delete
// the single oldest one (10m cooldown) so the Deployment recreates
// it instead of skipping forever. Returns pods deleted.
func (w *cfTunnelProxyWatchdog) healCloudflaredWedges(ctx context.Context) (int, error) {
	log := logf.FromContext(ctx)
	now := w.now.Now()
	// The ledger keys carry controller names that outlive their pods
	// but die with their Deployments — bound the map so decommissioned
	// workloads' stamps cannot accumulate forever.
	w.lastHeal.PruneExpired(now, cfTunnelHealCooldown)
	// Maintenance mutex + global heal budget — the deletes below kill
	// LIVE pods, so they defer while a cordon/drain/kured reboot or a
	// k0s upgrade is in flight, and "cannot verify" fails closed.
	// heal.Gate runs the nil-heals-ledger preamble: this module's
	// pacing is the per-controller lastHeal cooldown checked per pod
	// inside healConnectorTarget — only the mutex and budget gates
	// apply here, shared via w.verdict so the sweep pays one
	// evaluation.
	if w.dyn != nil {
		proceed, unverifiable := heal.Gate(ctx, log, &w.verdict,
			w.cs, w.dyn, "cloudflared-wedges", now)
		if unverifiable {
			metrics.IncError(w.queue)
			return 0, nil
		}
		if !proceed {
			return 0, nil
		}
	}
	healed := 0
	for _, tgt := range w.connectorTargets() {
		n, err := w.healConnectorTarget(ctx, tgt, now)
		if err != nil {
			return healed, err
		}
		healed += n
	}
	if healed > 0 {
		log.Info("ACTION: deleted wedged cloudflared pod(s)", "deleted", healed)
	}
	return healed, nil
}

// healConnectorTarget scans one pod population. Only Running pods
// are candidates; Ready=True pods are never touched. Unready pods
// younger than cfTunnelUnreadyMinAge are left alone — rollout
// startup churn must not trigger deletes.
func (w *cfTunnelProxyWatchdog) healConnectorTarget(ctx context.Context,
	tgt cfTunnelConnectorTarget, now time.Time) (int, error) {
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: tgt.selector,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(w.cs, tgt.namespace))
	if err != nil {
		return 0, fmt.Errorf("list connector pods in %s: %w",
			tgt.namespace, err)
	}
	var running []*corev1.Pod
	var unreadyStale []*corev1.Pod
	ready := 0
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		running = append(running, p)
		if kube.PodReadyCond(p) {
			ready++
			continue
		}
		if age, ok := kube.PodUnreadyFor(p, now); ok && age >= cfTunnelUnreadyMinAge {
			unreadyStale = append(unreadyStale, p)
		}
	}
	if len(running) == 0 || len(unreadyStale) == 0 {
		return 0, nil
	}
	log := logf.FromContext(ctx)
	healed := 0
	// Fatal-signature pods: unready >= 5m AND wedged logs — doomed
	// pods a config resync cannot revive. Bounded per target per
	// sweep so a mass-wedge cannot delete the whole fleet at once.
	for _, p := range unreadyStale {
		if healed >= cfTunnelMaxHealsPerTarget {
			break
		}
		wedged, err := w.podLogWedged(ctx, p)
		if err != nil {
			// Log read failure is not proof of health — skip this
			// pod this cycle; the all-unready path below can still
			// cover it.
			log.Info("connector log read failed — skipping wedge check",
				"pod", p.Namespace+"/"+p.Name, "error", err.Error())
			continue
		}
		if !wedged || w.healCooledDown(ctx, p, now) {
			continue
		}
		if err := w.deleteConnectorPod(ctx, p, "fatal_logs"); err != nil {
			log.Error(err, "delete wedged connector pod failed",
				"pod", p.Namespace+"/"+p.Name)
			continue
		}
		w.lastHeal.Stamp(kube.PodControllerKey(p), now)
		w.stampHealPersisted(ctx, p, now)
		healed++
	}
	// readyCount==0 deadlock: every running replica unready — the
	// resync loop can never converge. Delete the single OLDEST
	// stale-unready pod (10m cooldown) so its Deployment recreates
	// it; one per sweep bounds churn during a genuine outage.
	if ready == 0 && healed < cfTunnelMaxHealsPerTarget {
		oldest := unreadyStale[0]
		for _, p := range unreadyStale[1:] {
			if p.CreationTimestamp.Before(&oldest.CreationTimestamp) {
				oldest = p
			}
		}
		if !w.healCooledDown(ctx, oldest, now) {
			if err := w.deleteConnectorPod(ctx, oldest,
				"all_unready_oldest"); err != nil {
				log.Error(err, "delete oldest unready connector pod failed",
					"pod", oldest.Namespace+"/"+oldest.Name)
			} else {
				w.lastHeal.Stamp(kube.PodControllerKey(oldest), now)
				w.stampHealPersisted(ctx, oldest, now)
				healed++
			}
		}
	}
	return healed, nil
}

// healCooledDown reports whether this pod's controller is inside
// cfTunnelHealCooldown on EITHER clock — the in-RAM lastHeal ledger
// OR the passiontech.dev/last-cloudflared-heal annotation persisted
// on the pod's owning ReplicaSet (the durable half that survives an
// operator restart). Both reads are the heal.PersistedCooledDown
// wider-of contract. Keyed on the owner (not the pod name) so a
// recreated pod that wedges again waits out the window instead of
// being killed every sweep under a fresh name. A failed (or absent)
// ReplicaSet read degrades the gate to the in-RAM ledger alone —
// never fail a heal over its cooldown's cheap half.
func (w *cfTunnelProxyWatchdog) healCooledDown(ctx context.Context,
	p *corev1.Pod, now time.Time) bool {
	var rs metav1.Object
	if ref := metav1.GetControllerOf(p); ref != nil && ref.Name != "" {
		got, err := w.cs.AppsV1().ReplicaSets(p.Namespace).
			Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			logf.FromContext(ctx).Info(
				"replicaset read failed — heal cooldown degrades to the in-RAM ledger",
				"replicaset", p.Namespace+"/"+ref.Name, "error", err.Error())
		} else {
			rs = got
		}
	}
	return heal.PersistedCooledDown(&w.lastHeal, rs, cfTunnelHealAnno,
		kube.PodControllerKey(p), cfTunnelHealCooldown, now)
}

// stampHealPersisted is the durable half of the heal cooldown: the
// RFC3339 annotation on the pod's owning ReplicaSet, delivered via
// heal.StampPersisted AFTER the delete landed. A failed annotation
// patch leaves the in-RAM lastHeal stamp holding (it was stamped on
// the delivered delete) and only costs durability — the same
// annotation-fails-but-heal-stands shape dragonfly_heals uses.
func (w *cfTunnelProxyWatchdog) stampHealPersisted(ctx context.Context,
	p *corev1.Pod, now time.Time) {
	ref := metav1.GetControllerOf(p)
	if ref == nil || ref.Name == "" {
		return // standalone pod — no ReplicaSet to persist on
	}
	err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := w.cs.AppsV1().ReplicaSets(p.Namespace).
				Patch(ctx, ref.Name, types.MergePatchType, data, metav1.PatchOptions{})
			return err
		},
		cfTunnelHealAnno, nil, "", now)
	if err != nil {
		logf.FromContext(ctx).Error(err, "persist cloudflared heal stamp failed",
			"replicaset", p.Namespace+"/"+ref.Name)
	}
}

// deleteConnectorPod deletes a connector pod with a UID precondition
// — the listed pod could already have been replaced by a same-named
// fresh pod, and killing the replacement would undo the heal.
func (w *cfTunnelProxyWatchdog) deleteConnectorPod(ctx context.Context,
	p *corev1.Pod, reason string) error {
	err := w.cs.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		kube.UIDDeleteOptions(p.UID, ""))
	if apierrors.IsNotFound(err) {
		return nil // already gone — not a delete we delivered
	}
	if err != nil {
		return err
	}
	// Count only delivered deletes — incrementing before the call
	// recorded every API failure as a heal that never happened.
	metrics.CFTunnelWedgePodsDeletedTotal.WithLabelValues(
		p.Namespace, reason).Inc()
	return nil
}

// podLogWedged fetches the tail of the pod's log and matches the
// cloudflared wedge signatures.
func (w *cfTunnelProxyWatchdog) podLogWedged(ctx context.Context,
	p *corev1.Pod) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, cfTunnelLogTimeout)
	defer cancel()
	tail := int64(cfTunnelLogTailLines)
	stream, err := w.cs.CoreV1().Pods(p.Namespace).GetLogs(p.Name,
		&corev1.PodLogOptions{TailLines: &tail}).Stream(lctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, cfTunnelLogMaxBytes))
	if err != nil {
		return false, err
	}
	return cloudflaredLogsWedged(string(data)), nil
}

// cloudflaredLogsWedged matches the observed cloudflared failure
// signatures: fatal startup/config errors, and a sustained
// error loop (>=3 weighted error lines in the tail — a single blip
// during an edge rollout is normal). The QUIC patterns cover the
// UDP-blackhole wedge where the connector still reports Ready but
// every dial to the edge times out: "failed to dial to edge with
// quic", "timeout: no recent network activity" and the "quic: "
// error prefix.
//
// "failed to sufficiently increase receive buffer size" is NOT
// fatal: it is the benign startup warning cloudflared logs on every
// Linux node whose default rmem is below its request, so it only
// counts as weight-1 loop noise — three of them (or mixed with real
// edge errors) still mean wedged, one alone never does.
func cloudflaredLogsWedged(logs string) bool {
	edgeErrs := 0
	for _, line := range strings.Split(logs, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "couldn't start tunnel") ||
			strings.Contains(l, "serve tunnel error") {
			return true
		}
		if strings.Contains(l, "failed to sufficiently increase receive buffer") {
			// Benign startup warning — weight-1 noise, never an
			// instant kill (it appears on EVERY Linux node at boot).
			edgeErrs++
			continue
		}
		if strings.Contains(l, "connection with edge") &&
			(strings.Contains(l, "err") ||
				strings.Contains(l, "failed") ||
				strings.Contains(l, "timeout") ||
				strings.Contains(l, "reset") ||
				strings.Contains(l, "closed")) {
			edgeErrs++
			continue
		}
		if strings.Contains(l, "failed to dial to edge with quic") ||
			strings.Contains(l, "timeout: no recent network activity") ||
			strings.Contains(l, "quic: ") {
			edgeErrs++
		}
	}
	return edgeErrs >= 3
}

// ---------------------------------------------------------------------------
// W16-CI2 — cloudflare-tunnel-gateway-controller sync-error audit.
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
