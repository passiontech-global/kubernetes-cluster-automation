// pvc_resize_stall_guard.go — the pvc-resize-stall-guard check
// (pvc-resize): a PersistentVolumeClaim wedged in filesystem-expansion
// limbo. Two condition types mark an in-flight resize:
//
//   - FileSystemResizePending=True — the control-plane resize
//     succeeded but kubelet's node-side filesystem grow never ran
//     (usually a pod restart that never happened); the volume shows
//     the new size while the filesystem inside stays at the old one.
//   - Resizing=True — the resize controller's expansion is still
//     being applied; wedged here means the storage backend or the
//     expand controller lost the claim mid-operation.
//
// Either condition True past PVCResizeStallMinAge (30m default) is a
// stall: a healthy expansion is seconds-to-minutes. Detection-only —
// the gauge node_automation_pvc_resize_stalled{namespace,pvc,
// condition} is the alert contract; nothing here deletes or patches.
package pvc

import (
	"cmp"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	pvcResizeStallDefaultMinAge = 30 * time.Minute
	pvcResizeBounceCooldown     = 30 * time.Minute
	pvcResizeBounceAnno         = "passiontech.dev/auto-bounce-for-fs-resize"
)

// pvcResizeStallGuardCheck is the pvc-resize PVC expansion watchdog.
type pvcResizeStallGuardCheck struct {
	*probefw.Deps

	minAge        time.Duration
	bounceEnabled bool

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// seen: "ns/pvc/condition" → first sweep a resize condition
	// held — the persistence clock for conditions whose
	// lastTransitionTime never landed (a can't-tell timestamp reads
	// as fresh observation, never as stalled-on-arrival); pruned on
	// resolve so a flap re-arms.
	seen state.FirstSeenLedger
}

// NewPVCResizeStallGuardCheck builds the pvc-resize check — resolves
// HEALTH_PVC_RESIZE_STALL_MIN_AGE and NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED
// and initializes the check ledgers.
func NewPVCResizeStallGuardCheck(d *probefw.Deps) probefw.Check {
	return &pvcResizeStallGuardCheck{
		Deps:          d,
		minAge:        envx.GetenvDuration("HEALTH_PVC_RESIZE_STALL_MIN_AGE", pvcResizeStallDefaultMinAge),
		bounceEnabled: envx.Gate("NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED", false),
	}
}

const (
	// CheckNamePVCResizeStallGuard is the check's kuberhealthy_check
	// label value — pvc-resize; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNamePVCResizeStallGuard = "pvc-resize-stall-guard"
)

// pvcResizeStalledGauge is the pvc-resize signal: 1 while a PVC carries
// FileSystemResizePending or Resizing True past the stall window —
// the filesystem never caught up to the expanded volume.
var pvcResizeStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pvc_resize_stalled",
	Help: "1 while a PVC's FileSystemResizePending or Resizing condition has been True past the stall window.",
}, []string{"namespace", "pvc", "condition"})

func init() {
	ctrlmetrics.Registry.MustRegister(pvcResizeStalledGauge)
}

// pvcResizeStallConditions are the two in-flight expansion markers —
// either True past the window means the resize pipeline lost the
// claim.
var pvcResizeStallConditions = map[corev1.PersistentVolumeClaimConditionType]bool{
	corev1.PersistentVolumeClaimFileSystemResizePending: true,
	corev1.PersistentVolumeClaimResizing:                true,
}

// Run censuses every PVC cluster-wide and flags each stalled
// expansion condition. The stall clock prefers the condition's own
// lastTransitionTime (the honest transition moment); a condition
// that carries none falls back to the first-seen ledger — mixing
// them on one key would let an old ledger entry outrank a fresh
// transition.
func (p *pvcResizeStallGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	minAge := p.minAge
	if minAge <= 0 {
		minAge = pvcResizeStallDefaultMinAge
	}

	pvcs, err := p.AllPVCs(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pvcs: %w", err)}
	}

	var rep probefw.SweepReport
	live := map[string]bool{} // zero-timestamp ledger keys still holding
	var fsResizeStalled []*corev1.PersistentVolumeClaim
	for i := range pvcs {
		pvc := &pvcs[i]
		// A terminating claim's lingering resize conditions are
		// teardown noise, not a stall — the volume is going away.
		if pvc.DeletionTimestamp != nil {
			continue
		}
		ns, name := pvc.Namespace, pvc.Name
		fsStalled := false
		for _, c := range pvc.Status.Conditions {
			if c.Status != corev1.ConditionTrue ||
				!pvcResizeStallConditions[c.Type] {
				continue
			}
			lk := ns + "/" + name + "/" + string(c.Type)
			persisted := false
			if !c.LastTransitionTime.IsZero() {
				persisted = now.Sub(c.LastTransitionTime.Time) >= minAge
			} else {
				live[lk] = true
				persisted = probefw.Persisted(&p.seen, lk, now, minAge, log)
			}
			if !persisted {
				continue
			}
			if c.Type == corev1.PersistentVolumeClaimFileSystemResizePending {
				fsStalled = true
			}
			rep.Emit(pvcResizeStalledGauge, lk,
				[]string{ns, name, string(c.Type)},
				fmt.Sprintf("%s/%s %s=True held >=%s",
					ns, name, c.Type, minAge))
			log.Info("pvc filesystem resize stalled",
				"pvc", ns+"/"+name, "condition", string(c.Type))
		}
		if fsStalled {
			fsResizeStalled = append(fsResizeStalled, pvc)
		}
	}
	p.seen.Prune(func(k string) bool { return live[k] })

	if len(fsResizeStalled) > 0 {
		p.bounceStalledFSResizePods(ctx, log, fsResizeStalled, now)
	}

	return rep.Result(&p.emitted, pvcResizeStalledGauge.DeleteLabelValues,
		"pvc resize stalled: ", ", ")
}

func (p *pvcResizeStallGuardCheck) bounceStalledFSResizePods(
	ctx context.Context,
	log logr.Logger,
	stalledPVCs []*corev1.PersistentVolumeClaim,
	now time.Time,
) {
	candidates := make([]*corev1.PersistentVolumeClaim, 0, len(stalledPVCs))
	for _, pvc := range stalledPVCs {
		if pvc.Namespace == "kube-system" {
			continue
		}
		pvcAnno := strings.TrimSpace(kube.EffectiveAnno(ctx, pvc, pvcResizeBounceAnno))
		if strings.EqualFold(pvcAnno, "false") {
			continue
		}
		candidates = append(candidates, pvc)
	}
	if len(candidates) == 0 {
		return
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — pvc resize bounce skipped", "error", err)
		return
	}

	slices.SortFunc(candidates, func(a, b *corev1.PersistentVolumeClaim) int {
		if d := cmp.Compare(a.Namespace, b.Namespace); d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})

	for _, pvc := range candidates {
		pvcKey := pvc.Namespace + "/" + pvc.Name
		pvcAnno := strings.TrimSpace(kube.EffectiveAnno(ctx, pvc, pvcResizeBounceAnno))

		var eligible []*corev1.Pod
		for i := range pods {
			pod := &pods[i]
			if pod.Namespace != pvc.Namespace || pod.Namespace == "kube-system" {
				continue
			}
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase == corev1.PodSucceeded ||
				pod.Status.Phase == corev1.PodFailed {
				continue
			}
			if pod.Annotations["kubernetes.io/config.mirror"] != "" {
				continue
			}
			// Never kill unowned standalone pods.
			if metav1.GetControllerOf(pod) == nil {
				continue
			}
			if !slices.Contains(kube.PodClaimedPVCs(pod), pvc.Name) {
				continue
			}
			podAnno := strings.TrimSpace(kube.EffectiveAnno(ctx, pod, pvcResizeBounceAnno))
			if strings.EqualFold(podAnno, "false") {
				continue
			}
			if !p.bounceEnabled &&
				!strings.EqualFold(pvcAnno, "true") &&
				!strings.EqualFold(podAnno, "true") {
				continue
			}
			eligible = append(eligible, pod)
		}
		if len(eligible) == 0 {
			continue
		}

		slices.SortFunc(eligible, func(a, b *corev1.Pod) int {
			return cmp.Compare(a.Name, b.Name)
		})
		target := eligible[0]
		podKey := target.Namespace + "/" + target.Name

		ck := probefw.SelfHealKey(CheckNamePVCResizeStallGuard, pvcKey)
		proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals, ck, pvcResizeBounceCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			return
		}
		if !proceed {
			continue
		}

		if allowed, reason := heal.TryAcquireTarget(CheckNamePVCResizeStallGuard, pvcKey, now); !allowed {
			heal.RefundGrant(now)
			log.Info("DEFER: pvc-resize bounce target circuit open",
				"pvc", pvcKey, "pod", podKey, "reason", reason)
			continue
		}

		evicted, refused, notFound, err := heal.EvictPodNotFound(ctx, p.CS, &p.Heals, ck, target, now)
		switch {
		case err != nil:
			metrics.IncError(p.Name)
			log.Error(err, "pvc-resize pod eviction failed", "pvc", pvcKey, "pod", podKey)
		case refused:
			heal.RefundTarget(CheckNamePVCResizeStallGuard, pvcKey, now)
			heal.RefundGrant(now)
			if notFound {
				log.V(1).Info("DEFER: pvc-resize pod vanished before eviction", "pvc", pvcKey, "pod", podKey)
			} else {
				log.Info("DEFER: pvc-resize pod eviction refused (PDB/hold/quorum)", "pvc", pvcKey, "pod", podKey)
			}
		case evicted:
			metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNamePVCResizeStallGuard).Inc()
			log.Info("EVICT: bounced pod for offline FileSystemResizePending PVC",
				"pvc", pvcKey, "pod", podKey)
		}
	}
}
