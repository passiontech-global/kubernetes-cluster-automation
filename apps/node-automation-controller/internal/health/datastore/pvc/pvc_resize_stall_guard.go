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
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// pvcResizeStallGuardCheck is the pvc-resize PVC expansion watchdog.
type pvcResizeStallGuardCheck struct {
	*probefw.Deps

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

// NewPVCResizeStallGuardCheck builds the pvc-resize check — its only
// state is the two ledgers; the check is detection-only and carries
// no heal state.
func NewPVCResizeStallGuardCheck(d *probefw.Deps) probefw.Check {
	return &pvcResizeStallGuardCheck{Deps: d}
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
	minAge := p.Cfg.Datastore.PVCResizeStallMinAge

	pvcs, err := p.AllPVCs(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pvcs: %w", err)}
	}

	var rep probefw.SweepReport
	live := map[string]bool{} // zero-timestamp ledger keys still holding
	for i := range pvcs {
		pvc := &pvcs[i]
		// A terminating claim's lingering resize conditions are
		// teardown noise, not a stall — the volume is going away.
		if pvc.DeletionTimestamp != nil {
			continue
		}
		ns, name := pvc.Namespace, pvc.Name
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
			rep.Emit(pvcResizeStalledGauge, lk,
				[]string{ns, name, string(c.Type)},
				fmt.Sprintf("%s/%s %s=True held >=%s",
					ns, name, c.Type, minAge))
			log.Info("pvc filesystem resize stalled",
				"pvc", ns+"/"+name, "condition", string(c.Type))
		}
	}
	p.seen.Prune(func(k string) bool { return live[k] })
	return rep.Result(&p.emitted, pvcResizeStalledGauge.DeleteLabelValues,
		"pvc resize stalled: ", ", ")
}
