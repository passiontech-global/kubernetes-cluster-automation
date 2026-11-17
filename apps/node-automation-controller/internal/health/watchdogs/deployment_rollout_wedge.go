// deployment_rollout_wedge.go — the deployment-rollout-wedge
// check (P1.9): a Deployment whose rollout gave up
// (Progressing=False/ProgressDeadlineExceeded) or whose ReplicaSets
// report ReplicaFailure=True past the persistence window is a
// wedged rollout — usually a handful of terminal pods (Failed /
// Evicted) and zero-ready old ReplicaSets still holding
// ResourceQuota slots, so the deployment can neither finish nor
// be scaled back up.
//
// Past the window the check, in order:
//   - garbage-collects the terminal pods (Failed/Evicted) owned by
//     the deployment's ReplicaSets — terminal-object GC is exempt
//     from the maintenance mutex by contract,
//   - scales to 0 every OLD ReplicaSet (not the newest revision)
//     whose readyReplicas==0 while spec.replicas>0 — the quota-
//     holding zombie RSs blocking the rollout,
//   - when the blockers are cleared but the deployment is still
//     wedged, applies kube.RestartTemplatePatch once per persisted
//     cooldown (kube.AnnoLastDeploymentUnstick, 1h) — the
//     template-nudge that forces a fresh ReplicaSet.
//
// Gauge node_automation_deployment_rollout_wedge + one deduped
// Event per window always fire; heals ride the shared gates.
package watchdogs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// deploymentRolloutWedgeCheck is the wedged-rollout detector +
// three-stage unwedger.
type deploymentRolloutWedgeCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger.
	emitted state.GaugeLedger[string]
	// eventHealed dedupes the cluster Event per window.
	eventHealed state.CooldownSet
	// nudgeHeals is the in-RAM half of the template-nudge cooldown —
	// the persisted half rides kube.AnnoLastDeploymentUnstick on the
	// Deployment (heal.PersistedCooledDown reads the wider of both).
	nudgeHeals state.CooldownSet
}

// NewDeploymentRolloutWedgeCheck builds the check.
func NewDeploymentRolloutWedgeCheck(d *probefw.Deps) probefw.Check {
	return &deploymentRolloutWedgeCheck{Deps: d}
}

const (
	CheckNameDeploymentRolloutWedge = "deployment-rollout-wedge"

	// The wedge signature must hold this long before relief — a
	// rollout that is merely slow is not wedged.
	rolloutWedgeMinAge = 20 * time.Minute
	// One cluster Event per window.
	rolloutWedgeEventCooldown = 30 * time.Minute
	// Template-nudge persisted cooldown — an hour between nudges of
	// the same Deployment.
	rolloutWedgeNudgeCooldown = time.Hour
	// rolloutWedgeRSZeroCooldown rate-limits the stage-2 stale-RS
	// zeroing per Deployment — same hour shape as the nudge.
	rolloutWedgeRSZeroCooldown = time.Hour
	// Max stale ReplicaSets scaled to 0 per wedged Deployment per
	// sweep — bounds the blast radius of a pathological revision
	// history.
	rolloutWedgeMaxRSZero = 8
)

var (
	// deployment-rollout-wedge — 1 per wedged Deployment, labelled
	// by reason.
	deploymentRolloutWedgeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_deployment_rollout_wedge",
		Help: "1 while a Deployment holds ProgressDeadlineExceeded or ReplicaFailure past the window — deployment-rollout-wedge.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(deploymentRolloutWedgeGauge)
}

// rsCensusRow is one ReplicaSet's wedge-relevant fields, grouped
// under its owning Deployment UID.
type rsCensusRow struct {
	name         string
	uid          types.UID
	failed       bool
	failedSince  time.Time // ReplicaFailure condition's LastTransitionTime
	replicas     int32
	ready        int32
	creationTime time.Time
}

// Run scans every Deployment for the wedge signatures and runs the
// three-stage unwedger on each confirmed target.
func (p *deploymentRolloutWedgeCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list deployments: %w", err)}
	}
	// Typed RS census — AllReplicaSets is metadata-only; the wedge
	// signature needs spec.replicas/status.conditions, so this
	// check pays its own paged typed LIST once per sweep.
	rss, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.ReplicaSets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list replicasets: %w", err)}
	}
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	// Group RSs under their owning Deployment UID.
	rsByDep := map[types.UID][]rsCensusRow{}
	for i := range rss {
		rs := &rss[i]
		c := metav1.GetControllerOf(rs)
		if c == nil || c.Kind != "Deployment" {
			continue
		}
		row := rsCensusRow{
			name:         rs.Name,
			uid:          rs.UID,
			creationTime: rs.CreationTimestamp.Time,
		}
		if rs.Spec.Replicas != nil {
			row.replicas = *rs.Spec.Replicas
		}
		row.ready = rs.Status.ReadyReplicas
		for _, cond := range rs.Status.Conditions {
			if cond.Type == appsv1.ReplicaSetReplicaFailure &&
				cond.Status == corev1.ConditionTrue {
				row.failed = true
				row.failedSince = cond.LastTransitionTime.Time
			}
		}
		rsByDep[c.UID] = append(rsByDep[c.UID], row)
	}

	var findings []string
	for i := range deps {
		d := &deps[i]
		rsList := rsByDep[d.UID]
		var reasons []string
		for _, c := range d.Status.Conditions {
			if c.Type == appsv1.DeploymentProgressing &&
				c.Status == corev1.ConditionFalse &&
				c.Reason == "ProgressDeadlineExceeded" &&
				!c.LastTransitionTime.IsZero() &&
				now.Sub(c.LastTransitionTime.Time) >= rolloutWedgeMinAge {
				reasons = append(reasons, "progress_deadline_exceeded")
			}
		}
		for _, rs := range rsList {
			// ReplicaFailure needs the SAME persistence window as
			// ProgressDeadlineExceeded — a condition that just
			// flipped is a rollout in progress, not a wedge.
			if rs.failed && !rs.failedSince.IsZero() &&
				now.Sub(rs.failedSince) >= rolloutWedgeMinAge {
				reasons = append(reasons, "replica_failure")
				break
			}
		}
		if len(reasons) == 0 {
			continue
		}
		key := d.Namespace + "/" + d.Name
		for _, reason := range reasons {
			rep.Flag(deploymentRolloutWedgeGauge, key+"/"+reason,
				[]string{d.Namespace, d.Name, reason})
		}
		finding := key + "(" + strings.Join(reasons, ",") + ")"
		findings = append(findings, finding)
		rep.Find(finding)
		p.unwedgeDeployment(ctx, log, d, rsList, pods, now)
	}
	p.emitWedgeEvent(ctx, log, findings, now)
	return rep.Result(&p.emitted, deploymentRolloutWedgeGauge.DeleteLabelValues,
		"deployments rollout-wedged: ", ", ")
}

// unwedgeDeployment runs the three stages for one wedged
// Deployment: terminal-pod GC (mutex-exempt), stale-RS zeroing,
// then the persisted template nudge.
func (p *deploymentRolloutWedgeCheck) unwedgeDeployment(ctx context.Context,
	log logr.Logger, d *appsv1.Deployment, rsList []rsCensusRow,
	pods []corev1.Pod, now time.Time) {

	ns, name := d.Namespace, d.Name
	// Stage 1 — terminal pod GC: Failed-phase or Evicted pods owned
	// by this Deployment's ReplicaSets. Terminal-object GC is
	// exempt from the maintenance mutex by contract.
	rsUIDs := map[types.UID]bool{}
	for _, rs := range rsList {
		rsUIDs[rs.uid] = true
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != ns {
			continue
		}
		terminal := pod.Status.Phase == corev1.PodFailed ||
			pod.Status.Reason == "Evicted"
		if !terminal || pod.DeletionTimestamp != nil {
			continue
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != "ReplicaSet" || !rsUIDs[owner.UID] {
			continue
		}
		if err := p.CS.CoreV1().Pods(ns).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: metav1.NewUIDPreconditions(string(pod.UID)),
			}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "rollout wedge terminal pod delete failed",
				"pod", ns+"/"+pod.Name)
			continue
		}
		log.Info("GC: deleted terminal pod blocking rollout",
			"pod", ns+"/"+pod.Name, "deployment", ns+"/"+name)
	}
	// Stage 2 — stale ReplicaSet zeroing: old revisions with
	// spec.replicas>0 but readyReplicas==0 hold ResourceQuota
	// slots the new rollout needs. The NEWEST RS (by creation
	// time) is never touched — it is the rollout's own target.
	// Spec writes on live ReplicaSets go through the shared
	// maintenance mutex + heal budget like every other heal.
	if len(rsList) > 1 {
		ck2 := probefw.SelfHealKey(CheckNameDeploymentRolloutWedge,
			ns+"/"+name+"/rs-zero")
		proceed2, unverifiable2 := p.HealAllowed(ctx, log, &p.nudgeHeals,
			ck2, rolloutWedgeRSZeroCooldown, now)
		if unverifiable2 {
			metrics.IncError(p.Name)
			return
		}
		if proceed2 {
			sorted := append([]rsCensusRow{}, rsList...)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].creationTime.Before(sorted[j].creationTime)
			})
			zeroed := 0
			for i := 0; i < len(sorted)-1 && zeroed < rolloutWedgeMaxRSZero; i++ {
				rs := sorted[i]
				if rs.replicas == 0 || rs.ready > 0 {
					continue
				}
				payload, _ := json.Marshal(map[string]any{
					"spec": map[string]any{"replicas": int32(0)},
				})
				if _, err := p.CS.AppsV1().ReplicaSets(ns).Patch(ctx, rs.name,
					types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
					metrics.IncError(p.Name)
					log.Error(err, "rollout wedge stale RS zero failed",
						"replicaset", ns+"/"+rs.name)
					continue
				}
				zeroed++
				log.Info("ACTION: scaled stale ReplicaSet to 0 (quota release)",
					"replicaset", ns+"/"+rs.name, "deployment", ns+"/"+name)
			}
			if zeroed > 0 {
				p.nudgeHeals.Stamp(ck2, now)
			}
		}
	}
	// Stage 3 — template nudge: skip intentionally-downscaled
	// Deployments (the wedge signature is expected there) and
	// Git-owned objects (a template nudge on a Flux-managed
	// Deployment ping-pongs the source every reconcile).
	if kube.IsIntentionallyDownscaled(d.Annotations, d.Spec.Replicas) {
		return
	}
	if !heal.FluxPatchGate("deployment", d, ns+"/"+name, now) {
		log.Info("SKIP: rollout wedge nudge — Flux Heal-Revert Loop",
			"deployment", ns+"/"+name)
		return
	}
	// Only when the persisted cooldown clears AND the maintenance
	// gate allows. The wider-of in-RAM+annotation window keeps a
	// restarted operator honest.
	ck := probefw.SelfHealKey(CheckNameDeploymentRolloutWedge, ns+"/"+name)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.nudgeHeals, d, kube.AnnoLastDeploymentUnstick, ck,
		rolloutWedgeNudgeCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	patch := kube.RestartTemplatePatch(now)
	if _, err := p.CS.AppsV1().Deployments(ns).Patch(ctx, name,
		types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "rollout wedge template nudge failed",
			"deployment", ns+"/"+name)
		return
	}
	if err := heal.StampPersisted(ctx, d,
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().Deployments(ns).Patch(ctx, name,
				types.MergePatchType, data, metav1.PatchOptions{})
			return err
		}, kube.AnnoLastDeploymentUnstick, &p.nudgeHeals, ck, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "rollout wedge nudge stamp failed",
			"deployment", ns+"/"+name)
	}
	log.Info("ACTION: deployment rollout wedge template nudge",
		"deployment", ns+"/"+name)
	p.InvalidateDeployments(ctx)
}

// emitWedgeEvent fires ONE deduped Warning event per window naming
// the wedged Deployments.
func (p *deploymentRolloutWedgeCheck) emitWedgeEvent(ctx context.Context,
	log logr.Logger, findings []string, now time.Time) {

	if len(findings) == 0 {
		return
	}
	ck := probefw.SelfHealKey(CheckNameDeploymentRolloutWedge, "event")
	if p.eventHealed.CooledDown(ck, rolloutWedgeEventCooldown, now) {
		return
	}
	msg := fmt.Sprintf("deployment rollout wedge: %d deployment(s) (%s)",
		len(findings), findings[0])
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "deployment-rollout-wedge-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "DeploymentRolloutWedged",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: rollout wedge event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: DeploymentRolloutWedged", "detail", msg)
}
