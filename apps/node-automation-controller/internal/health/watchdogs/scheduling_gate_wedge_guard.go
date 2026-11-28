// scheduling_gate_wedge_guard.go — health check "scheduling-gate-wedge-guard":
// detects Pending Pods carrying non-empty spec.schedulingGates past >= 15m.
// Emits node_automation_pod_scheduling_gate_wedged{namespace,gate} and
// cooldown-deduped Warning Events (SchedulingGateWedged).
//
// Opt-in heal (NODE_AUTOMATION_SCHEDULING_GATE_HEAL_ENABLED=true, default false):
// removes spec.schedulingGates ONLY on Pods carrying
// passiontech.dev/scheduling-gate-heal="true", gated behind HealAllowed +
// cooldown + UID-preconditioned resourceVersion merge patch.
package watchdogs

import (
	"cmp"
	"context"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	// CheckNameSchedulingGateWedgeGuard is the registry check name for scheduling-gate-wedge-guard.
	CheckNameSchedulingGateWedgeGuard = "scheduling-gate-wedge-guard"

	schedulingGateMinAge           = 15 * time.Minute
	schedulingGateEventCooldown    = 30 * time.Minute
	schedulingGateHealCooldown     = 30 * time.Minute
	schedulingGateMaxEventsSweep   = 20
	schedulingGateMaxHealsPerSweep = 4
	schedulingGateEventReason      = "SchedulingGateWedged"
	schedulingGateHealAnno         = "passiontech.dev/scheduling-gate-heal"
)

var schedulingGateWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pod_scheduling_gate_wedged",
	Help: "1 while Pending Pods in a namespace carry non-empty spec.schedulingGates past >=15m.",
}, []string{"namespace", "gate"})

func init() {
	ctrlmetrics.Registry.MustRegister(schedulingGateWedgedGauge)
}

type schedulingGateWedgeGuardCheck struct {
	*probefw.Deps

	healEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewSchedulingGateWedgeGuardCheck constructs the scheduling-gate-wedge-guard check.
func NewSchedulingGateWedgeGuardCheck(d *probefw.Deps) probefw.Check {
	return &schedulingGateWedgeGuardCheck{
		Deps:        d,
		healEnabled: envx.Gate("NODE_AUTOMATION_SCHEDULING_GATE_HEAL_ENABLED", false),
	}
}

type schedulingGateFinding struct {
	pod   *corev1.Pod
	gates []string
}

func (c *schedulingGateWedgeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, schedulingGateEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	var findings []schedulingGateFinding
	liveFirstSeen := map[string]bool{}

	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodPending ||
			len(pod.Spec.SchedulingGates) == 0 {
			continue
		}

		persisted := false
		if !pod.CreationTimestamp.IsZero() {
			persisted = kube.AgeAtLeast(pod.CreationTimestamp.Time, now, schedulingGateMinAge)
		} else {
			fsKey := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
			liveFirstSeen[fsKey] = true
			persisted = probefw.Persisted(&c.firstSeen, fsKey, now, schedulingGateMinAge, log)
		}
		if !persisted {
			continue
		}

		var gates []string
		seenGate := map[string]bool{}
		for _, g := range pod.Spec.SchedulingGates {
			if g.Name == "" || seenGate[g.Name] {
				continue
			}
			seenGate[g.Name] = true
			gates = append(gates, g.Name)
			tupleKey := pod.Namespace + "/" + g.Name
			rep.Flag(schedulingGateWedgedGauge, tupleKey, []string{pod.Namespace, g.Name})
		}
		if len(gates) == 0 {
			continue
		}
		slices.Sort(gates)
		rep.Find(fmt.Sprintf("%s/%s (gates=%s)", pod.Namespace, pod.Name, strings.Join(gates, ",")))
		findings = append(findings, schedulingGateFinding{pod: pod, gates: gates})
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b schedulingGateFinding) int {
		if x := cmp.Compare(a.pod.Namespace, b.pod.Namespace); x != 0 {
			return x
		}
		return cmp.Compare(a.pod.Name, b.pod.Name)
	})

	c.emitEvents(ctx, log, now, findings)

	if c.healEnabled && len(findings) > 0 {
		c.healOptedInPods(ctx, log, now, findings)
	}

	return rep.Result(&c.emitted, schedulingGateWedgedGauge.DeleteLabelValues,
		"scheduling gate wedged: ", ", ")
}

func (c *schedulingGateWedgeGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []schedulingGateFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= schedulingGateMaxEventsSweep {
			log.Info("SKIP rest: scheduling-gate-wedge-guard event cap reached",
				"cap", schedulingGateMaxEventsSweep)
			break
		}
		cooldownKey := "schedgate." + f.pod.Namespace + "." + f.pod.Name
		note := fmt.Sprintf("Pod %s/%s stuck Pending for >=%s due to schedulingGates [%s]",
			f.pod.Namespace, f.pod.Name, schedulingGateMinAge, strings.Join(f.gates, ", "))
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, schedulingGateEventCooldown, now, kube.WarningEvent{
			Namespace: f.pod.Namespace,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  f.pod.Namespace,
				Name:       f.pod.Name,
				UID:        f.pod.UID,
			},
			Reason:            schedulingGateEventReason,
			Note:              note,
			ReportingInstance: cmp.Or(c.Name, CheckNameSchedulingGateWedgeGuard),
		}) {
			emitted++
		}
	}
}

func (c *schedulingGateWedgeGuardCheck) healOptedInPods(ctx context.Context, log logr.Logger, now time.Time, findings []schedulingGateFinding) {
	healed := 0
	invalidated := false
	for _, f := range findings {
		if healed >= schedulingGateMaxHealsPerSweep {
			log.Info("SKIP rest: scheduling-gate-wedge-guard heal cap reached",
				"cap", schedulingGateMaxHealsPerSweep)
			break
		}
		pod := f.pod
		if !strings.EqualFold(strings.TrimSpace(kube.EffectiveAnno(ctx, pod, schedulingGateHealAnno)), "true") {
			continue
		}

		podKey := pod.Namespace + "/" + pod.Name
		healKey := probefw.SelfHealKey(CheckNameSchedulingGateWedgeGuard, podKey)
		proceed, unverifiable := c.HealAllowed(ctx, log, &c.Heals, healKey, schedulingGateHealCooldown, now)
		if unverifiable {
			metrics.IncError(c.Name)
			break
		}
		if !proceed {
			continue
		}

		metaPatch := map[string]any{}
		if pod.UID != "" {
			metaPatch["uid"] = string(pod.UID)
		}
		if pod.ResourceVersion != "" {
			metaPatch["resourceVersion"] = pod.ResourceVersion
		}
		patchDoc := map[string]any{
			"spec": map[string]any{"schedulingGates": nil},
		}
		if len(metaPatch) > 0 {
			patchDoc["metadata"] = metaPatch
		}
		payload, err := json.Marshal(patchDoc, json.FormatNilMapAsNull(true))
		if err != nil {
			heal.RefundGrant(now)
			metrics.IncError(c.Name)
			log.Error(err, "marshal schedulingGates clear patch", "pod", podKey)
			continue
		}
		_, err = c.CS.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, payload, metav1.PatchOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				heal.RefundGrant(now)
				continue
			}
			metrics.IncError(c.Name)
			log.Error(err, "clear schedulingGates failed", "pod", podKey)
			continue
		}
		c.Heals.Stamp(healKey, now)
		healed++
		invalidated = true
		log.Info("PATCH: removed stuck schedulingGates from opted-in Pod",
			"pod", podKey, "gates", strings.Join(f.gates, ","))
	}
	if invalidated {
		c.InvalidatePods(ctx)
	}
}
