// readiness_gate_wedge_guard.go — health check "readiness-gate-wedge-guard":
// detects Running Pods whose ContainersReady=True and Ready=False due to an
// unsatisfied spec.readinessGates condition persisting >= 10m (FirstSeenLedger).
// Emits node_automation_pod_readiness_gate_wedged{namespace,pod,gate} and
// cooldown-deduped Warning Events (ReadinessGateWedged).
//
// Opt-in heal (NODE_AUTOMATION_READINESS_GATE_HEAL_ENABLED=true, default false):
// bounces wedged Pods carrying passiontech.dev/readiness-gate-heal="true" via
// probefw.DeletePodHeal (HealAllowed + workload disruption slot + UID-preconditioned
// delete + cooldown).
package watchdogs

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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameReadinessGateWedgeGuard is the registry check name for readiness-gate-wedge-guard.
	CheckNameReadinessGateWedgeGuard = "readiness-gate-wedge-guard"

	readinessGateMinAge           = 10 * time.Minute
	readinessGateEventCooldown    = 30 * time.Minute
	readinessGateHealCooldown     = 30 * time.Minute
	readinessGateMaxEventsSweep   = 20
	readinessGateMaxHealsPerSweep = 4
	readinessGateEventReason      = "ReadinessGateWedged"
	readinessGateHealAnno         = "passiontech.dev/readiness-gate-heal"
)

var readinessGateWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_pod_readiness_gate_wedged",
	Help: "1 while a Running Pod has ContainersReady=True and Ready=False due to an unsatisfied spec.readinessGates condition >=10m.",
}, []string{"namespace", "pod", "gate"})

func init() {
	ctrlmetrics.Registry.MustRegister(readinessGateWedgedGauge)
}

type readinessGateWedgeGuardCheck struct {
	*probefw.Deps

	healEnabled bool

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewReadinessGateWedgeGuardCheck constructs the readiness-gate-wedge-guard check.
func NewReadinessGateWedgeGuardCheck(d *probefw.Deps) probefw.Check {
	return &readinessGateWedgeGuardCheck{
		Deps:        d,
		healEnabled: envx.Gate("NODE_AUTOMATION_READINESS_GATE_HEAL_ENABLED", false),
	}
}

type readinessGateFinding struct {
	pod  *corev1.Pod
	gate string
}

func (c *readinessGateWedgeGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, readinessGateEventCooldown)

	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	var findings []readinessGateFinding
	liveFirstSeen := map[string]bool{}

	for i := range pods {
		pod := &pods[i]
		gates := readinessGateUnsatisfied(pod)
		if len(gates) == 0 {
			continue
		}
		for _, gate := range gates {
			fsKey := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID) + "/" + gate
			liveFirstSeen[fsKey] = true
			if !probefw.Persisted(&c.firstSeen, fsKey, now, readinessGateMinAge, log) {
				continue
			}
			tupleKey := pod.Namespace + "/" + pod.Name + "/" + gate
			rep.Emit(readinessGateWedgedGauge, tupleKey,
				[]string{pod.Namespace, pod.Name, gate},
				fmt.Sprintf("%s/%s (gate=%s)", pod.Namespace, pod.Name, gate))
			findings = append(findings, readinessGateFinding{pod: pod, gate: gate})
		}
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b readinessGateFinding) int {
		if x := cmp.Compare(a.pod.Namespace, b.pod.Namespace); x != 0 {
			return x
		}
		if x := cmp.Compare(a.pod.Name, b.pod.Name); x != 0 {
			return x
		}
		return cmp.Compare(a.gate, b.gate)
	})

	c.emitEvents(ctx, log, now, findings)

	if c.healEnabled && len(findings) > 0 {
		c.healOptedInPods(ctx, log, now, findings)
	}

	return rep.Result(&c.emitted, readinessGateWedgedGauge.DeleteLabelValues,
		"readiness gate wedged: ", ", ")
}

func (c *readinessGateWedgeGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []readinessGateFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= readinessGateMaxEventsSweep {
			log.Info("SKIP rest: readiness-gate-wedge-guard event cap reached",
				"cap", readinessGateMaxEventsSweep)
			break
		}
		cooldownKey := "readinessgate." + f.pod.Namespace + "." + f.pod.Name + "." + f.gate
		note := fmt.Sprintf("Pod %s/%s has ContainersReady=True but Ready=False due to unsatisfied readinessGate %q for >=%s",
			f.pod.Namespace, f.pod.Name, f.gate, readinessGateMinAge)
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, readinessGateEventCooldown, now, kube.WarningEvent{
			Namespace: f.pod.Namespace,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  f.pod.Namespace,
				Name:       f.pod.Name,
				UID:        f.pod.UID,
			},
			Reason:            readinessGateEventReason,
			Note:              note,
			ReportingInstance: cmp.Or(c.Name, CheckNameReadinessGateWedgeGuard),
		}) {
			emitted++
		}
	}
}

func (c *readinessGateWedgeGuardCheck) healOptedInPods(ctx context.Context, log logr.Logger, now time.Time, findings []readinessGateFinding) {
	seenPod := map[string]bool{}
	healed := 0
	for _, f := range findings {
		if healed >= readinessGateMaxHealsPerSweep {
			log.Info("SKIP rest: readiness-gate-wedge-guard heal cap reached",
				"cap", readinessGateMaxHealsPerSweep)
			break
		}
		pod := f.pod
		podKey := pod.Namespace + "/" + pod.Name
		if seenPod[podKey] {
			continue
		}
		seenPod[podKey] = true

		if !strings.EqualFold(strings.TrimSpace(kube.EffectiveAnno(ctx, pod, readinessGateHealAnno)), "true") {
			continue
		}
		if c.DeletePodHeal(ctx, log, CheckNameReadinessGateWedgeGuard,
			kube.PodControllerKey(pod), pod, readinessGateHealCooldown, now) {
			healed++
		}
	}
}

func readinessGateUnsatisfied(pod *corev1.Pod) []string {
	if pod.DeletionTimestamp != nil ||
		pod.Status.Phase != corev1.PodRunning ||
		len(pod.Spec.ReadinessGates) == 0 {
		return nil
	}
	condStatus := make(map[corev1.PodConditionType]corev1.ConditionStatus, len(pod.Status.Conditions))
	for _, cond := range pod.Status.Conditions {
		condStatus[cond.Type] = cond.Status
	}
	if condStatus[corev1.ContainersReady] != corev1.ConditionTrue ||
		condStatus[corev1.PodReady] != corev1.ConditionFalse {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, rg := range pod.Spec.ReadinessGates {
		gate := string(rg.ConditionType)
		if gate == "" || seen[gate] {
			continue
		}
		if condStatus[rg.ConditionType] != corev1.ConditionTrue {
			seen[gate] = true
			out = append(out, gate)
		}
	}
	return out
}
