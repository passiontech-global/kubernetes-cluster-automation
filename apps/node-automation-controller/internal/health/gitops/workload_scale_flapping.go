// workload_scale_flapping.go — the workload-scale-flapping check
// (scale-flap): counts ScalingReplicaSet events per
// Deployment/StatefulSet over the last hour and flags any workload
// whose scale direction reversed >=6 times — the runtime signature
// of a three-way tug-of-war between Flux GitOps (static
// spec.replicas), go-kube-downscaler and HPA/KEDA, where each
// reconcile scales the workload back the other way. Detection only —
// the static --downscaler gate in check-workload-hygiene.sh is the
// prevention half; this check is the canary.
package gitops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// workloadScaleFlappingCheck is the scale-flap scale tug-of-war
// detector.
type workloadScaleFlappingCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]
}

// NewWorkloadScaleFlappingCheck builds the scale-flap check — the
// emitted ledger is zero-value usable.
func NewWorkloadScaleFlappingCheck(d *probefw.Deps) probefw.Check {
	return &workloadScaleFlappingCheck{Deps: d}
}

const (
	// CheckNameWorkloadScaleFlapping is the check's kuberhealthy_check
	// label value — scale-flap; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameWorkloadScaleFlapping = "workload-scale-flapping"
	// scaleFlapReason is the kube-controller-manager event reason for
	// replica-set scale actions — emitted on the owning
	// Deployment/StatefulSet for every scale-up/scale-down, whoever
	// drove it (GitOps apply, downscaler, HPA, KEDA, kubectl).
	scaleFlapReason = "ScalingReplicaSet"
	// stsFlapCreateReason / stsFlapDeleteReason are the StatefulSet
	// controller's pod create/delete event reasons — the STS scale
	// surface. StatefulSets never emit ScalingReplicaSet (that
	// reason belongs to the Deployment→ReplicaSet path): their
	// scale-up/down appears as SuccessfulCreate/SuccessfulDelete
	// with messages "create Pod X in StatefulSet Y successful" /
	// "delete Pod X in StatefulSet Y successful" and the
	// StatefulSet as the involved object.
	stsFlapCreateReason = "SuccessfulCreate"
	stsFlapDeleteReason = "SuccessfulDelete"
	// W16-G1 — the Argo Rollouts controller's scale event reasons.
	// The Rollouts controller never emits ScalingReplicaSet (it
	// creates its ReplicaSets directly): its scale-ups/downs surface
	// as RolloutScaledUp/RolloutScaledDown on the parent Rollout
	// with the same "Scaled up replica set X to N" message shape.
	rolloutFlapUpReason   = "RolloutScaledUp"
	rolloutFlapDownReason = "RolloutScaledDown"
	// scaleFlapWindow bounds the event history the flap counter
	// reads — events older than this cannot be evidence of a live
	// tug-of-war (event TTLs are short anyway).
	scaleFlapWindow = time.Hour
	// scaleFlapMinFlips is the direction-change count inside
	// scaleFlapWindow that marks a tug-of-war. Each full up→down or
	// down→up oscillation is one flip; a workload scaling steadily in
	// one direction never reaches it.
	scaleFlapMinFlips = 6
)

var (
	// scale-flap — workload scale tug-of-war.
	workloadScaleFlappingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_workload_scale_flapping",
		Help: "1 while the workload's scale direction flipped >=6 times in the last hour (GitOps/downscaler/autoscaler tug-of-war) — scale-flap.",
	}, []string{"namespace", "kind", "name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		workloadScaleFlappingGauge)
}

// scaleFlapEvent is one direction-tagged scaling observation.
type scaleFlapEvent struct {
	t  time.Time
	up bool // true = scale up, false = scale down
}

// flapKey is the (namespace, kind, name) identity of the workload an
// event's involvedObject names.
type flapKey struct {
	ns, kind, name string
}

// Run scans corev1 Events carrying scale actions over the last hour
// — Deployments flap on reason=ScalingReplicaSet, StatefulSets on
// SuccessfulCreate/SuccessfulDelete (their controller never emits
// ScalingReplicaSet). The server-side reason field selector does the
// first cut per reason and the in-code re-check keeps the count
// honest under clients that accept the selector silently (and under
// the fake clientset). Per involvedObject the events sort by their
// freshest timestamp (kube.EventTime's LAST-observed convention);
// each transition from "Scaled up" to "Scaled down" — or create to
// delete — counts one flip, and >=6 flips in the window emits the
// gauge + FAILs the check.
func (p *workloadScaleFlappingCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var events []corev1.Event
	for _, reason := range []string{
		scaleFlapReason, stsFlapCreateReason, stsFlapDeleteReason,
		rolloutFlapUpReason, rolloutFlapDownReason} {
		evs, err := kube.ListAll(ctx, metav1.ListOptions{
			FieldSelector: "reason=" + reason,
			Limit:         probefw.HealthListPageSize,
		}, kube.Events(p.CS, metav1.NamespaceAll))
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("list scaling events: %w", err)}
		}
		events = append(events, evs...)
	}

	perWorkload := map[flapKey][]scaleFlapEvent{}
	for i := range events {
		e := &events[i]
		t := kube.EventTime(e)
		if t.IsZero() || now.Sub(t) > scaleFlapWindow {
			continue
		}
		// Direction lives in the verb on both event surfaces: the
		// Deployment path's message is "Scaled up replica set X to N"
		// / "Scaled down replica set X to N"; the StatefulSet
		// path's is "create Pod X in StatefulSet Y successful" /
		// "delete Pod X in StatefulSet Y successful" — create is a
		// scale-UP signal, delete a scale-DOWN one. The StatefulSet
		// reasons additionally key on kind+message so a Job's
		// SuccessfulCreate ("Created pod: ...") can never count.
		var up, down bool
		switch e.Reason {
		case scaleFlapReason:
			up = strings.Contains(e.Message, "Scaled up")
			down = strings.Contains(e.Message, "Scaled down")
		case stsFlapCreateReason, stsFlapDeleteReason:
			if e.InvolvedObject.Kind != "StatefulSet" ||
				!strings.Contains(e.Message, "in StatefulSet ") {
				continue
			}
			up = e.Reason == stsFlapCreateReason
			down = e.Reason == stsFlapDeleteReason
		case rolloutFlapUpReason, rolloutFlapDownReason:
			// W16-G1 — the reason IS the direction; the message
			// re-check keeps the count honest under silent-selector
			// fakes the same way the Deployment path does. The
			// involvedObject kind is the parent Rollout (GVRArgoRollout).
			if e.InvolvedObject.Kind != "Rollout" ||
				!strings.Contains(e.Message, "Scaled") {
				continue
			}
			up = e.Reason == rolloutFlapUpReason
			down = e.Reason == rolloutFlapDownReason
		}
		if !up && !down {
			continue
		}
		io := e.InvolvedObject
		ns := io.Namespace
		if ns == "" {
			ns = e.Namespace
		}
		if io.Kind == "" || io.Name == "" {
			continue // cannot attribute the flap
		}
		k := flapKey{ns: ns, kind: io.Kind, name: io.Name}
		perWorkload[k] = append(perWorkload[k],
			scaleFlapEvent{t: t, up: up})
	}

	var rep probefw.SweepReport
	for k, evs := range perWorkload {
		// Direction changes are order-sensitive — sort by the
		// event's freshest timestamp so a re-emitted event lands by
		// its latest observation, not its birth.
		sort.Slice(evs, func(i, j int) bool { return evs[i].t.Before(evs[j].t) })
		flips := 0
		for i := 1; i < len(evs); i++ {
			if evs[i].up != evs[i-1].up {
				flips++
			}
		}
		if flips < scaleFlapMinFlips {
			continue
		}
		key := k.ns + "/" + k.kind + "/" + k.name
		rep.Emit(workloadScaleFlappingGauge, key,
			[]string{k.ns, k.kind, k.name},
			fmt.Sprintf("%s %s/%s(%d flips)", k.kind, k.ns, k.name, flips))
		log.Info("workload scale tug-of-war detected",
			"namespace", k.ns, "kind", k.kind, "name", k.name,
			"flips", flips, "window", scaleFlapWindow)
	}
	return rep.Result(&p.emitted, workloadScaleFlappingGauge.DeleteLabelValues,
		"workloads scale-flapping: ", ", ")
}
