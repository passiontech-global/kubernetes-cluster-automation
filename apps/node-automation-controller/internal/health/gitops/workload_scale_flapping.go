// workload_scale_flapping.go — the workload-scale-flapping check
// (scale-flap): counts ScalingReplicaSet events per
// Deployment/StatefulSet-kind workload and RolloutScaledUp/Down
// events per Argo Rollout over the last hour, plus StatefulSet
// spec.replicas reversals observed across sweeps — and flags any
// workload whose scale direction reversed >=6 times — the runtime
// signature of a three-way tug-of-war between Flux GitOps (static
// spec.replicas), go-kube-downscaler and HPA/KEDA, where each
// reconcile scales the workload back the other way. StatefulSets
// deliberately do NOT use their SuccessfulCreate/SuccessfulDelete
// pod events: those measure status.replicas churn (reschedules fire
// them with no spec change) — spec.replicas is the intent signal.
// Detection only —
// the static --downscaler gate in check-workload-hygiene.sh is the
// prevention half; this check is the canary.
package gitops

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// workloadScaleFlappingCheck is the scale-flap scale tug-of-war
// detector.
type workloadScaleFlappingCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]

	// stsSpecFlap tracks each StatefulSet's last observed
	// spec.replicas and its direction reversals inside
	// scaleFlapWindow. The SuccessfulCreate/SuccessfulDelete pod
	// events this replaces measure status.replicas churn — pod
	// reschedules and restarts fire them with NO spec.replicas
	// change, so node pressure alone could read as scale tug-of-war.
	// spec.replicas is the declarative intent GitOps/downscaler/HPA
	// actually write; reversals in it ARE the flap. In-RAM like
	// emitted: a controller restart re-arms the baseline (the safe
	// direction is a delayed flap alert, never a false one).
	stsSpecFlap map[string]*stsSpecFlapState
}

// stsSpecFlapState is one StatefulSet's spec.replicas flap memory:
// the last desired count, the last direction it moved, and the
// reversal timestamps still inside the event window.
type stsSpecFlapState struct {
	replicas int32
	dir      int8 // last observed direction: +1 up, -1 down, 0 none yet
	flips    []time.Time
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
	// Deployment for every scale-up/scale-down, whoever
	// drove it (GitOps apply, downscaler, HPA, KEDA, kubectl).
	scaleFlapReason = "ScalingReplicaSet"
	// rollout-scale-flap — the Argo Rollouts controller's scale event reasons.
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

// scaleFlapEvent is one direction-tagged scaling observation. rs is
// the ReplicaSet name the message references ("") for non-Deployment
// reasons — the pair-exclusion key that tells one RollingUpdate's
// alternating up/down cadence apart from a real tug-of-war.
type scaleFlapEvent struct {
	t  time.Time
	up bool // true = scale up, false = scale down
	rs string
}

// flapKey is the (namespace, kind, name) identity of the workload an
// event's involvedObject names.
type flapKey struct {
	ns, kind, name string
}

// Run scans corev1 Events carrying scale actions over the last hour
// — Deployments flap on reason=ScalingReplicaSet, Argo Rollouts on
// RolloutScaledUp/RolloutScaledDown; StatefulSets are scored from
// spec.replicas reversals across sweeps instead (their pod
// create/delete events measure status.replicas churn — reschedules
// fire them with no spec change). The events come from the sweep's
// shared census
// (one cluster-wide LIST per run()), filtered client-side on the
// reasons the old server-side field selector pre-cut — the in-code
// re-check keeps the count honest under clients that accept the
// selector silently (and under the fake clientset). Per
// involvedObject the events sort by their freshest timestamp
// (kube.EventTime's LAST-observed convention); each transition from
// "Scaled up" to "Scaled down" — or create to delete — counts one
// flip, EXCEPT the pairs a single rolling update produces (see
// isRolloutPair / the STS mid-rollout gate), and >=6 flips in the
// window emits the gauge + FAILs the check.
func (p *workloadScaleFlappingCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	census, err := p.AllEvents(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list scaling events: %w", err)}
	}
	// The StatefulSet census feeds the spec.replicas flap tracker —
	// a read failure aborts the check (an unreadable desired count
	// must not silently re-enable the false-positive class the
	// spec-anchored signal exists to kill).
	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	// StatefulSet flap evidence comes from spec.replicas transitions
	// (see stsSpecFlap) — the SuccessfulCreate/SuccessfulDelete pod
	// events measure status.replicas churn and are skipped below.
	stsFlips := p.trackSTSSpecFlaps(stss, now)

	perWorkload := map[flapKey][]scaleFlapEvent{}
	for i := range census {
		e := &census[i]
		switch e.Reason {
		case scaleFlapReason, rolloutFlapUpReason, rolloutFlapDownReason:
		default:
			continue
		}
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
		rs := ""
		switch e.Reason {
		case scaleFlapReason:
			up = strings.Contains(e.Message, "Scaled up")
			down = strings.Contains(e.Message, "Scaled down")
			rs = scalingRSName(e.Message)
		case rolloutFlapUpReason, rolloutFlapDownReason:
			// rollout-scale-flap — the reason IS the direction; the message
			// re-check keeps the count honest under silent-selector
			// fakes the same way the Deployment path does. The
			// involvedObject kind is the parent Rollout (GVRArgoRollout).
			if e.InvolvedObject.Kind != "Rollout" ||
				!strings.Contains(e.Message, "Scaled") {
				continue
			}
			up = e.Reason == rolloutFlapUpReason
			down = e.Reason == rolloutFlapDownReason
			// Same ReplicaSet-name separation as the Deployment path:
			// a canary's alternating scale-up/down lands on DIFFERENT
			// ReplicaSets (stable vs canary), and without the rs tag
			// the pair-exclusion below cannot tell that rollout
			// cadence from a real tug-of-war.
			rs = scalingRSName(e.Message)
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
			scaleFlapEvent{t: t, up: up, rs: rs})
	}

	var rep probefw.SweepReport
	// StatefulSet verdicts come from spec.replicas reversals — the
	// pod create/delete events that used to feed this path measure
	// status.replicas churn (reschedules fire them with no spec
	// change), so they no longer count.
	for key, n := range stsFlips {
		if n < scaleFlapMinFlips {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		k := flapKey{ns: parts[0], kind: "StatefulSet", name: parts[1]}
		gkey := k.ns + "/" + k.kind + "/" + k.name
		rep.Emit(workloadScaleFlappingGauge, gkey,
			[]string{k.ns, k.kind, k.name},
			fmt.Sprintf("%s %s/%s(%d spec.replicas flips)",
				k.kind, k.ns, k.name, n))
		log.Info("workload scale tug-of-war detected",
			"namespace", k.ns, "kind", k.kind, "name", k.name,
			"flips", n, "window", scaleFlapWindow, "signal", "spec.replicas")
	}
	for k, evs := range perWorkload {
		// Direction changes are order-sensitive — sort by the
		// event's freshest timestamp so a re-emitted event lands by
		// its latest observation, not its birth.
		slices.SortFunc(evs, func(a, b scaleFlapEvent) int {
			return a.t.Compare(b.t)
		})
		flips := 0
		for i := 1; i < len(evs); i++ {
			if evs[i].up == evs[i-1].up {
				continue
			}
			// One RollingUpdate on a Deployment scales the NEW
			// ReplicaSet up and the OLD one down in an alternating
			// up/down cadence — maxSurge makes it look exactly like
			// tug-of-war. A direction change between two
			// ScalingReplicaSet events naming DIFFERENT ReplicaSets
			// is that rollout cadence, not a flap: only the same
			// ReplicaSet scaling back and forth counts.
			if evs[i].rs != "" && evs[i-1].rs != "" &&
				evs[i].rs != evs[i-1].rs {
				continue
			}
			flips++
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

// trackSTSSpecFlaps folds this sweep's StatefulSet census into the
// per-STS spec.replicas flap memory and returns each workload's
// reversal count inside scaleFlapWindow. A direction reversal only
// counts when the desired count actually moved the OTHER way — a
// steady scale-up series never flips, and a spec.replicas value
// that oscillates faster than the sweep cadence nets out between
// observations (the documented sampling bound of the durable
// signal; the Deployment/Rollout event paths keep sub-sweep
// granularity).
func (p *workloadScaleFlappingCheck) trackSTSSpecFlaps(
	stss []appsv1.StatefulSet, now time.Time) map[string]int {

	if p.stsSpecFlap == nil {
		p.stsSpecFlap = map[string]*stsSpecFlapState{}
	}
	live := make(map[string]bool, len(stss))
	flips := map[string]int{}
	for i := range stss {
		sts := &stss[i]
		key := sts.Namespace + "/" + sts.Name
		live[key] = true
		want := int32(1) // nil spec.replicas defaults to 1
		if sts.Spec.Replicas != nil {
			want = *sts.Spec.Replicas
		}
		st := p.stsSpecFlap[key]
		if st == nil {
			// First observation is the baseline — a workload's
			// current count says nothing about its history.
			p.stsSpecFlap[key] = &stsSpecFlapState{replicas: want}
			continue
		}
		if st.replicas != want {
			dir := int8(1)
			if want < st.replicas {
				dir = -1
			}
			if st.dir != 0 && dir != st.dir {
				st.flips = append(st.flips, now)
			}
			st.dir = dir
			st.replicas = want
		}
		// Drop reversals that aged out of the window — every live
		// STS reports its in-window count, changed or not, or a
		// steady workload's flips would vanish between changes.
		keep := st.flips[:0]
		for _, t := range st.flips {
			if now.Sub(t) <= scaleFlapWindow {
				keep = append(keep, t)
			}
		}
		st.flips = keep
		flips[key] = len(st.flips)
	}
	// Workloads gone from the census drop their memory — a deleted
	// STS recreated under the same name re-arms the baseline.
	for key := range p.stsSpecFlap {
		if !live[key] {
			delete(p.stsSpecFlap, key)
		}
	}
	return flips
}

// scalingRSName extracts the ReplicaSet name a ScalingReplicaSet
// message references — "Scaled up replica set web-5d8f7b9c4 to 3"
// yields "web-5d8f7b9c4". "" when the message does not carry the
// shape (the caller then counts the flip as before instead of
// guessing).
func scalingRSName(msg string) string {
	const marker = "replica set "
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	if j := strings.Index(rest, " to "); j >= 0 {
		return rest[:j]
	}
	return ""
}
