// workload_scale_flapping.go — the workload-scale-flapping check
// (W13-SC1 / Gap #5): counts ScalingReplicaSet events per
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// workloadScaleFlappingCheck is the W13-SC1 scale tug-of-war
// detector.
type workloadScaleFlappingCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]
}

// NewWorkloadScaleFlappingCheck builds the W13-SC1 check — the
// emitted ledger is zero-value usable.
func NewWorkloadScaleFlappingCheck(d *probefw.Deps) probefw.Check {
	return &workloadScaleFlappingCheck{Deps: d}
}

const (
	// CheckNameWorkloadScaleFlapping is the check's kuberhealthy_check
	// label value — W13-SC1; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameWorkloadScaleFlapping = "workload-scale-flapping"
	// scaleFlapReason is the kube-controller-manager event reason for
	// replica-set scale actions — emitted on the owning
	// Deployment/StatefulSet for every scale-up/scale-down, whoever
	// drove it (GitOps apply, downscaler, HPA, KEDA, kubectl).
	scaleFlapReason = "ScalingReplicaSet"
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
	// W13-SC1 — workload scale tug-of-war.
	workloadScaleFlappingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_workload_scale_flapping",
		Help: "1 while the workload's scale direction flipped >=6 times in the last hour (GitOps/downscaler/autoscaler tug-of-war) — W13-SC1.",
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

// Run scans corev1 Events with reason=ScalingReplicaSet over the
// last hour — the server-side reason field selector does the first
// cut and the in-code re-check keeps the count honest under clients
// that accept the selector silently (and under the fake clientset).
// Per involvedObject the events sort by their freshest timestamp
// (kube.EventTime's LAST-observed convention); each transition from
// "Scaled up" to "Scaled down" or back counts one flip, and >=6
// flips in the window emits the gauge + FAILs the check.
func (p *workloadScaleFlappingCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	events, err := kube.ListAll(ctx, metav1.ListOptions{
		FieldSelector: "reason=" + scaleFlapReason,
		Limit:         probefw.HealthListPageSize,
	}, kube.Events(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list scaling events: %w", err)}
	}

	perWorkload := map[flapKey][]scaleFlapEvent{}
	for i := range events {
		e := &events[i]
		if e.Reason != scaleFlapReason {
			continue // selector re-check — belt-and-braces
		}
		t := kube.EventTime(e)
		if t.IsZero() || now.Sub(t) > scaleFlapWindow {
			continue
		}
		// The controller's message is "Scaled up replica set X to N"
		// / "Scaled down replica set X to N" — direction lives in the
		// verb; anything else under this reason is not a direction
		// signal.
		up, down := strings.Contains(e.Message, "Scaled up"),
			strings.Contains(e.Message, "Scaled down")
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
