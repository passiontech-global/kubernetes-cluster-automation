// stateful_masterless_services.go — the
// stateful-masterless-services check (stateful-masterless-services): a master-role Service
// routing to a ready StatefulSet's pods reporting 0 Ready endpoints
// past the gauge window — the operator that assigns the role wedged.
// The per-sweep phases live in stateful_masterless_sweep.go; the
// dragonfly auto-heals live in dragonfly_heals.go, the generic
// db-operator heal in db_operator_heals.go, and the stateful-split-brain
// split-brain/site-skew signatures in split_brain.go/site_skew.go.
package datastore

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// statefulMasterlessCheck is the stateful-masterless-services masterless service guard plus
// the stateful-split-brain signature watches; the Dragonfly/db-operator
// auto-heals live in dragonfly_heals.go / db_operator_heals.go.
type statefulMasterlessCheck struct {
	*probefw.Deps

	// stateful-masterless-services watchdog state (serial sweep — unguarded):
	//   - stsZeroSince: "ns/svc/sts" → first sweep the master-role
	//     Service showed 0 Ready endpoints.
	//   - stsZeroEmitted: the emitted-gauge ledger for
	//     statefulServiceZeroEndpointsGauge — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1 (same hygiene as the
	//     webhook guard's brokenEmitted).
	//   - drHealed: operator pod controller "ns/<rs>" → last delete
	//     (kube.PodControllerKey — the ReplicaSet outlives every pod
	//     it spawns) — the in-RAM half of the 30m dragonfly heal
	//     cooldown (the STS annotation stamp is the durable half).
	//   - drPodHealed: "ns/sts" → last ordinal-0 pod delete — the
	//     in-RAM half of the 30m dual-replica-deadlock cooldown
	//     (dual-replica-deadlock; the STS annotation is the durable half).
	//   - drOpHealed: "ns/sts" -> newest drHealed stamp for THAT
	//     StatefulSet — the in-RAM half of "when did step 1 last
	//     land" for the dual-replica-deadlock settle gate; CooldownSet.Last reports
	//     the stamp back, which a plain CooledDown gate cannot. Keyed
	//     per-STS: a single shared stamp let a second Dragonfly STS ride
	//     on an unrelated STS's operator bounce and skip its settle
	//     window entirely.
	stsZeroSince   state.FirstSeenLedger
	stsZeroEmitted state.GaugeLedger[string]
	drHealed       state.CooldownSet
	drPodHealed    state.CooldownSet
	drOpHealed     state.CooldownSet
	// stateful-split-brain signature watches — each owns its ledgers (see
	// split_brain.go / site_skew.go).
	splitBrain splitBrainWatch
	siteSkew   siteSkewWatch
}

// newStatefulMasterlessCheck builds the stateful-masterless-services check — the ledgers
// arm lazily on first use (the GaugeLedger zero value is ready).
func NewStatefulMasterlessCheck(d *probefw.Deps) probefw.Check {
	return &statefulMasterlessCheck{Deps: d}
}

// stateful-masterless-services — stateful-masterless-services knobs.
const (
	// CheckNameStatefulMasterless is the check's kuberhealthy_check
	// label value — stateful-masterless-services; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameStatefulMasterless = "stateful-masterless-services"
	// masterlessZeroMinAge: a master-role Service must report 0
	// Ready endpoints this long before the gauge fires.
	masterlessZeroMinAge = 3 * time.Minute
	// masterlessHealMinAge: the zero-endpoint streak must reach this
	// before the dragonfly-operator leader gets bounced (5m —
	// longer than the gauge so a flap doesn't kill the operator).
	masterlessHealMinAge  = 5 * time.Minute
	dragonflyHealCooldown = 30 * time.Minute
	// DragonflyOperatorNS + dragonflyOperatorPodPrefix locate
	// the operator pods the heal deletes to force re-election (the
	// namespace is shared with the watchdogs operator-target table).
	dragonflyOperatorPodPrefix = "dragonfly-operator-controller-manager"
	// dragonflyHealAnno persists the last heal moment on the STS —
	// the restart-proof half of the cooldown.
	dragonflyHealAnno = kube.AnnoLastDragonflyOperatorHeal

	// dual-replica-deadlock — dual-replica deadlock: past this zero-endpoint streak
	// the operator restart (step 1) demonstrably failed to re-elect
	// a master, so the STS ordinal-0 pod is deleted to force the
	// whole election from scratch.
	dragonflyReplicaDeadlockMinAge = 10 * time.Minute
	// dragonflyOperatorSettleMin bounds how fresh the operator heal
	// must be before the pod kill is allowed — step 1 needs a few
	// minutes to relabel the pods; deleting ordinal-0 while the new
	// operator is still reconciling reaps the pod pointlessly.
	dragonflyOperatorSettleMin = 3 * time.Minute
	// dragonflyPodHealCooldown bounds ordinal-0 pod deletes to one
	// per STS — wider of the in-RAM ledger and the persisted
	// passiontech.dev/last-dragonfly-pod-heal stamp (same wider-of-both
	// shape as the operator heal above).
	dragonflyPodHealCooldown = 30 * time.Minute
	// dragonflyPodHealAnno persists the last ordinal-0 pod delete on
	// the STS — the restart-proof half of the cooldown.
	dragonflyPodHealAnno = kube.AnnoLastDragonflyPodHeal
)

var (
	// stateful-masterless-services — the masterless-service signal: 1 while the master-role
	// Service of a ready StatefulSet reports 0 Ready endpoints.
	statefulServiceZeroEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_service_zero_endpoints",
		Help: "1 while the master-role Service of a ready StatefulSet reports 0 Ready endpoints.",
	}, []string{"namespace", "service", "statefulset"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		statefulServiceZeroEndpointsGauge)
}

// ---------------------------------------------------------------------------
// stateful-masterless-services (stateful-masterless-services) — masterless service guard +
// dragonfly auto-heal.
// ---------------------------------------------------------------------------

// masterlessRoleKeys are the label keys marking a Service that routes
// only to the master/primary of a stateful set — 0 Ready endpoints on
// it means the workload is leaderless.
var masterlessRoleKeys = []string{"role", "redis-role", "app.kubernetes.io/role"}

// masterlessRoleValues are the role values identifying the master
// side of a replicated stateful service.
var masterlessRoleValues = []string{"master", "primary", "leader"}

// masterRoleService reports whether svc carries a master-role key —
// in its selector (selects only the leader pods) or its own labels
// (the Service is labeled as the master endpoint).
func masterRoleService(svc *corev1.Service) bool {
	for _, k := range masterlessRoleKeys {
		if v := svc.Spec.Selector[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	for _, k := range masterlessRoleKeys {
		if v := svc.Labels[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	return false
}

// selectorMatchesSTS reports whether the Service routes to the
// StatefulSet's pods: every NON-role key in svc.Spec.Selector must
// appear in the STS pod-template labels. Role keys are stripped —
// operators write role=master/replica onto the POD at runtime, never
// into the template, so a literal subset match would never fire for
// exactly the services this check exists to watch (dragonfly/redis
// master services). A selector that carries nothing but role keys
// cannot be attributed to one STS — it matches every workload, so it
// is excluded.
func selectorMatchesSTS(svc *corev1.Service, podLabels map[string]string) bool {
	nonRole := map[string]string{}
	for k, v := range svc.Spec.Selector {
		if slices.Contains(masterlessRoleKeys, k) {
			continue
		}
		nonRole[k] = v
	}
	if len(nonRole) == 0 {
		return false
	}
	return labels.SelectorFromSet(nonRole).Matches(labels.Set(podLabels))
}

// masterSvc pairs a master-role Service with the ready StatefulSet
// whose pod labels its selector matches.
type masterSvc struct {
	ns, svc string
	sts     *appsv1.StatefulSet
}

// masterlessDue pairs a master-role service past the heal window
// with the moment its zero-endpoint streak began — the dual-replica-deadlock
// deadlock heal needs the streak length, not just "past 5m".
type masterlessDue struct {
	svc   masterSvc
	since time.Time
}

// dragonflyOwned reports whether the StatefulSet is managed by the
// dragonfly-operator — via app.kubernetes.io/part-of=dragonfly or
// app.kubernetes.io/created-by=dragonfly-operator on the STS metadata
// or its pod template.
func dragonflyOwned(sts *appsv1.StatefulSet) bool {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		if lbls["app.kubernetes.io/part-of"] == "dragonfly" ||
			lbls["app.kubernetes.io/created-by"] == "dragonfly-operator" {
			return true
		}
	}
	return false
}

// checkStatefulMasterlessServices detects a masterless stateful
// service: a non-headless Service routing to a ready StatefulSet's
// pods under a master-role key whose EndpointSlices report 0 Ready
// endpoints — the STS is alive but clients have no master to reach
// (the operator that assigns the role wedged).
//
// Past masterlessZeroMinAge the gauge
// node_automation_stateful_service_zero_endpoints{ns,svc,sts} goes to
// 1 and the check FAILs; past masterlessHealMinAge a Dragonfly-owned
// STS additionally triggers a dragonfly-operator leader delete (30m
// cooldown) — a wedged operator is the common cause of a missing
// master label/election.
//
// The per-sweep phases (census → candidate pairing → streak/signature
// eval → report close → heal dispatch → verdict) live in
// stateful_masterless_sweep.go.
func (p *statefulMasterlessCheck) Run(ctx context.Context) probefw.Result {
	s, err := p.beginMasterlessSweep(ctx)
	if err != nil {
		return probefw.Result{Infra: err}
	}
	s.evalCandidates(ctx)
	s.closeReports()
	s.healDue(ctx)
	return s.verdict()
}

// podMasterRole reports whether the pod carries a master/primary/
// leader value under any master-role label key — the positive form
// of the dual-replica deadlock check (a pod already holding the
// master role means the election produced a winner and a pod kill
// would fight it).
func podMasterRole(pod *corev1.Pod) bool {
	for _, k := range masterlessRoleKeys {
		if slices.Contains(masterlessRoleValues, pod.Labels[k]) {
			return true
		}
	}
	return false
}

// logStatefulPodRoles dumps per-pod role-label diagnostics for a
// masterless non-dragonfly StatefulSet — the dual-replica-deadlock pod-delete heal
// is dragonfly-only (its election contract is operator-driven), so
// for Percona/PostgreSQL/NATS the check leaves this evidence trail
// for the on-call engineer instead of acting on it. Diagnostics
// only: a list failure must not escalate into a run error.
func (p *statefulMasterlessCheck) logStatefulPodRoles(ctx context.Context, log logr.Logger, sig masterSvc) {
	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		return
	}
	allPods, err := p.AllPods(ctx)
	if err != nil {
		return
	}
	for i := range allPods {
		pod := &allPods[i]
		if pod.Namespace != sig.sts.Namespace ||
			!sel.Matches(labels.Set(pod.Labels)) {
			continue
		}
		roles := map[string]string{}
		for _, k := range masterlessRoleKeys {
			if v := pod.Labels[k]; v != "" {
				roles[k] = v
			}
		}
		log.Info("masterless service — pod role diagnostic",
			"service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
			"pod", pod.Name,
			"ready", kube.PodReadyCond(pod),
			"roles", fmt.Sprintf("%v", roles))
	}
}
