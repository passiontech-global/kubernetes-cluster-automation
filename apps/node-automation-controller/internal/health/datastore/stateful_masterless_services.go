// stateful_masterless_services.go — the
// stateful-masterless-services check (stateful-masterless-services): a master-role Service
// routing to a ready StatefulSet's pods reporting 0 Ready endpoints
// past the gauge window — the operator that assigns the role wedged.
// The dragonfly auto-heals live in dragonfly_heals.go, the generic
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
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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
	//   - drHealed: operator pod "ns/name" → last delete — the
	//     in-RAM half of the 30m dragonfly heal cooldown (the STS
	//     annotation stamp is the durable half).
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
func (p *statefulMasterlessCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	stsList, err := p.AllStatefulSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	svcList, err := p.AllServices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	// Ready-endpoint census per ns/service — the shared rollup the
	// endpoint censuses converge on (service-name label binding,
	// nil ready counts as ready — kube.ReadyEndpointsByService). A
	// list error skips the whole check: "0 ready" is
	// indistinguishable from "no data". stateful-split-brain keeps the endpoint
	// detail (zone/node/targetRef) the rollup captures so the
	// split-brain and site-skew signatures can place each endpoint.
	// The census rides the per-sweep snapshot — this check was the
	// last one paying its own cluster-wide list.
	esSlices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}
	ready := kube.ReadyEndpointsByService(esSlices)

	// stateful-split-brain(ii) — arm the cross-DC site-skew sweep: the census
	// reads, the multi-zone gate and the trigger bookkeeping live
	// in site_skew.go.
	skew := p.siteSkew.begin(ctx, log, p.Deps)

	// Candidates: a ready STS paired with a master-role Service
	// routing to its pods.
	var candidates []masterSvc
	for i := range stsList {
		sts := &stsList[i]
		// A StatefulSet the go-kube-downscaler parked at
		// spec.replicas:0 (downscaler/* annotations present) is
		// asleep on purpose — its master Service reading 0 ready
		// endpoints is intent, not a wedged operator.
		if kube.IsIntentionallyDownscaled(sts.Annotations, sts.Spec.Replicas) {
			continue
		}
		if sts.Status.ReadyReplicas == 0 {
			continue
		}
		for j := range svcList {
			svc := &svcList[j]
			if svc.Namespace != sts.Namespace ||
				svc.Spec.ClusterIP == "" ||
				svc.Spec.ClusterIP == corev1.ClusterIPNone {
				continue // headless services are deliberately per-pod
			}
			if !masterRoleService(svc) ||
				!selectorMatchesSTS(svc, sts.Spec.Template.Labels) {
				continue
			}
			candidates = append(candidates,
				masterSvc{ns: svc.Namespace, svc: svc.Name, sts: sts})
		}
	}

	seen := map[string]bool{}      // tuples observed at 0 ready this sweep
	evaluated := map[string]bool{} // candidate keys evaluated this sweep — the streak's keep set
	var rep probefw.SweepReport    // tuples past the gauge window
	var multiRep probefw.SweepReport
	var due []masterlessDue // past the heal window
	for _, c := range candidates {
		key := c.ns + "/" + c.svc + "/" + c.sts.Name
		evaluated[key] = true
		sts := c.sts
		patch := func(ctx context.Context, data []byte) error {
			_, err := p.CS.AppsV1().StatefulSets(sts.Namespace).Patch(ctx,
				sts.Name, types.MergePatchType, data,
				metav1.PatchOptions{})
			return err
		}
		eps := ready[c.ns+"/"+c.svc]
		// stateful-split-brain(i)/(ii) — the split-brain streak and the cross-DC
		// pin accounting, one signature per file.
		p.splitBrain.eval(c, key, len(eps), &multiRep)
		skew.evalMaster(c, key, eps, &rep)
		if len(eps) > 0 {
			// Master reachable — the signature resolved on a live
			// object: drop the persisted stamp so a recurrence
			// re-arms the full window (a stale stamp would
			// fast-trip the heal). Tolerated sub-failure — the
			// ledger Forget already landed, the annotation retry
			// is Warn-only.
			if err := heal.ClearPersistedFirstSeen(ctx, log,
				&p.stsZeroSince, sts,
				kube.AnnoFirstSeenStatefulMasterless, key,
				patch); err != nil {
				log.Info("WARN: masterless first-seen clear failed",
					"statefulset", sts.Namespace+"/"+sts.Name,
					"error", err)
			}
			continue
		}
		seen[key] = true
		// The zero-endpoint streak gates the dragonfly/db-operator
		// bounce and the dual-replica-deadlock ordinal-0 pod delete, so it runs the
		// persisted (annotation-backed) variant — the stamp on the
		// STS survives an operator restart that would otherwise
		// re-arm the gauge and heal windows mid-wedge.
		if !heal.FirstSeenPersisted(ctx, log, &p.stsZeroSince, sts,
			kube.AnnoFirstSeenStatefulMasterless, key,
			masterlessZeroMinAge, now, patch) {
			continue
		}
		rep.Emit(statefulServiceZeroEndpointsGauge, key,
			[]string{c.ns, c.svc, c.sts.Name}, key)
		// The heal window reads the same streak — Seen never
		// re-stamps, and reports the WIDER window once
		// FirstSeenPersisted Seeds a resumed persisted stamp back
		// into the ledger (a streak that crossed a restart keeps
		// its full age).
		if age, _ := p.stsZeroSince.Seen(key, now); age >= masterlessHealMinAge {
			due = append(due, masterlessDue{svc: c, since: now.Add(-age)})
		}
	}

	skew.close(&rep)

	p.stsZeroSince.Prune(func(k string) bool { return seen[k] })
	p.splitBrain.streak.Prune(func(k string) bool { return evaluated[k] })
	rep.Close(&p.stsZeroEmitted, statefulServiceZeroEndpointsGauge.DeleteLabelValues)
	multiRep.Close(&p.splitBrain.emitted, statefulServiceMultipleMastersGauge.DeleteLabelValues)

	// Dragonfly auto-heal — a masterless dragonfly past the heal
	// window bounces the operator leader to force re-election (step
	// 1); past the deadlock window and >=3m after that bounce the
	// dual-replica heal deletes the lowest-ordinal pod to restart
	// the election from scratch (step 2, dual-replica-deadlock). A non-dragonfly
	// masterless STS gets per-pod role diagnostics instead — its
	// election contract is operand-specific and a generic pod kill
	// is not safe to automate.
	for _, d := range due {
		if !dragonflyOwned(d.svc.sts) {
			// va-stuck-terminating: a masterless stateful service owned by a known db
			// operator gets the operator pod bounced to force
			// re-election — the same re-election nudge as the
			// dragonfly heal, on its own per-operator 30m cooldown.
			if op := dbOperatorFor(d.svc.sts); op != "" {
				p.healDBOperator(ctx, log, d.svc, op, now)
			} else {
				p.logStatefulPodRoles(ctx, log, d.svc)
			}
			continue
		}
		p.healDragonflyOperator(ctx, log, d.svc, now)
		if now.Sub(d.since) >= dragonflyReplicaDeadlockMinAge {
			p.healDragonflyReplicaDeadlock(ctx, log, d.svc, now)
		}
	}

	// Zero-endpoints and split-brain are OPPOSITE signatures (0
	// ready masters vs >1) — each renders under its own verdict
	// wording instead of the split-brain findings hiding behind the
	// "0 ready endpoints" prefix (heal-budget verdict-detail fix).
	res := rep.Verdict(fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: ",
		masterlessZeroMinAge), ", ")
	if split := multiRep.Verdict(
		"master-role services with multiple ready masters (split brain) "+
			">=2 sweeps: ", ", "); split.Why != "" {
		if res.Why != "" {
			res.Why += " | " + split.Why
		} else {
			res.Why = split.Why
			res.Pass = false
		}
		if res.Infra == nil {
			res.Infra = split.Infra
		}
	}
	return res
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
