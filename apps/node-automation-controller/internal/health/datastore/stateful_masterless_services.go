// stateful_masterless_services.go — the
// stateful-masterless-services check (W6.2): a master-role Service
// routing to a ready StatefulSet's pods reporting 0 Ready endpoints
// past the gauge window — the operator that assigns the role wedged.
// The dragonfly auto-heals live in dragonfly_heals.go, the generic
// db-operator heal in db_operator_heals.go.
package datastore

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// statefulMasterlessCheck is the W6.2 masterless service guard plus
// the Dragonfly/db-operator auto-heals.
type statefulMasterlessCheck struct {
	*probefw.Deps

	// W6.2 watchdog state (serial sweep — unguarded):
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
	//     (W7-C3; the STS annotation is the durable half).
	//   - drOpHealAt: the newest drHealed stamp — the in-RAM half
	//     of "when did step 1 last land" for the W7-C3 settle gate
	//     (a CooldownSet suppresses repeats but cannot report the
	//     latest stamp back, so the moment is carried alongside).
	stsZeroSince   state.FirstSeenLedger
	stsZeroEmitted state.GaugeLedger[string]
	drHealed       state.CooldownSet
	drPodHealed    state.CooldownSet
	drOpHealAt     time.Time
	// W12-SC2 watchdog state:
	//   - multiMasterStreak: "ns/svc/sts" → consecutive sweeps the
	//     master-role Service showed >1 Ready endpoints — a
	//     split-brain must hold two sweeps to outlive a relabeling
	//     flap.
	//   - multiMasterEmitted / siteSkewEmitted: the emitted-gauge
	//     ledgers for the W12-SC2 tuples — a split-brain or skew
	//     that resolves loses its series via DeleteLabelValues.
	multiMasterStreak  state.StreakLedger
	multiMasterEmitted state.GaugeLedger[string]
	siteSkewEmitted    state.GaugeLedger[string]
	// verdict memoizes the maintenance-mutex evaluation the
	// per-target heal preambles share — one evaluation per
	// Verdict TTL instead of three API reads per masterless service.
	verdict kube.Verdict
}

// newStatefulMasterlessCheck builds the W6.2 check — the ledgers
// arm lazily on first use (the GaugeLedger zero value is ready).
func NewStatefulMasterlessCheck(d *probefw.Deps) probefw.Check {
	return &statefulMasterlessCheck{Deps: d}
}

// W6.2 — stateful-masterless-services knobs.
const (
	// CheckNameStatefulMasterless is the check's kuberhealthy_check
	// label value — W6.2; not a ported HealthCheck but reports
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

	// W7-C3 — dual-replica deadlock: past this zero-endpoint streak
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

	// W12-SC2 — split-brain: a master-role Service carrying >1
	// Ready endpoint must hold this many consecutive sweeps — an
	// operator relabeling flap settles inside one.
	statefulMultiMasterMinStreak = 2
	// W12-SC2 — primary-site skew: the two DC zones this cluster
	// spans. After maintenance on the main site every stateful
	// master can stay pinned to the standby site — reads/writes
	// then pay the inter-DC tunnel RTT forever.
	statefulMainSiteZone    = "datahub"
	statefulStandbySiteZone = "lanit"
	// statefulSiteSkewMaxPinned: at or above this share of all
	// evaluated stateful masters pinned to the standby zone the
	// pinning is a cluster-level skew event, not one operator's
	// election outcome.
	statefulSiteSkewMaxPinned = 0.8
)

var (
	// W6.2 — the masterless-service signal: 1 while the master-role
	// Service of a ready StatefulSet reports 0 Ready endpoints.
	statefulServiceZeroEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_service_zero_endpoints",
		Help: "1 while the master-role Service of a ready StatefulSet reports 0 Ready endpoints.",
	}, []string{"namespace", "service", "statefulset"})

	// W12-SC2 — the split-brain signal: 1 while a master-role
	// Service routes to more than one Ready pod for two consecutive
	// sweeps (two pods answering the master role at once).
	statefulServiceMultipleMastersGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_service_multiple_masters",
		Help: "1 while a master-role Service reports >1 Ready endpoints for >=2 consecutive sweeps — a multi-master split brain.",
	}, []string{"namespace", "service", "statefulset"})

	// W12-SC2 — the cross-DC pinning signal: 1 while a stateful
	// master's Ready endpoint lives in the standby zone (lanit)
	// while the STS also serves Ready replicas in the main zone
	// (datahub) — or while >=80% of all stateful masters are pinned
	// to the standby zone.
	statefulMasterSiteSkewGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_master_site_skew",
		Help: "1 while a stateful master's Ready endpoint is pinned to the standby topology zone while the main zone serves Ready replicas (or >=80% of all stateful masters are standby-pinned).",
	}, []string{"namespace", "service", "statefulset", "zone"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		statefulServiceZeroEndpointsGauge,
		statefulServiceMultipleMastersGauge,
		statefulMasterSiteSkewGauge)
}

// ---------------------------------------------------------------------------
// stateful-masterless-services (W6.2) — masterless service guard +
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
// with the moment its zero-endpoint streak began — the W7-C3
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

	stsList, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.StatefulSets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	svcList, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.Services(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	// Ready-endpoint census per ns/service — same source as the
	// webhook guard (paged, service-name label binding, nil ready
	// counts as ready). A list error skips the whole check: "0
	// ready" is indistinguishable from "no data". W12-SC2 keeps the
	// endpoint detail (zone/node/targetRef) so the split-brain and
	// site-skew signatures can place each endpoint.
	ready := map[string][]readyEndpoint{}
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.EndpointSlices(p.CS, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				key := s.Namespace + "/" + svc
				for _, ep := range s.Endpoints {
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						continue
					}
					e := readyEndpoint{}
					if ep.Zone != nil {
						e.zone = *ep.Zone
					}
					if ep.NodeName != nil {
						e.node = *ep.NodeName
					}
					if ref := ep.TargetRef; ref != nil && ref.Kind == "Pod" {
						e.podKey = ref.Namespace + "/" + ref.Name
					}
					ready[key] = append(ready[key], e)
				}
			}
			return nil
		})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}

	// W12-SC2 reads: node topology zones (the skew gate + the
	// nodeName resolution path) and the pod census (targetRef
	// fallback + STS replica zones). Same full-truth posture —
	// either list failing skips the skew eval entirely, never a
	// false pin.
	nodeZone := map[string]string{}
	zoneWorkers := map[string]bool{} // zones with >=1 Ready schedulable worker
	podNode := map[string]string{}   // "ns/name" -> nodeName
	var podItems []corev1.Pod
	nodes, nerr := kube.ListNodes(ctx, p.CS)
	pods, perr := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.Pods(p.CS, metav1.NamespaceAll))
	skewEval := nerr == nil && perr == nil
	if !skewEval {
		// Tolerated: the skew signatures go dark this sweep, the
		// masterless/multimaster ones are unaffected.
		log.Info("WARN: node/pod census failed — site-skew evaluation skipped",
			"nodeErr", fmt.Sprint(nerr), "podErr", fmt.Sprint(perr))
	} else {
		for i := range nodes {
			nodeZone[nodes[i].Name] = nodes[i].Labels[corev1.LabelTopologyZone]
			if kube.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
				!kube.IsControlPlane(&nodes[i]) {
				if z := nodeZone[nodes[i].Name]; z != "" {
					zoneWorkers[z] = true
				}
			}
		}
		podItems = pods
		for i := range pods {
			podNode[pods[i].Namespace+"/"+pods[i].Name] = pods[i].Spec.NodeName
		}
	}
	// The skew signatures only mean something on a multi-zone
	// cluster where BOTH sites have live workers — a single-zone
	// cluster or a dead site can't skew.
	multiZone := zoneWorkers[statefulMainSiteZone] &&
		zoneWorkers[statefulStandbySiteZone]

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
	var multiRep, skewRep probefw.SweepReport
	var due []masterlessDue // past the heal window
	totalMasters := 0
	lanitPinned := map[string][]string{} // candidate key -> lv, for standby-pinned masters
	emittedSkew := map[string]bool{}     // keys already flagged this sweep (dedup A vs B triggers)
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
		// W12-SC2(i) — multi-master split brain: >1 Ready endpoint
		// on the master role two sweeps running. A relabeling flap
		// settles inside one sweep; two pods answering the role at
		// once is an election split.
		if len(eps) > 1 {
			if p.multiMasterStreak.Hit(key) >= statefulMultiMasterMinStreak {
				multiRep.Flag(statefulServiceMultipleMastersGauge, key,
					[]string{c.ns, c.svc, c.sts.Name})
				rep.Find(key + "(multiple_masters)")
			}
		} else {
			p.multiMasterStreak.Reset(key)
		}
		// W12-SC2(ii) — cross-DC pin accounting: only meaningful on
		// a multi-zone cluster with a live master to place.
		if multiZone && len(eps) >= 1 {
			totalMasters++
			zones := map[string]bool{}
			resolved := 0
			for _, e := range eps {
				z := endpointZone(e, podNode, nodeZone)
				if z == "" {
					continue
				}
				resolved++
				zones[z] = true
			}
			if zones[statefulStandbySiteZone] {
				// Trigger A: the master lives in the standby zone
				// while the STS still serves Ready replicas in the
				// main zone — reads/writes pay the inter-DC RTT.
				if p.stsReadyInZone(c.sts, podItems, podNode, nodeZone,
					statefulMainSiteZone) {
					skewRep.Flag(statefulMasterSiteSkewGauge,
						key+"/"+statefulStandbySiteZone,
						[]string{c.ns, c.svc, c.sts.Name,
							statefulStandbySiteZone})
					rep.Find(key + "(site_skew " + statefulStandbySiteZone +
						" while datahub replicas ready)")
					emittedSkew[key] = true
				}
			}
			// "Pinned to lanit" = every resolved endpoint lives in
			// the standby zone (an unresolved endpoint can't
			// disprove the pin).
			if resolved > 0 && zones[statefulStandbySiteZone] &&
				!zones[statefulMainSiteZone] {
				lanitPinned[key] = []string{c.ns, c.svc, c.sts.Name,
					statefulStandbySiteZone}
			}
		}
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
		// bounce and the W7-C3 ordinal-0 pod delete, so it runs the
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

	// W12-SC2(ii) trigger B — the pin is cluster-wide when >=80% of
	// evaluated stateful masters live in the standby zone (every
	// resolved endpoint lanit, none datahub). Flag every pinned
	// master not already caught by trigger A.
	if multiZone && totalMasters > 0 &&
		float64(len(lanitPinned))/float64(totalMasters) >= statefulSiteSkewMaxPinned {
		for key, lv := range lanitPinned {
			if emittedSkew[key] {
				continue
			}
			skewRep.Flag(statefulMasterSiteSkewGauge,
				key+"/"+statefulStandbySiteZone, lv)
			rep.Find(fmt.Sprintf("%s(site_skew >=%d%% masters pinned to %s)",
				key, int(statefulSiteSkewMaxPinned*100), statefulStandbySiteZone))
		}
	}

	p.stsZeroSince.Prune(func(k string) bool { return seen[k] })
	p.multiMasterStreak.Prune(func(k string) bool { return evaluated[k] })
	rep.Close(&p.stsZeroEmitted, statefulServiceZeroEndpointsGauge.DeleteLabelValues)
	multiRep.Close(&p.multiMasterEmitted, statefulServiceMultipleMastersGauge.DeleteLabelValues)
	skewRep.Close(&p.siteSkewEmitted, statefulMasterSiteSkewGauge.DeleteLabelValues)

	// Dragonfly auto-heal — a masterless dragonfly past the heal
	// window bounces the operator leader to force re-election (step
	// 1); past the deadlock window and >=3m after that bounce the
	// dual-replica heal deletes the lowest-ordinal pod to restart
	// the election from scratch (step 2, W7-C3). A non-dragonfly
	// masterless STS gets per-pod role diagnostics instead — its
	// election contract is operand-specific and a generic pod kill
	// is not safe to automate.
	for _, d := range due {
		if !dragonflyOwned(d.svc.sts) {
			// W4: a masterless stateful service owned by a known db
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

	return rep.Verdict(fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: ",
		masterlessZeroMinAge), ", ")
}

// ---------------------------------------------------------------------------
// W12-SC2 — split-brain + cross-DC pin helpers.
// ---------------------------------------------------------------------------

// readyEndpoint is the slice-endpoint detail the W12-SC2 signatures
// place: the endpoint's own zone hint, its nodeName, and the
// targetRef pod key the nodeName fallback resolves through.
type readyEndpoint struct {
	zone   string
	node   string
	podKey string // "ns/name" of the targetRef Pod
}

// endpointZone resolves the topology zone a Ready endpoint lives in:
// the slice's own zone field first (the endpointslice controller
// copies the node's zone label — custom producers may not fill it),
// then the endpoint's nodeName through the node census, then the
// targetRef pod's spec.nodeName — the fallback chain the spec calls
// for. "" means unresolvable: an unresolvable endpoint can neither
// confirm nor disprove a pin.
func endpointZone(e readyEndpoint, podNode, nodeZone map[string]string) string {
	if e.zone != "" {
		return e.zone
	}
	if e.node != "" {
		return nodeZone[e.node]
	}
	if e.podKey != "" {
		return nodeZone[podNode[e.podKey]]
	}
	return ""
}

// stsReadyInZone reports whether the StatefulSet has at least one
// Ready pod on a node labeled with the given topology zone — the
// "the STS still serves the main site" half of trigger A.
func (p *statefulMasterlessCheck) stsReadyInZone(sts *appsv1.StatefulSet,
	pods []corev1.Pod, podNode, nodeZone map[string]string, zone string) bool {

	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return false
	}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != sts.Namespace ||
			!sel.Matches(labels.Set(pod.Labels)) ||
			pod.DeletionTimestamp != nil ||
			!kube.PodReadyCond(pod) {
			continue
		}
		if nodeZone[podNode[pod.Namespace+"/"+pod.Name]] == zone {
			return true
		}
	}
	return false
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

// smallestOrdinalPod returns the pod with the lowest StatefulSet
// ordinal — "<sts>-0" in the common case — or nil when none of the
// pods match the "<sts>-<n>" naming. StatefulSet pod names are the
// only source of truth for the ordinal (there is no field for it).
func smallestOrdinalPod(pods []corev1.Pod, stsName string) *corev1.Pod {
	var best *corev1.Pod
	bestOrd := -1
	for i := range pods {
		name := pods[i].Name
		if !strings.HasPrefix(name, stsName+"-") {
			continue
		}
		ord, err := strconv.Atoi(name[len(stsName)+1:])
		if err != nil {
			continue
		}
		if bestOrd < 0 || ord < bestOrd {
			bestOrd = ord
			best = &pods[i]
		}
	}
	return best
}

// logStatefulPodRoles dumps per-pod role-label diagnostics for a
// masterless non-dragonfly StatefulSet — the W7-C3 pod-delete heal
// is dragonfly-only (its election contract is operator-driven), so
// for Percona/PostgreSQL/NATS the check leaves this evidence trail
// for the on-call engineer instead of acting on it. Diagnostics
// only: a list failure must not escalate into a run error.
func (p *statefulMasterlessCheck) logStatefulPodRoles(ctx context.Context, log logr.Logger, sig masterSvc) {
	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		return
	}
	pods, err := p.CS.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
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

// ---------------------------------------------------------------------------
// go-kube-downscaler awareness — shared by the datastore cluster-CR
// checks (rabbitmq-quorum-health, dragonfly-replica-sync-storm).
// ---------------------------------------------------------------------------

// downscaledClusterCRs lists the cluster CRs of gvr the
// go-kube-downscaler parked — spec.replicas explicitly 0 plus a
// downscaler/* annotation (kube.IsIntentionallyDownscaled) — keyed
// "ns/name". A nil dynamic client or an absent CRD reads as "none
// parked": the calling check works pod-first and simply cannot
// prove the park, so the pod-level signatures keep their normal
// posture.
func downscaledClusterCRs(ctx context.Context, dyn dynamic.Interface,
	gvr schema.GroupVersionResource) (map[string]bool, error) {
	out := map[string]bool{}
	if dyn == nil {
		return out, nil
	}
	list, err := dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return out, nil
	case err != nil:
		return nil, err
	}
	for i := range list.Items {
		cr := &list.Items[i]
		var reps *int32
		if n, found := kube.NestedInt64(cr.Object, "spec", "replicas"); found {
			r := int32(n)
			reps = &r
		}
		if kube.IsIntentionallyDownscaled(cr.GetAnnotations(), reps) {
			out[cr.GetNamespace()+"/"+cr.GetName()] = true
		}
	}
	return out, nil
}

// ownsOrdinalPod reports whether podName is one of the cluster CR's
// member pods — the operators name them "<cr>-<ordinal>"
// (dragonfly) or "<cr>-server-<ordinal>" (rabbitmq), so the
// remainder after the "<cr>-" prefix must be an ordinal with an
// optional "server-" midfix. A bare prefix match would let a parked
// "db" cluster excuse a live "db-cache-0" pod.
func ownsOrdinalPod(crName, podName string) bool {
	rest, ok := strings.CutPrefix(podName, crName+"-")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "server-")
	_, err := strconv.Atoi(rest)
	return err == nil
}

// downscaledMemberPod reports whether ns/podName is a member pod of
// an intentionally-downscaled cluster CR (a key set built by
// downscaledClusterCRs).
func downscaledMemberPod(ns, podName string, downscaled map[string]bool) bool {
	for key := range downscaled {
		crNS, crName, ok := strings.Cut(key, "/")
		if !ok || crNS != ns {
			continue
		}
		if ownsOrdinalPod(crName, podName) {
			return true
		}
	}
	return false
}
