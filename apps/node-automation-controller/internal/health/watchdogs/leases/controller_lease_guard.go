// controller_lease_guard.go — the controller-lease-guard check:
// audits the control-plane leader-election Leases for the two shapes
// a wedged elector takes —
//
//	a) flapping: spec.leaseTransitions climbed >=5 inside the flap
//	   window — the leader keeps dying and being re-elected (crash
//	   loop, clock skew, split brain);
//	b) expired_with_running_pods: spec.renewTime went stale >10m
//	   (but <2h — past that the lease is an abandoned corpse, not a
//	   wedge) while the holder's controller still runs pods — the
//	   pod is alive but its elector loop died (deadlocked client,
//	   expired token), so nothing renews and no standby can take
//	   over;
//
// and c) the kube-state-metrics wedge: a KSM pod whose log tail (or
// its kube_state_metrics_*_total error counters) shows a continuous
// reflector watch/list failure or a stuck 401 Unauthorized / expired
// SA token — the pod stays Ready while every kube_* metric it
// serves silently goes stale. Its detector and healer live in
// ksm_wedge.go.
//
// The heal for (b) and (c) is the shared pod bounce — a
// UID-preconditioned delete through probefw.DeletePodHeal, gated by
// the 30m cooldown and the maintenance mutex: restarting the holder
// restarts its elector loop / re-authenticates the watch stream on
// a fresh SA token.
package leases

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// controllerLeaseGuardCheck is the control-plane lease watchdog —
// the flap ledger, the KSM wedge's persistence tracking and the
// emitted-gauge ledger are its state; pod-delete cooldowns ride the
// shared Deps.Heals set.
type controllerLeaseGuardCheck struct {
	*probefw.Deps

	// transitions is the flap ledger: each watched lease's
	// spec.leaseTransitions samples inside the flap window — the
	// counter is monotonic over a Lease's life, so the increase
	// across the window's oldest and newest samples is the churn
	// count. A sample DECREASE means the Lease object was
	// recreated — the history resets instead of undercounting.
	transitions map[string][]leaseTransitionSample
	// wedgeSeen tracks the kube-state-metrics wedge signature's
	// first-seen sweep — the persistence window a reflector/401
	// wedge must outlast before the pod counts as wedged; pruned on
	// recovery so a later wedge re-arms instead of instantly
	// re-firing. The window gates a pod bounce, so it runs the
	// annotation-backed variant (heal.FirstSeenPersisted, stamped
	// on the pod under kube.AnnoFirstSeenKSMWedge) — a restart
	// resumes the count instead of re-arming it.
	wedgeSeen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	// thrashEmitted is the stateful-split-brain twin for the thrashing tuples.
	emitted       state.GaugeLedger[string]
	thrashEmitted state.GaugeLedger[string]

	// ksmLogProbe is the pod log-tail seam — tests inject a
	// fixture; the zero value runs the real bounded GetLogs tail
	// through kube.ReadPodLogTail.
	ksmLogProbe func(ctx context.Context, pod *corev1.Pod) (string, error)
}

// leaseTransitionSample is one sweep's observation of a lease's
// cumulative spec.leaseTransitions counter.
type leaseTransitionSample struct {
	at          time.Time
	transitions int32
}

// NewControllerLeaseGuardCheck builds the lease guard — its state is
// the transitions/wedgeSeen/emitted ledgers; heal cooldowns ride the
// shared Deps.Heals set.
func NewControllerLeaseGuardCheck(d *probefw.Deps) probefw.Check {
	return &controllerLeaseGuardCheck{Deps: d}
}

const (
	CheckNameControllerLeaseGuard = "controller-lease-guard"

	// Flap detection: a lease whose holder changed >=5 times inside
	// the window is election churn — the controller is crash-looping
	// or split-braining, not electing normally.
	leaseFlapMinTransitions = int32(5)
	leaseFlapWindow         = 15 * time.Minute

	// stateful-split-brain — thrashing: the tighter early-warning under the flap
	// threshold. >=4 transitions inside 10m is election churn the
	// 15m window hasn't proven yet.
	leaseThrashMinTransitions = int32(4)
	leaseThrashWindow         = 10 * time.Minute

	// Expired-lease window: a client-go elector renews every ~2s
	// inside a ~15s leaseDuration, so a renewTime stale past 10m
	// means the elector loop is dead. Past 2h the lease is an
	// abandoned corpse — a standby would have taken it over on
	// leaseDuration expiry or the workload is genuinely gone, and a
	// pod bounce there heals nothing.
	leaseStaleMinAge = 10 * time.Minute
	leaseStaleMaxAge = 2 * time.Hour

	// leasePodHealCooldown bounds controller-pod bounces to one per
	// stale lease per 30m — the restarted elector needs the
	// leaseDuration plus renew headroom to prove the heal worked.
	leasePodHealCooldown = 30 * time.Minute

	// node_automation_controller_lease_unhealthy reason labels.
	leaseReasonFlapping           = "flapping"
	leaseReasonExpiredRunningPods = "expired_with_running_pods"
)

// leaseGuardNamespaces are the namespaces whose
// coordination.k8s.io/v1 Leases the guard audits — every namespace a
// cluster controller or platform operator elects its leader in.
// W20 adds the platform-operator set: backup (velero), progressive
// delivery (argo-rollouts, kargo), the everest DB stack, the
// dragonfly operator, the second monitoring plane, liqo, the
// stakater reloader, and the CNPG/Scylla operators.
var leaseGuardNamespaces = []string{
	"kube-system", "flux-system", "node-ops", "operators",
	"linkerd", "argocd", "cert-manager", "external-secrets",
	"velero", "argo-rollouts", "kargo", "everest-system", "everest",
	"dragonfly-operator-system", "monitoring", "liqo", "reloader",
	"cnpg-system", "scylla-operator",
}

var (
	// Control-plane leader-election Leases unhealthy past their
	// window, plus wedged kube-state-metrics pods (the lease label
	// carries the pod name for KSM findings).
	controllerLeaseUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_controller_lease_unhealthy",
		Help: "1 while a control-plane Lease flaps or sits expired with running pods, or a kube-state-metrics pod is wedged.",
	}, []string{"namespace", "lease", "reason"})

	// stateful-split-brain — the thrashing early-warning: 1 while a lease's
	// leaseTransitions counter jumped >=4 inside 10m — election
	// churn below the flap threshold.
	controllerLeaseThrashingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_controller_lease_thrashing",
		Help: "1 while a control-plane Lease's leaseTransitions jumped >=4 within 10m — election churn below the flap threshold.",
	}, []string{"namespace", "lease"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		controllerLeaseUnhealthyGauge,
		controllerLeaseThrashingGauge)
}

// checkControllerLeaseGuard sweeps the watched namespaces' Leases for
// the flap and expired-lease signatures, then the KSM wedge healer.
// A per-namespace list error marks the check infra-failed but does
// not stop the sweep — and the failed namespace's held tuples carry
// forward so "never evaluated" never reads as "resolved".
func (p *controllerLeaseGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	var rep, thrashRep probefw.SweepReport

	// podsCache memoizes the per-namespace pod slice the
	// expired-lease heuristic needs — filtered client-side from the
	// sweep's shared pod census (one cluster-wide LIST per cycle),
	// fetched lazily, only for namespaces that actually carry a
	// stale-aged lease; the census error is memoized with the
	// snapshot, so a failing apiserver is not re-listed once per
	// stale lease in the namespace.
	podsCache := map[string][]corev1.Pod{}
	podErrs := map[string]error{}
	podsInNS := func(ns string) ([]corev1.Pod, error) {
		if l, ok := podsCache[ns]; ok {
			return l, nil
		}
		if err, ok := podErrs[ns]; ok {
			return nil, err
		}
		all, err := p.AllPods(ctx)
		if err != nil {
			podErrs[ns] = err
			return nil, err
		}
		var l []corev1.Pod
		for i := range all {
			if all[i].Namespace == ns {
				l = append(l, all[i])
			}
		}
		podsCache[ns] = l
		return l, nil
	}

	liveLeases := map[string]bool{}
	// One memoized cluster LIST per sweep replaces the per-namespace
	// lease LISTs — the census is grouped client-side below. A list
	// failure leaves EVERY guarded namespace unverifiable, so all of
	// them carry forward rather than silently passing.
	allLeases, err := p.AllLeases(ctx)
	if err != nil {
		rep.InfraErr(fmt.Errorf("list leases: %w", err))
		for _, ns := range leaseGuardNamespaces {
			p.carryNamespace(&rep, &thrashRep, liveLeases, ns)
		}
	} else {
		leasesByNS := map[string][]coordinationv1.Lease{}
		for i := range allLeases {
			l := allLeases[i]
			leasesByNS[l.Namespace] = append(leasesByNS[l.Namespace], l)
		}
		// renewTime staleness measures against the moment the census
		// was FETCHED, not p.Now() at this check's run time — the
		// worker pool can delay a check minutes behind the sweep's
		// first reader, and a lease renewed just before the fetch
		// would read artificially stale (and get bounced) to a late
		// runner. Flap/thrash ledgers keep `now`: their windows are
		// check-local bookkeeping, not apiserver-clock comparisons.
		leaseNow := p.LeasesFetchedAt(ctx)
		for _, ns := range leaseGuardNamespaces {
			leases := leasesByNS[ns]
			// podsNSFailed gates the per-namespace pods-list error
			// reporting: every stale lease of the namespace shares the
			// one memoized list (and its error), so the InfraErr and
			// the carry-forward fire ONCE per namespace, not once per
			// lease that never got its pods evaluated.
			podsNSFailed := false
			for i := range leases {
				lease := &leases[i]
				key := ns + "/" + lease.Name
				liveLeases[key] = true
				if p.leaseFlapping(key, lease, now) {
					p.emitUnhealthy(&rep, ns, lease.Name, leaseReasonFlapping)
					rep.Find(key + "(" + leaseReasonFlapping + ")")
				}
				// stateful-split-brain — the tighter early-warning under the flap
				// threshold: >=4 transitions inside 10m is election
				// churn the 15m window hasn't proven yet.
				if p.leaseThrashing(key, now) {
					thrashRep.Flag(controllerLeaseThrashingGauge, key,
						[]string{ns, lease.Name})
					rep.Find(key + "(thrashing)")
				}
				if !leaseStaleWindow(lease, leaseNow) {
					continue
				}
				pods, err := podsInNS(ns)
				if err != nil {
					if !podsNSFailed {
						podsNSFailed = true
						rep.InfraErr(fmt.Errorf("list pods in %s: %w", ns, err))
						p.carryNamespace(&rep, &thrashRep, liveLeases, ns)
					}
					continue
				}
				targets, ambiguous := controllerRunningPods(lease, pods)
				if len(targets) == 0 {
					// Holder gone AND no sibling under the same
					// controller — a dead operator, not a wedged
					// elector (pod-status checks own that class).
					continue
				}
				p.emitUnhealthy(&rep, ns, lease.Name,
					leaseReasonExpiredRunningPods)
				rep.Find(key + "(" + leaseReasonExpiredRunningPods + ")")
				if ambiguous {
					// The "<lease>-*" fallback matched pods from more
					// than one controller — the oldest pod is not
					// provably the wedged elector's, so no heal this
					// cycle (a healthy component must not die on a
					// name-prefix guess).
					log.Info("skip controller lease heal: fallback pod match spans multiple controllers",
						"lease", key)
					continue
				}
				p.healStaleLeaseController(ctx, log, lease, targets, now)
			}
		}
	}
	p.pruneTransitions(liveLeases)

	rep.InfraErr(p.checkKSMWedged(ctx, log, now, &rep))

	thrashRep.Close(&p.thrashEmitted, controllerLeaseThrashingGauge.DeleteLabelValues)
	return rep.Result(&p.emitted, controllerLeaseUnhealthyGauge.DeleteLabelValues,
		"controller leases unhealthy: ", ", ")
}

// ---------------------------------------------------------------------------
// Flap detection — spec.leaseTransitions churn inside the window
// ---------------------------------------------------------------------------

// leaseFlapping records this sweep's leaseTransitions sample for key
// and reports whether the counter climbed >= leaseFlapMinTransitions
// inside leaseFlapWindow. Samples older than the window are dropped
// before the increase is measured; a counter that DECREASED since the
// last sample means the Lease was recreated — its history resets
// rather than undercounting the churn.
func (p *controllerLeaseGuardCheck) leaseFlapping(key string,
	lease *coordinationv1.Lease, now time.Time) bool {

	if p.transitions == nil {
		p.transitions = map[string][]leaseTransitionSample{}
	}
	transitions := int32(0)
	if lease.Spec.LeaseTransitions != nil {
		transitions = *lease.Spec.LeaseTransitions
	}
	samples := p.transitions[key]
	if n := len(samples); n > 0 && transitions < samples[n-1].transitions {
		samples = nil // recreated Lease — the counter restarted
	}
	samples = append(samples,
		leaseTransitionSample{at: now, transitions: transitions})
	cutoff := now.Add(-leaseFlapWindow)
	keep := samples[:0]
	for _, s := range samples {
		if !s.at.Before(cutoff) {
			keep = append(keep, s)
		}
	}
	samples = keep
	p.transitions[key] = samples
	if len(samples) < 2 {
		return false
	}
	return transitions-samples[0].transitions >= leaseFlapMinTransitions
}

// leaseThrashing reports whether the lease's transitions counter
// climbed >= leaseThrashMinTransitions inside leaseThrashWindow —
// the tighter early-warning under leaseFlapping. It reuses the flap
// ledger's samples (leaseFlapping already appended this sweep's
// sample and trimmed to the flap window); the in-window oldest
// sample is the baseline. Fewer than two in-window samples can't
// prove a jump — first sightings read clean.
func (p *controllerLeaseGuardCheck) leaseThrashing(key string, now time.Time) bool {
	samples := p.transitions[key]
	if len(samples) == 0 {
		return false // leaseFlapping normally appends first — never index blind
	}
	cutoff := now.Add(-leaseThrashWindow)
	var first *leaseTransitionSample
	for i := range samples {
		if !samples[i].at.Before(cutoff) {
			first = &samples[i]
			break
		}
	}
	if first == nil {
		return false
	}
	return samples[len(samples)-1].transitions-first.transitions >=
		leaseThrashMinTransitions
}

// pruneTransitions drops flap history for leases that vanished — an
// entry whose Lease no longer exists cannot accumulate into a flap.
func (p *controllerLeaseGuardCheck) pruneTransitions(live map[string]bool) {
	for k := range p.transitions {
		if !live[k] {
			delete(p.transitions, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Gauge + carry-forward helpers
// ---------------------------------------------------------------------------

// emitUnhealthy records one unhealthy tuple on the gauge and in this
// sweep's report — Close at the end prunes every tuple the sweep did
// not re-assert.
func (p *controllerLeaseGuardCheck) emitUnhealthy(
	rep *probefw.SweepReport, ns, name, reason string) {

	rep.Flag(controllerLeaseUnhealthyGauge, ns+"/"+name+"/"+reason,
		[]string{ns, name, reason})
}

// carryNamespace re-registers the held gauge tuples and flap history
// keys of a namespace whose scan never ran this sweep (list error) —
// "not evaluated" must not read as "resolved", or one API flap would
// prune live series and re-arm every persistence window.
func (p *controllerLeaseGuardCheck) carryNamespace(
	rep, thrashRep *probefw.SweepReport, liveLeases map[string]bool, ns string) {

	for k, lv := range p.emitted.Last() {
		if strings.HasPrefix(k, ns+"/") {
			rep.Carry(k, lv)
		}
	}
	for k, lv := range p.thrashEmitted.Last() {
		if strings.HasPrefix(k, ns+"/") {
			thrashRep.Carry(k, lv)
		}
	}
	for k := range p.transitions {
		if strings.HasPrefix(k, ns+"/") {
			liveLeases[k] = true
		}
	}
}
