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
// serves silently goes stale.
//
// The heal for (b) and (c) is the shared pod bounce — a
// UID-preconditioned delete through probefw.DeletePodHeal, gated by
// the 30m cooldown and the maintenance mutex: restarting the holder
// restarts its elector loop / re-authenticates the watch stream on
// a fresh SA token.
package nodehealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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
	// re-firing.
	wedgeSeen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]

	// ksmLogProbe is the pod log-tail seam — tests inject a
	// fixture; the zero value runs the real bounded GetLogs tail
	// through probefw.PodLogTail.
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

	// A KSM reflector/401 signature must persist 10m before the pod
	// counts as wedged — a single retry burst is self-healing.
	ksmWedgeMinAge     = 10 * time.Minute
	ksmPodHealCooldown = 30 * time.Minute
	ksmLogTailLines    = int64(200)
	ksmLogMaxBytes     = int64(256 * 1024)
	ksmLogTimeout      = 8 * time.Second

	// node_automation_controller_lease_unhealthy reason labels.
	leaseReasonFlapping           = "flapping"
	leaseReasonExpiredRunningPods = "expired_with_running_pods"
	leaseReasonKSMUnauthorized    = "ksm_unauthorized"
	leaseReasonKSMReflectorErrors = "ksm_reflector_errors"
)

// leaseGuardNamespaces are the control-plane namespaces whose
// coordination.k8s.io/v1 Leases the guard audits — every namespace a
// cluster controller or platform operator elects its leader in.
var leaseGuardNamespaces = []string{
	"kube-system", "flux-system", "node-ops", "operators",
	"linkerd", "argocd", "cert-manager", "external-secrets",
}

// ksmWedgeSignatures map a lower-cased log marker to the reason it
// reports — ordered most-specific first so a reflector line whose
// cause is a 401 still classifies as the auth wedge. "the server has
// asked for the client to provide credentials" is client-go's
// canonical expired-SA-token 401.
var ksmWedgeSignatures = []struct {
	marker string
	reason string
}{
	{"unauthorized", leaseReasonKSMUnauthorized},
	{"401", leaseReasonKSMUnauthorized},
	{"provide credentials", leaseReasonKSMUnauthorized},
	{"token expired", leaseReasonKSMUnauthorized},
	{"failed to list", leaseReasonKSMReflectorErrors},
	{"failed to watch", leaseReasonKSMReflectorErrors},
	{"unable to sync caches", leaseReasonKSMReflectorErrors},
}

var (
	// Control-plane leader-election Leases unhealthy past their
	// window, plus wedged kube-state-metrics pods (the lease label
	// carries the pod name for KSM findings).
	controllerLeaseUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_controller_lease_unhealthy",
		Help: "1 while a control-plane Lease flaps or sits expired with running pods, or a kube-state-metrics pod is wedged.",
	}, []string{"namespace", "lease", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		controllerLeaseUnhealthyGauge)
}

// checkControllerLeaseGuard sweeps the watched namespaces' Leases for
// the flap and expired-lease signatures, then the KSM wedge healer.
// A per-namespace list error marks the check infra-failed but does
// not stop the sweep — and the failed namespace's held tuples carry
// forward so "never evaluated" never reads as "resolved".
func (p *controllerLeaseGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()

	current := map[string][]string{}
	var findings []string
	var firstErr error

	// podsCache memoizes the per-namespace pod list the
	// expired-lease heuristic needs — fetched lazily, only for
	// namespaces that actually carry a stale-aged lease; the error
	// is memoized too, so a failing apiserver is not re-listed once
	// per stale lease in the namespace.
	podsCache := map[string][]corev1.Pod{}
	podErrs := map[string]error{}
	podsInNS := func(ns string) ([]corev1.Pod, error) {
		if l, ok := podsCache[ns]; ok {
			return l, nil
		}
		if err, ok := podErrs[ns]; ok {
			return nil, err
		}
		l, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.Pods(p.CS, ns))
		if err != nil {
			podErrs[ns] = err
			return nil, err
		}
		podsCache[ns] = l
		return l, nil
	}

	liveLeases := map[string]bool{}
	for _, ns := range leaseGuardNamespaces {
		leases, err := p.CS.CoordinationV1().Leases(ns).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("list leases in %s: %w", ns, err)
			}
			p.carryNamespace(current, liveLeases, ns)
			continue
		}
		for i := range leases.Items {
			lease := &leases.Items[i]
			key := ns + "/" + lease.Name
			liveLeases[key] = true
			if p.leaseFlapping(key, lease, now) {
				p.emitUnhealthy(current, ns, lease.Name, leaseReasonFlapping)
				findings = append(findings, key+"("+leaseReasonFlapping+")")
			}
			if !leaseStaleWindow(lease, now) {
				continue
			}
			pods, err := podsInNS(ns)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("list pods in %s: %w", ns, err)
				}
				p.carryNamespace(current, liveLeases, ns)
				continue
			}
			targets := controllerRunningPods(lease, pods)
			if len(targets) == 0 {
				// Holder gone AND no sibling under the same
				// controller — a dead operator, not a wedged
				// elector (pod-status checks own that class).
				continue
			}
			p.emitUnhealthy(current, ns, lease.Name,
				leaseReasonExpiredRunningPods)
			findings = append(findings,
				key+"("+leaseReasonExpiredRunningPods+")")
			p.healStaleLeaseController(ctx, log, lease, targets, now)
		}
	}
	p.pruneTransitions(liveLeases)

	ksmFindings, err := p.checkKSMWedged(ctx, log, now, current)
	findings = append(findings, ksmFindings...)
	if err != nil && firstErr == nil {
		firstErr = err
	}

	p.emitted.Reconcile(current, controllerLeaseUnhealthyGauge.DeleteLabelValues)
	if len(findings) == 0 {
		if firstErr != nil {
			return probefw.Result{Infra: firstErr}
		}
		return probefw.Result{Pass: true}
	}
	sort.Strings(findings)
	return probefw.Result{
		Infra: firstErr,
		Why:   "controller leases unhealthy: " + strings.Join(findings, ", "),
	}
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
// Expired lease + running pods — the wedged-elector signature + heal
// ---------------------------------------------------------------------------

// leaseStaleWindow reports whether the lease's renewTime is inside
// the wedge window: stale past leaseStaleMinAge but younger than
// leaseStaleMaxAge. A nil renewTime can't be judged; a lease stale
// past the max is an abandoned corpse, not a wedged elector.
func leaseStaleWindow(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.RenewTime == nil {
		return false
	}
	stale := now.Sub(lease.Spec.RenewTime.Time)
	return stale >= leaseStaleMinAge && stale < leaseStaleMaxAge
}

// controllerRunningPods returns the Running, non-terminating pods in
// pods attributable to the lease's controller: pods the holderIdentity
// names directly (client-go's "<pod>_<uuid>", kept verbatim too for
// electors that don't suffix), pods sharing the controller owner UID
// of a resolved holder pod, and — the fallback for a holder pod
// already gone — pods named "<lease name>-*".
func controllerRunningPods(lease *coordinationv1.Lease, pods []corev1.Pod) []corev1.Pod {
	holderNames := map[string]bool{}
	if h := lease.Spec.HolderIdentity; h != nil && *h != "" {
		holderNames[*h] = true
		if i := strings.LastIndex(*h, "_"); i > 0 {
			holderNames[(*h)[:i]] = true
		}
	}
	ownerUIDs := map[types.UID]bool{}
	for i := range pods {
		if !holderNames[pods[i].Name] {
			continue
		}
		if ref := metav1.GetControllerOf(&pods[i]); ref != nil {
			ownerUIDs[ref.UID] = true
		}
	}
	var out []corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodRunning ||
			pod.DeletionTimestamp != nil {
			continue
		}
		if _, mirror := pod.Annotations["kubernetes.io/config.mirror"]; mirror {
			// Static control-plane pods (kube-controller-manager,
			// kube-scheduler) hold leader-election leases by node
			// name and match the "<lease>-*" fallback — but deleting
			// a mirror pod never restarts the static process, so it
			// is a no-op heal that would repeat every cooldown.
			continue
		}
		if holderNames[pod.Name] ||
			strings.HasPrefix(pod.Name, lease.Name+"-") {
			out = append(out, *pod)
			continue
		}
		if ref := metav1.GetControllerOf(pod); ref != nil &&
			ownerUIDs[ref.UID] {
			out = append(out, *pod)
		}
	}
	return out
}

// healStaleLeaseController bounces the oldest Running pod of the
// stale lease's controller — restarting the holder's pod restarts
// its elector loop (and re-reads a fresh SA token), which either
// renews the lease or clears the way for a standby to take it. The
// shared pod-delete heal carries the cooldown, the maintenance-mutex
// gate and the UID precondition.
func (p *controllerLeaseGuardCheck) healStaleLeaseController(
	ctx context.Context, log logr.Logger, lease *coordinationv1.Lease,
	targets []corev1.Pod, now time.Time) {

	oldest := &targets[0]
	for i := range targets {
		if targets[i].CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = &targets[i]
		}
	}
	p.DeletePodHeal(ctx, log, CheckNameControllerLeaseGuard,
		lease.Namespace+"/"+lease.Name, oldest, leasePodHealCooldown, now)
}

// ---------------------------------------------------------------------------
// kube-state-metrics wedge healer
// ---------------------------------------------------------------------------

// checkKSMWedged scans Running kube-state-metrics pods for the
// reflector/token wedge and returns this sweep's finding strings. A
// signature that persists past ksmWedgeMinAge reports the pod on the
// gauge AND bounces it — the restart re-mounts a fresh SA token and
// re-opens the watch streams a wedged client cannot recover.
func (p *controllerLeaseGuardCheck) checkKSMWedged(ctx context.Context,
	log logr.Logger, now time.Time,
	current map[string][]string) ([]string, error) {

	pods, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(p.CS, metav1.NamespaceAll))
	if err != nil {
		// Never evaluated — carry the held ksm tuples forward so the
		// sweep-end reconcile keeps their series (the scan failed;
		// nothing was proven resolved).
		for k, lv := range p.emitted.Last() {
			if len(lv) == 3 && strings.HasPrefix(lv[2], "ksm_") {
				current[k] = lv
			}
		}
		return nil, fmt.Errorf("list pods (kube-state-metrics wedge scan): %w", err)
	}
	var findings []string
	wedgeLive := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if !isKSMPod(pod) || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		reason, err := p.ksmWedgeReason(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken log/metrics read
			// must not read as "no wedge": keep the first-seen
			// tracking and any held series for this pod.
			log.Info("WARN: ksm wedge signature inconclusive",
				"pod", key, "error", err)
			wedgeLive[key] = true
			for k, lv := range p.emitted.Last() {
				if strings.HasPrefix(k, key+"/") {
					current[k] = lv
				}
			}
			continue
		}
		if reason == "" {
			continue
		}
		wedgeLive[key] = true
		if !probefw.Persisted(&p.wedgeSeen, key, now,
			ksmWedgeMinAge, log) {
			continue
		}
		p.emitUnhealthy(current, pod.Namespace, pod.Name, reason)
		findings = append(findings, key+"("+reason+")")
		p.DeletePodHeal(ctx, log, CheckNameControllerLeaseGuard,
			"ksm/"+key, pod, ksmPodHealCooldown, now)
	}
	p.wedgeSeen.Prune(func(k string) bool { return wedgeLive[k] })
	return findings, nil
}

// isKSMPod matches kube-state-metrics pods by the
// app.kubernetes.io/name label the kube-prometheus-stack chart
// ships, falling back to the deployment name prefix for installs
// without the label.
func isKSMPod(pod *corev1.Pod) bool {
	return pod.Labels["app.kubernetes.io/name"] == "kube-state-metrics" ||
		strings.HasPrefix(pod.Name, "kube-state-metrics-")
}

// ksmWedgeReason resolves this sweep's wedge signature for one
// kube-state-metrics pod. The log tail is the primary signal — the
// injected seam in tests, the bounded GetLogs tail in production;
// when the tail reads clean, the Prometheus counter increase is the
// "or metrics" half of the detection (a spamming reflector can
// rotate the 401 storm out of the last tail lines between sweeps).
// "" is clean; an error means inconclusive.
func (p *controllerLeaseGuardCheck) ksmWedgeReason(ctx context.Context,
	pod *corev1.Pod) (string, error) {

	probe := p.ksmLogProbe
	if probe == nil {
		probe = func(ctx context.Context, pod *corev1.Pod) (string, error) {
			return ksmLogTailWedge(ctx, p.CS, pod)
		}
	}
	reason, err := probe(ctx, pod)
	if err != nil {
		return "", fmt.Errorf("log tail: %w", err)
	}
	if reason != "" {
		return reason, nil
	}
	errs, err := p.ksmReflectorErrorIncrease(ctx, pod)
	if err != nil {
		return "", fmt.Errorf("prometheus: %w", err)
	}
	if errs > 0 {
		return leaseReasonKSMReflectorErrors, nil
	}
	return "", nil
}

// ksmLogTailWedge is the production log-tail probe: the pod's last
// ksmLogTailLines lines (bounded by ksmLogMaxBytes / ksmLogTimeout)
// scanned for the wedge signatures — the reason of the first hit,
// "" when clean. A fetch failure is inconclusive, not healthy.
func ksmLogTailWedge(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod) (string, error) {

	reason := ""
	hit, err := probefw.PodLogTail(ctx, cs, pod, "",
		ksmLogTailLines, ksmLogMaxBytes, ksmLogTimeout,
		func(line string) bool {
			l := strings.ToLower(line)
			for _, sig := range ksmWedgeSignatures {
				if strings.Contains(l, sig.marker) {
					reason = sig.reason
					return true
				}
			}
			return false
		})
	if err != nil || !hit {
		return "", err
	}
	return reason, nil
}

// ksmReflectorErrorIncrease is the metrics half of the wedge OR: KSM
// exports per-resource list/watch counters labelled result="error" —
// a wedged stream shows a continuous increase. A missing series is
// clean; a query failure is inconclusive.
func (p *controllerLeaseGuardCheck) ksmReflectorErrorIncrease(
	ctx context.Context, pod *corev1.Pod) (float64, error) {

	samples, err := p.PromQuery(ctx, fmt.Sprintf(
		`sum(increase(kube_state_metrics_list_total{result="error",pod="%s"}[10m])) + sum(increase(kube_state_metrics_watch_total{result="error",pod="%s"}[10m]))`,
		pod.Name, pod.Name))
	if err != nil {
		return 0, err
	}
	total := 0.0
	for _, s := range samples {
		total += s.Value
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// Gauge + carry-forward helpers
// ---------------------------------------------------------------------------

// emitUnhealthy records one unhealthy tuple on the gauge and in this
// sweep's current set — Reconcile at the end prunes every tuple the
// sweep did not re-assert.
func (p *controllerLeaseGuardCheck) emitUnhealthy(
	current map[string][]string, ns, name, reason string) {

	lv := []string{ns, name, reason}
	current[ns+"/"+name+"/"+reason] = lv
	controllerLeaseUnhealthyGauge.WithLabelValues(lv...).Set(1)
}

// carryNamespace re-registers the held gauge tuples and flap history
// keys of a namespace whose scan never ran this sweep (list error) —
// "not evaluated" must not read as "resolved", or one API flap would
// prune live series and re-arm every persistence window.
func (p *controllerLeaseGuardCheck) carryNamespace(
	current map[string][]string, liveLeases map[string]bool, ns string) {

	for k, lv := range p.emitted.Last() {
		if strings.HasPrefix(k, ns+"/") {
			current[k] = lv
		}
	}
	for k := range p.transitions {
		if strings.HasPrefix(k, ns+"/") {
			liveLeases[k] = true
		}
	}
}
