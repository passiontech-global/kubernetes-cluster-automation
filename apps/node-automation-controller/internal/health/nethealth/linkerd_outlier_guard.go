// linkerd_outlier_guard.go — the linkerd-outlier-guard check
// (linkerd-outlier): a single meshed pod whose inbound request traffic
// fails at >=80% while serving >=1 rps — with every same-revision
// sibling healthy (median sibling error <5%) — is a gray-failed
// replica: readiness probes ride HTTP/1.1 and stay green while the
// pod 5xx's every request it is served. Recreating the pod rebuilds
// the proxy's connection/balancer state; the math below exists to
// prove the failure is local to ONE pod, because a downstream
// outage (DB down, upstream wedged) makes the WHOLE cohort fail at
// the same rate and a mass eviction would amplify it.
//
// Detection (Prometheus, 5m window, direction="inbound" — the
// linkerd-proxy response_total vector the destination control plane
// labels per namespace/deployment/pod):
//
//	rps_p  = sum by (namespace, deployment, pod)
//	         (rate(response_total{direction="inbound"}[5m]))
//	err_p  = sum by (namespace, deployment, pod)
//	         (rate(response_total{direction="inbound",
//	          classification="failure"}[5m])) / rps_p
//
// Four mandatory conditions before a pod counts as an outlier:
//  1. rps_p >= 1.0  (>=300 req/5m — a 1/1-request failure must never
//     read as 100% gray failure);
//  2. cohort coherence: every live pod of the Deployment carries the
//     same pod-template-hash (a mid-rollout or canary cohort has no
//     valid control group → skip), and >=1 sibling serves >=0.5 rps;
//  3. err_p >= 0.80;
//  4. median(err_siblings) < 0.05 — a fleet-wide failure rate breaks
//     this and stands the whole check down.
//
// Six safety gates then precede the auto-evict:
//  1. the outlier signature must persist >=5m (FirstSeenLedger —
//     >=2 sweep cycles) and the pod must be >=10m old;
//  2. >=1 genuinely separate Ready sibling under the same
//     controller (ReadySiblings) — evicting the last absorbable
//     replica blackholes the workload;
//  3. a 30m CooldownSet keyed by kube.PodControllerKey(pod) — at
//     most one evicted pod per controller per window;
//  4. every matching PodDisruptionBudget must allow a disruption,
//     and the kill itself rides policy/v1 Eviction (the apiserver
//     re-enforces the budget atomically) with a UID precondition;
//  5. heal.AllowedV — the maintenance mutex plus the global heal
//     budget, fail closed;
//  6. LINKERD_OUTLIER_EVICT_ENABLED=false (resolved at Setup into
//     Cfg.Linkerd.OutlierEvictEnabled) disables only the evict —
//     detection and the gauge stay live either way.
package nethealth

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// linkerdOutlierGuardCheck is the linkerd-outlier single-pod 5xx gray-
// failure watchdog — detection on response_total, eviction behind
// the six gates documented in the file header.
type linkerdOutlierGuardCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// seen is the outlier persistence ledger — the 5m window the
	// evict side requires so a one-sweep blip never kills a pod
	// (in-RAM only: the pod is the delete target, so a persisted
	// stamp would die with it anyway — same posture as the
	// balancer-wedge ledger in the h2 guard).
	seen state.FirstSeenLedger
}

// NewLinkerdOutlierGuardCheck builds the linkerd-outlier check — its state
// is the emitted-gauge and first-seen ledgers; evict cooldowns ride
// the shared Deps.Heals set.
func NewLinkerdOutlierGuardCheck(d *probefw.Deps) probefw.Check {
	return &linkerdOutlierGuardCheck{Deps: d}
}

const (
	CheckNameLinkerdOutlierGuard = "linkerd-outlier-guard"

	// linkerd-outlier-guard knobs (linkerd-outlier resolved design
	// decision 1 — the cohort-math thresholds are compile-time:
	// they are the false-positive boundary, not tuning knobs).
	linkerdOutlierMinRPS        = 1.0              // condition 1
	linkerdOutlierSiblingMinRPS = 0.5              // condition 2 — a valid control sample
	linkerdOutlierErrRatio      = 0.80             // condition 3
	linkerdOutlierSiblingMedian = 0.05             // condition 4
	linkerdOutlierPersistence   = 5 * time.Minute  // gate 1 — >=2 sweep cycles
	linkerdOutlierPodMinAge     = 10 * time.Minute // gate 1 — startup churn excluded
	linkerdOutlierHealCool      = 30 * time.Minute // gate 3
)

var (
	// linkerd-outlier — a confirmed single-pod gray failure: the pod serves
	// real traffic (>=1 rps inbound) and fails >=80% of it while its
	// same-revision siblings stay healthy (<5% median).
	linkerdOutlierPodsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_outlier_pods",
		Help: "1 while the meshed pod's inbound request error ratio is >=80% at >=1 rps with healthy same-revision siblings — linkerd-outlier gray-failure outlier.",
	}, []string{"namespace", "deployment", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdOutlierPodsGauge)
}

// outlierSample is one deployment-grouped pod rate read — rps or
// the failure-side numerator, depending on which query produced it.
type outlierSample struct {
	ns, deploy, pod string
	value           float64
}

// outlierGroupKey joins the (namespace, deployment) cohort key the
// sibling math groups by — "|" cannot appear in a k8s name.
func outlierGroupKey(ns, deploy string) string { return ns + "|" + deploy }

// outlierPodKey joins the (namespace, deployment, pod) sample key.
func outlierPodKey(ns, deploy, pod string) string {
	return ns + "|" + deploy + "|" + pod
}

// linkerdOutlierSamples flattens one instant-vector query into the
// pod-keyed sample map, dropping series that carry no
// namespace/deployment/pod label (an unlabeled series can never
// join a cohort — linkerd's own control-plane pods and
// non-Deployment workloads read that way).
func linkerdOutlierSamples(series []promq.Sample) map[string]outlierSample {
	out := map[string]outlierSample{}
	for _, s := range series {
		ns, deploy, pod := s.Label("namespace"), s.Label("deployment"), s.Label("pod")
		if ns == "" || deploy == "" || pod == "" {
			continue
		}
		out[outlierPodKey(ns, deploy, pod)] = outlierSample{ns, deploy, pod, s.Value}
	}
	return out
}

// linkerdDeploymentPods returns the live (non-deleting) pods of
// Deployment deploy in ns plus the uniform pod-template-hash
// verdict: a member is a pod whose ReplicaSet owner is named
// deploy+"-"+hash where hash is the pod's own pod-template-hash
// label — the naming shape a Deployment rollout guarantees.
// uniform=false means the members carry >1 distinct hash (rollout
// or canary in flight → no valid control group).
func linkerdDeploymentPods(pods []corev1.Pod, ns, deploy string) (
	members []*corev1.Pod, hash string, uniform bool) {

	hashes := map[string]bool{}
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != ns || pod.DeletionTimestamp != nil {
			continue
		}
		h := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if h == "" {
			continue
		}
		ref := metav1.GetControllerOf(pod)
		if ref == nil || ref.Kind != "ReplicaSet" || ref.Name != deploy+"-"+h {
			continue
		}
		hashes[h] = true
		members = append(members, pod)
	}
	if len(hashes) != 1 {
		return members, "", false
	}
	for h := range hashes {
		hash = h
	}
	return members, hash, true
}

// linkerdPodMember reports whether pod belongs to Deployment deploy
// — the same membership test linkerdDeploymentPods applies:
// ReplicaSet owner named deploy+"-"+<pod-template-hash>.
func linkerdPodMember(pod *corev1.Pod, deploy string) bool {
	h := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
	ref := metav1.GetControllerOf(pod)
	return h != "" && ref != nil && ref.Kind == "ReplicaSet" &&
		ref.Name == deploy+"-"+h
}

// siblingErrRatios collects the error ratios of a candidate's cohort
// siblings — same (ns, deployment) Prom group, excluding the pod
// itself, each carrying >= linkerdOutlierSiblingMinRPS (the control
// samples the median is computed over). ok=false when no sibling
// qualifies — no control group, no verdict.
func siblingErrRatios(group []outlierSample, pod string,
	rps, fails map[string]outlierSample) (errs []float64, ok bool) {

	for _, s := range group {
		if s.pod == pod || s.value < linkerdOutlierSiblingMinRPS {
			continue
		}
		errs = append(errs,
			fails[outlierPodKey(s.ns, s.deploy, s.pod)].value/s.value)
	}
	return errs, len(errs) > 0
}

// medianF64 returns the median of vals (average of the two middle
// elements on even counts) — vals must be non-empty.
func medianF64(vals []float64) float64 {
	sorted := append([]float64{}, vals...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// Run executes the cohort math then the gated evict pass. A
// Prometheus outage is inconclusive, not healthy — the check passes
// with a WARN like every metrics-backed sibling (http-content-check
// owns Prometheus liveness) but the emitted ledger still
// reconciles so a recovered sweep never inherits a phantom series.
func (p *linkerdOutlierGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport
	const why = "linkerd inbound 5xx outlier pods (>=80% err at >=1rps, siblings <5% median): "
	done := func() probefw.Result {
		return rep.Result(&p.emitted, linkerdOutlierPodsGauge.DeleteLabelValues,
			why, ", ")
	}

	if _, err := p.PromEndpoint(); err != nil {
		return done()
	}
	rpsSeries, err := p.PromQuery(ctx,
		`sum by (namespace, deployment, pod) (rate(response_total{direction="inbound"}[5m]))`)
	if err != nil {
		log.Info("WARN: linkerd outlier rps query failed — check inconclusive",
			"error", err)
		return done()
	}
	failSeries, err := p.PromQuery(ctx,
		`sum by (namespace, deployment, pod) (rate(response_total{direction="inbound",classification="failure"}[5m]))`)
	if err != nil {
		log.Info("WARN: linkerd outlier failure-ratio query failed — check inconclusive",
			"error", err)
		return done()
	}
	rps := linkerdOutlierSamples(rpsSeries)
	fails := linkerdOutlierSamples(failSeries)

	// Cohort index: (ns|deploy) -> the group's rps samples.
	groups := map[string][]outlierSample{}
	for _, s := range rps {
		gk := outlierGroupKey(s.ns, s.deploy)
		groups[gk] = append(groups[gk], s)
	}

	// Conditions 1+3 narrow to candidates worth a pod census — the
	// cohort hash check and the evict gates all need k8s truth, and
	// a cluster with no candidates pays zero API reads.
	type cand struct {
		s        outlierSample
		errRatio float64
	}
	var cands []cand
	for _, s := range rps {
		if s.value < linkerdOutlierMinRPS {
			continue
		}
		er := fails[outlierPodKey(s.ns, s.deploy, s.pod)].value / s.value
		if er < linkerdOutlierErrRatio {
			continue
		}
		cands = append(cands, cand{s, er})
	}
	if len(cands) == 0 {
		return done()
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	podByKey := map[string]*corev1.Pod{}
	for i := range pods {
		podByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}
	readyByOwner := probefw.ReadyByOwner(pods)

	live := map[string]bool{}
	for _, c := range cands {
		s := c.s
		// Condition 2a — cohort coherence: every live member of the
		// Deployment must carry ONE pod-template-hash (a mid-rollout
		// or canary cohort has no control group).
		if _, _, uniform := linkerdDeploymentPods(pods, s.ns, s.deploy); !uniform {
			continue
		}
		pod := podByKey[s.ns+"/"+s.pod]
		if pod == nil || pod.DeletionTimestamp != nil ||
			!linkerdPodMember(pod, s.deploy) {
			continue // stale series or hash-mismatched pod — no flag
		}
		// Conditions 2b+4 — >=1 sibling control sample whose median
		// error rate proves the failure is local to this pod.
		errs, ok := siblingErrRatios(groups[outlierGroupKey(s.ns, s.deploy)],
			s.pod, rps, fails)
		if !ok || medianF64(errs) >= linkerdOutlierSiblingMedian {
			continue
		}
		live[s.ns+"/"+s.pod+"/"+string(pod.UID)] = true
		key := s.ns + "/" + s.deploy + "/" + s.pod
		rep.Emit(linkerdOutlierPodsGauge, key,
			[]string{s.ns, s.deploy, s.pod},
			fmt.Sprintf("%s/%s pod=%s err=%.2f rps=%.2f",
				s.ns, s.deploy, s.pod, c.errRatio, s.value))
		p.maybeEvictOutlier(ctx, log, now, s, pod, readyByOwner)
	}
	p.seen.Prune(func(k string) bool { return live[k] })
	return done()
}

// maybeEvictOutlier walks the six gates for one confirmed outlier.
// The detection verdict is already recorded by the caller — this
// only decides whether the pod is recreated.
func (p *linkerdOutlierGuardCheck) maybeEvictOutlier(ctx context.Context,
	log logr.Logger, now time.Time, s outlierSample, pod *corev1.Pod,
	readyByOwner map[types.UID]int) {

	podKey := pod.Namespace + "/" + pod.Name
	// Gate 6 first — detection ran either way; the kill switch only
	// gates the actuation half.
	if !p.Cfg.Linkerd.OutlierEvictEnabled {
		return
	}
	// Gate 1 — persistence + pod age: the signature must hold the
	// full 5m window (>=2 sweep cycles) and the pod must outlive
	// startup churn before it can be called gray-failed.
	if pod.Status.Phase != corev1.PodRunning ||
		now.Sub(pod.CreationTimestamp.Time) < linkerdOutlierPodMinAge {
		return
	}
	if !probefw.Persisted(&p.seen,
		s.ns+"/"+s.pod+"/"+string(pod.UID), now,
		linkerdOutlierPersistence, log) {
		return
	}
	// Gate 2 — a genuinely separate Ready sibling must survive the
	// evict; ReadySiblings discounts the outlier itself when it
	// still reports Ready (the gray failure keeps probes green).
	if probefw.ReadySiblings(readyByOwner, pod) < 1 {
		log.Info("skip outlier evict: no Ready sibling replica — evict would blackhole the workload",
			"pod", podKey)
		return
	}
	// Gates 3+5 — the controller-scoped 30m cooldown, the
	// maintenance mutex and the global heal budget ride one
	// AllowedV call (fail closed: unverifiable counts as held and
	// IncErrors the queue).
	ck := probefw.SelfHealKey(CheckNameLinkerdOutlierGuard,
		kube.PodControllerKey(pod))
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, linkerdOutlierHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	// Gate 4 — the PDB pre-check (every matching PDB must allow a
	// disruption) then the policy/v1 Eviction, which re-enforces the
	// budget atomically server-side; the UID precondition closes the
	// TOCTOU between the census and the kill — a same-named recreate
	// is not ours to evict.
	allowed, err := p.pdbAllows(ctx, pod)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: outlier evict — PDB gate unverifiable (fail closed)",
			"pod", podKey, "error", err)
		return
	}
	if !allowed {
		log.Info("skip outlier evict: matching PDB allows no disruption",
			"pod", podKey)
		return
	}
	deleteOpts := kube.UIDDeleteOptions(pod.UID, "")
	if err := p.CS.CoreV1().Pods(pod.Namespace).EvictV1(ctx,
		&policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
			DeleteOptions: &deleteOpts,
		}); err != nil {
		if apierrors.IsTooManyRequests(err) {
			// HTTP 429 — a PDB with disruptionsAllowed==0 refused
			// between the pre-check and the kill: a deferral, not a
			// failure.
			log.Info("DEFER: PDB refused outlier eviction — keeping pod alive",
				"pod", podKey)
			return
		}
		metrics.IncError(p.Name)
		log.Error(err, "linkerd outlier pod eviction failed", "pod", podKey)
		return
	}
	p.Heals.Stamp(ck, now)
	p.InvalidatePods(ctx) // pod evicted — drop the census
	metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOutlierGuard).Inc()
	log.Info("EVICT: linkerd outlier pod — gray-failed replica recreated",
		"pod", podKey, "deployment", s.deploy)
}

// pdbAllows reports whether every PodDisruptionBudget in the pod's
// namespace selecting it allows at least one disruption — the
// pre-check half of gate 4 (the Eviction subresource stays the
// atomic arbiter). A selector that fails to parse treats as
// matching — unverifiable fails closed.
func (p *linkerdOutlierGuardCheck) pdbAllows(ctx context.Context,
	pod *corev1.Pod) (bool, error) {

	pdbs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PodDisruptionBudgets(p.CS, pod.Namespace))
	if err != nil {
		return false, err
	}
	for i := range pdbs {
		pdb := &pdbs[i]
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			sel = labels.Everything() // unparseable — fail closed
		}
		if !sel.Matches(labels.Set(pod.Labels)) {
			continue
		}
		if pdb.Status.DisruptionsAllowed < 1 {
			return false, nil
		}
	}
	return true, nil
}
