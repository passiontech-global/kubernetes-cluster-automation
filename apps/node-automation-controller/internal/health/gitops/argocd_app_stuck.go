// argocd_app_stuck.go — the argocd-app-stuck check (argocd-app-stuck):
// ArgoCD Applications stuck Progressing or carrying
// ComparisonError/InvalidSpecError conditions get a
// refresh=hard patch; >=2 simultaneous ComparisonErrors
// additionally restart the oldest argocd-repo-server pod.
package gitops

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// argoCDAppStuckCheck is the ArgoCD stuck-application watchdog with
// repo-server restart heal.
type argoCDAppStuckCheck struct {
	*probefw.Deps

	// seen tracks each stuck signature's first-seen sweep — the
	// persistence clock for health/condition shapes that carry no
	// timestamp of their own. The windows gate remediation (the
	// refresh patch AND the repo-server restart), so the ledger
	// runs the persisted variant: stamps ride the Application as a
	// per-key annotation map (kube.AnnoFirstSeenArgoCDAppStuck — one
	// map holds the "prog/" and every "cond/" key of an app) and a
	// restart resumes them; a resolved signature's key is cleared
	// so a later stall re-arms the window.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
	// downscaledSeen memoizes one sweep's downscale verdicts: an
	// Application's status.resources lists each workload once, but N
	// stuck apps sharing a workload (or one app re-evaluated across
	// signatures) would Get the same Deployment/StatefulSet once per
	// (app, resource) pair — the N+1 Get storm the map collapses to
	// one lookup per distinct workload. Reset at the top of every
	// Run (ownerSeen's shape in api-object-sprawl-report-gc).
	downscaledSeen map[string]bool
	// depIndex/stsIndex are the per-sweep ns/name indexes over the
	// shared Deployment/StatefulSet censuses — without them each
	// distinct workload linear-scanned the full census slice
	// (O(workloads×census) per sweep). Built once on first lookup
	// (the census LIST is already memoized per sweep), reset with
	// downscaledSeen; a census read failure returns nil uncached so
	// later lookups retry rather than poisoning the sweep.
	depIndex map[string]*appsv1.Deployment
	stsIndex map[string]*appsv1.StatefulSet
}

// newArgoCDAppStuckCheck builds the argocd-app-stuck check — its state is the
// seen/emitted ledgers (zero value usable); heal cooldowns ride the
// shared Deps.Heals set.
func NewArgoCDAppStuckCheck(d *probefw.Deps) probefw.Check {
	return &argoCDAppStuckCheck{Deps: d}
}

const (
	CheckNameArgoCDAppStuck = "argocd-app-stuck"

	// argocd-app-stuck — argocd-app-stuck knobs.
	argocdAppProgressingMinAge = 45 * time.Minute
	argocdConditionMinAge      = 5 * time.Minute
	argocdRefreshCooldown      = 30 * time.Minute
	argocdRepoServerCool       = 30 * time.Minute
	argocdRefreshAnno          = "argocd.argoproj.io/refresh"
	// argoCDRefreshHealAnno persists the last refresh=hard moment on
	// the Application — the durable half of the 30m refresh cooldown
	// (single-writer stamp, kept local like argocdRefreshAnno).
	argoCDRefreshHealAnno = "passiontech.dev/last-argocd-app-refresh"
)

// argoCDAppGVR is the Application CRD the argocd-app-stuck auditor reads —
// argoproj.io/v1alpha1 (distinct from the argoproj.io/v1beta1
// ArgoCD cluster CR the operator watchdog already scans).
var argocdAppGVR = kube.GVRArgoCDApplication

// rolloutZeroReplicas backs the rollout-scale-flap Rollout branch of
// argocdWorkloadDownscaled: unstructured Rollouts carry no typed
// *int32, so the zero-replica check needs a shared zero.
var rolloutZeroReplicas = int32(0)

var (
	// argocd-app-stuck — ArgoCD Application stuck.
	argoCDAppStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_argocd_app_stuck",
		Help: "1 while the ArgoCD Application reports Progressing >45m or an error condition — argocd-app-stuck.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		argoCDAppStuckGauge)
}

// checkArgoCDAppStuck audits ArgoCD Applications for the two stuck
// shapes: status.health.status=="Progressing" persisting >45m
// (first-seen ledger — health carries no transition timestamp), and
// status.conditions of type ComparisonError / InvalidSpecError
// (aged by lastTransitionTime, 5m floor). Each stuck app gets a
// argocd.argoproj.io/refresh=hard patch on a 30m cooldown; >=2
// simultaneous ComparisonErrors additionally restart the oldest
// argocd-repo-server pod — the shared stale-cache signature. A
// Progressing app whose every non-Healthy managed workload is
// intentionally downscaled (replicas:0 + downscaler/* annotations)
// is excused — sleep is not stuck evidence. An absent Application
// CRD is a clean pass (ArgoCD not installed).
func (p *argoCDAppStuckCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	if r := p.RequireDyn("argocd app check"); r != nil {
		return *r
	}
	now := p.Now()
	apps, err := p.AllUnstructured(ctx, argocdAppGVR)
	crdAbsent := apierrors.IsNotFound(err) || meta.IsNoMatchError(err)
	switch {
	case crdAbsent:
		// CRD absent — ArgoCD not installed. The sweep IS complete
		// (no Application can exist), so the ledgers still close out
		// below: seen keys and emitted series held from when ArgoCD
		// existed are resolved state now — returning early would
		// leak them pinned forever.
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list applications: %w", err)}
	}

	seenKeep := map[string]bool{}
	var rep probefw.SweepReport
	comparisonErrors := 0
	p.downscaledSeen = map[string]bool{} // per-sweep memo, reset each Run
	p.depIndex, p.stsIndex = nil, nil    // census indexes rebuilt lazily
	for i := range apps {
		app := &apps[i]
		ns, name := app.GetNamespace(), app.GetName()
		var reasons []string

		// patchApp is the durable-write half every persisted
		// first-seen call on this Application shares — several
		// signatures stamp/clear keys in the same per-object
		// annotation map per sweep, and the LISTED copy is stale
		// the moment the first write lands: mirroring each patch
		// into app keeps later reads current, or a second write
		// would drop a sibling key the earlier one just set (an
		// intra-sweep lost update the serial sweep otherwise
		// cannot see).
		patchApp := func(ctx context.Context, data []byte) error {
			if _, err := p.Dyn.Resource(argocdAppGVR).
				Namespace(ns).Patch(ctx, name, types.MergePatchType,
				data, metav1.PatchOptions{}); err != nil {
				return err
			}
			probefw.MergeAnnoPatchLocally(app, data)
			return nil
		}

		health, _ := kube.NestedString(app.Object,
			"status", "health", "status")
		// A Progressing roll-up whose only non-Healthy managed
		// workloads are ones the go-kube-downscaler parked at
		// replicas:0 is sleep, not stuck evidence — the downscaler
		// wakes them on schedule. The window gates the refresh
		// patch, so the first-seen rides the Application as a
		// durable annotation (wider of ledger vs annotation).
		if health == "Progressing" && !p.argocdAppOnlyDownscaled(ctx, app) {
			sig := "prog/" + ns + "/" + name
			seenKeep[sig] = true
			if heal.FirstSeenPersisted(ctx, log, &p.seen, app,
				kube.AnnoFirstSeenArgoCDAppStuck, sig,
				argocdAppProgressingMinAge, now, patchApp) {
				reasons = append(reasons,
					fmt.Sprintf("progressing>%s", argocdAppProgressingMinAge))
			}
		}
		reasonSet := map[string]bool{}
		hasComparisonError := false
		for _, c := range kube.Conditions(app.Object, "status", "conditions") {
			typ := c.Type
			lower := strings.ToLower(typ)
			isCmp := strings.Contains(lower, "comparisonerror")
			isInvalid := strings.Contains(lower, "invalidspecerror")
			// ArgoCD ApplicationCondition has NO status field —
			// presence in status.conditions IS the active signal.
			if !isCmp && !isInvalid {
				continue
			}
			sig := "cond/" + ns + "/" + name + "/" + typ
			seenKeep[sig] = true
			// lastTransitionTime is the condition's own clock;
			// absent/malformed falls back to the persisted
			// first-seen window — inside it the signature doesn't
			// count yet.
			if c.LastTransitionTime.IsZero() {
				if !heal.FirstSeenPersisted(ctx, log, &p.seen, app,
					kube.AnnoFirstSeenArgoCDAppStuck, sig,
					argocdConditionMinAge, now, patchApp) {
					continue
				}
			} else if now.Sub(c.LastTransitionTime) < argocdConditionMinAge {
				continue
			}
			if isCmp {
				reasonSet["comparison_error"] = true
				hasComparisonError = true
			} else {
				reasonSet["invalid_spec_error"] = true
			}
		}
		// Resolution clears — every first-seen key persisted on
		// this Application whose signature did NOT evaluate live
		// this sweep is resolved: health left Progressing (or the
		// downscaler excuse now applies), or a condition type
		// dropped out of status.conditions entirely (absent = the
		// only "resolved" a status-less ApplicationCondition can
		// show). Clearing drops the key from BOTH clocks so a
		// recurrence re-arms the full window — a stale stamp would
		// fast-trip it (premature remediation). Tolerated
		// sub-failure: Warn + continue, retry next sweep.
		for sig := range argoPersistedFirstSeen(app) {
			if seenKeep[sig] {
				continue
			}
			if err := heal.ClearPersistedFirstSeen(ctx, log,
				&p.seen, app, kube.AnnoFirstSeenArgoCDAppStuck,
				sig, patchApp); err != nil {
				log.Info("WARN: persisted first-seen clear failed — "+
					"a stale stamp could fast-trip the next stall",
					"application", ns+"/"+name, "key", sig, "error", err)
			}
		}
		for r := range reasonSet {
			reasons = append(reasons, r)
		}
		if hasComparisonError {
			comparisonErrors++ // count APPS, not conditions
		}
		if len(reasons) == 0 {
			continue
		}
		sort.Strings(reasons)
		reason := strings.Join(reasons, "+")
		rep.Emit(argoCDAppStuckGauge, ns+"/"+name+"/"+reason,
			[]string{ns, name, reason},
			fmt.Sprintf("%s/%s(%s)", ns, name, reason))
		p.refreshArgoCDApp(ctx, log, app, now)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	rep.Close(&p.emitted, argoCDAppStuckGauge.DeleteLabelValues)

	// >=2 simultaneous ComparisonErrors = shared stale repo-server
	// cache — restart the oldest repo-server pod to flush it.
	if comparisonErrors >= 2 {
		p.restartArgoCDRepoServer(ctx, log, now)
	}
	return rep.Verdict("argocd applications stuck: ", ", ")
}

// argocdAppOnlyDownscaled reports whether every non-Healthy entry
// in the Application's status.resources resolves to a live
// Deployment/StatefulSet the go-kube-downscaler intentionally
// parked at replicas:0 (kube.IsIntentionallyDownscaled). Fails
// closed on any other non-Healthy resource, an unreadable workload
// or NO non-Healthy resources at all — the Progressing signature
// then stands and the first-seen window decides as before.
func (p *argoCDAppStuckCheck) argocdAppOnlyDownscaled(ctx context.Context,
	app *unstructured.Unstructured) bool {
	res, found := kube.NestedSlice(app.Object, "status", "resources")
	if !found {
		return false
	}
	unhealthy := 0
	for _, r := range res {
		m, ok := r.(map[string]any)
		if !ok {
			return false
		}
		hs, _ := kube.NestedString(m, "health", "status")
		if hs == "" || hs == "Healthy" {
			continue
		}
		unhealthy++
		kind, _ := kube.NestedString(m, "kind")
		name, _ := kube.NestedString(m, "name")
		rns, _ := kube.NestedString(m, "namespace")
		if rns == "" {
			rns = app.GetNamespace() // app-namespace resource
		}
		if !p.argocdWorkloadDownscaled(ctx, kind, rns, name) {
			return false
		}
	}
	return unhealthy > 0
}

// argocdWorkloadDownscaled resolves one Application resource-tree
// entry to its live workload and asks the shared verdict — anything
// that is not a Deployment/StatefulSet/Rollout pinned at replicas:0
// with downscaler/* annotations counts as real stuck evidence. Verdicts
// memoize per sweep on downscaledSeen (kind/ns/name → verdict) so a
// workload shared by several Applications pays one Get, not one per
// app; the memo never changes a verdict, only its lookup count.
func (p *argoCDAppStuckCheck) argocdWorkloadDownscaled(ctx context.Context,
	kind, ns, name string) bool {
	key := kind + "/" + ns + "/" + name
	if v, memo := p.downscaledSeen[key]; memo {
		return v // same workload already resolved this sweep
	}
	var v bool
	switch kind {
	case "Deployment":
		v = p.deploymentDownscaled(ctx, ns, name)
	case "StatefulSet":
		v = p.statefulSetDownscaled(ctx, ns, name)
	case "Rollout":
		// rollout-scale-flap — Argo Rollouts workloads in the Application's
		// resource tree carry the same downscaled semantics: a
		// Rollout parked at spec.replicas:0 with downscaler/*
		// annotations is sleep, not stuck evidence. Rollouts are
		// unstructured CRs — read replicas off the unstructured spec.
		// The lookup rides the per-sweep unstructured snapshot — one
		// paged cluster LIST memoized per GVR, filtered client-side
		// to ns/name (the raw NotFound/NoMatch census error means no
		// Rollout CRD or failed read: fail closed, not downscaled).
		ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
		if err != nil {
			v = false
			break
		}
		var r *unstructured.Unstructured
		for i := range ros {
			if ros[i].GetNamespace() == ns && ros[i].GetName() == name {
				r = &ros[i]
				break
			}
		}
		if r == nil {
			v = false
			break
		}
		replicas, found, err := unstructured.NestedInt64(r.Object, "spec", "replicas")
		v = err == nil && found && replicas == 0 &&
			kube.IsIntentionallyDownscaled(r.GetAnnotations(), &rolloutZeroReplicas)
	}
	if p.downscaledSeen == nil {
		p.downscaledSeen = map[string]bool{} // lazy init — Run seeds it
	}
	p.downscaledSeen[key] = v
	return v
}

// deploymentIndex builds (once per sweep) the ns/name index over the
// shared Deployment census — AllDeployments already memoizes the
// cluster-wide LIST, so the map turns each distinct workload lookup
// O(1) instead of a full-slice scan. A census read failure returns
// nil UNCACHED: the next lookup retries the read rather than pinning
// a poisoned empty index for the whole sweep.
func (p *argoCDAppStuckCheck) deploymentIndex(
	ctx context.Context) map[string]*appsv1.Deployment {
	if p.depIndex != nil {
		return p.depIndex
	}
	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return nil
	}
	idx := make(map[string]*appsv1.Deployment, len(deps))
	for i := range deps {
		idx[deps[i].Namespace+"/"+deps[i].Name] = &deps[i]
	}
	p.depIndex = idx
	return idx
}

// statefulSetIndex is deploymentIndex's StatefulSet twin.
func (p *argoCDAppStuckCheck) statefulSetIndex(
	ctx context.Context) map[string]*appsv1.StatefulSet {
	if p.stsIndex != nil {
		return p.stsIndex
	}
	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		return nil
	}
	idx := make(map[string]*appsv1.StatefulSet, len(stss))
	for i := range stss {
		idx[stss[i].Namespace+"/"+stss[i].Name] = &stss[i]
	}
	p.stsIndex = idx
	return idx
}

// deploymentDownscaled resolves one workload against the sweep's
// shared Deployment census — via the per-sweep ns/name index (one
// LIST, O(1) per distinct workload). Absent (or unreadable) reads
// false: not proven downscaled is stuck evidence, the fail-closed
// posture.
func (p *argoCDAppStuckCheck) deploymentDownscaled(ctx context.Context,
	ns, name string) bool {

	idx := p.deploymentIndex(ctx)
	if idx == nil {
		return false
	}
	dep, ok := idx[ns+"/"+name]
	if !ok {
		return false
	}
	return kube.IsIntentionallyDownscaled(dep.Annotations, dep.Spec.Replicas)
}

// statefulSetDownscaled is the StatefulSet twin over the shared
// per-sweep census index.
func (p *argoCDAppStuckCheck) statefulSetDownscaled(ctx context.Context,
	ns, name string) bool {

	idx := p.statefulSetIndex(ctx)
	if idx == nil {
		return false
	}
	sts, ok := idx[ns+"/"+name]
	if !ok {
		return false
	}
	return kube.IsIntentionallyDownscaled(sts.Annotations, sts.Spec.Replicas)
}

// refreshArgoCDApp patches argocd.argoproj.io/refresh=hard on a
// stuck Application — the shared heal preamble gates it like every
// other heal (Deps.HealAllowedPersisted → heal.AllowedVPersisted):
// the 30m per-app cooldown is the wider of the in-RAM ledger and the
// passiontech.dev/last-argocd-app-refresh stamp persisted on the
// Application itself (a restart re-firing refresh=hard for every
// stuck app is the churn the persisted half exists to stop), then
// the maintenance mutex + global heal budget (a refresh patch during
// a drain re-triggers reconciliation churn exactly like a pod delete;
// "cannot verify" fails closed). The cooldown stamp rides the SAME
// merge patch as the refresh annotation — kube.MergePatchAnnos is
// RFC 7386, so sibling annotation keys survive, and one write lands
// the heal and its persisted cooldown together. ArgoCD consumes the
// refresh key once processed; the last-* stamp stays.
func (p *argoCDAppStuckCheck) refreshArgoCDApp(ctx context.Context,
	log logr.Logger, app *unstructured.Unstructured, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameArgoCDAppStuck,
		"refresh/"+app.GetNamespace()+"/"+app.GetName())
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log, &p.Heals,
		app, argoCDRefreshHealAnno, ck, argocdRefreshCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		argocdRefreshAnno:     "hard",
		argoCDRefreshHealAnno: now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Error(err, "marshal argocd refresh patch failed",
			"application", app.GetNamespace()+"/"+app.GetName())
		return
	}
	if _, err := p.Dyn.Resource(argocdAppGVR).
		Namespace(app.GetNamespace()).Patch(ctx, app.GetName(),
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Error(err, "argocd refresh patch failed",
			"application", app.GetNamespace()+"/"+app.GetName())
		return
	}
	p.Heals.Stamp(ck, now)
	log.Info("PATCH: argocd application refresh=hard",
		"application", app.GetNamespace()+"/"+app.GetName())
}

// argoPersistedFirstSeen returns the first-seen keys persisted on
// this Application — the annotation map is per-object, so every
// entry is one of this app's signatures. Absent/unparseable reads
// as empty (same "unparseable = absent" posture as
// kube.ParseAnnoTime); the in-RAM half needs no enumeration —
// p.seen.Prune drops non-live keys at sweep end.
func argoPersistedFirstSeen(app *unstructured.Unstructured) map[string]bool {
	sigs := map[string]bool{}
	raw := app.GetAnnotations()[kube.AnnoFirstSeenArgoCDAppStuck]
	if raw == "" {
		return sigs
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return sigs
	}
	for k := range m {
		sigs[k] = true
	}
	return sigs
}

// restartArgoCDRepoServer deletes the OLDEST argocd-repo-server
// pod — repo-server caches repo state; >=2 ComparisonErrors at once
// is the stale-cache signature and one restart flushes it. The
// primary list filters server-side on the operator's canonical
// app.kubernetes.io/name label; a repo-server pod missing the label
// can never reach that list, so an empty result re-lists
// unfiltered and matches the argocd-repo-server- name prefix (the
// helm-vs-operator label drift fallback).
func (p *argoCDAppStuckCheck) restartArgoCDRepoServer(ctx context.Context,
	log logr.Logger, now time.Time) {

	oldest := p.oldestRepoServerPod(ctx, log,
		"app.kubernetes.io/name=argocd-repo-server")
	if oldest == nil {
		oldest = p.oldestRepoServerPod(ctx, log, "")
	}
	if oldest == nil {
		log.Info("argocd repo-server restart requested but no repo-server pod found")
		return
	}
	// Only a controller-owned pod is restartable — the owner
	// recreates it. A lone, controller-less pod would be deleted
	// PERMANENTLY (repo-server gone until manual redeploy), so the
	// heal skips it.
	if metav1.GetControllerOf(oldest) == nil {
		log.Info("SKIP: repo-server pod has no controller owner — delete would not be recreated",
			"pod", oldest.Namespace+"/"+oldest.Name)
		return
	}
	// The heal cooldown keys on the pod's controller so the
	// replacement pod the restart spawns inherits the 30m window
	// instead of re-arming it under a fresh pod name
	// (kube.PodControllerKey).
	p.DeletePodHeal(ctx, log, CheckNameArgoCDAppStuck,
		kube.PodControllerKey(oldest), oldest, argocdRepoServerCool, now)
}

// oldestRepoServerPod returns the oldest non-terminating
// argocd-repo-server pod cluster-wide. selector=="" is the
// label-less fallback pass that matches on the name prefix plus the
// component label (an install shape where the canonical
// app.kubernetes.io/name label is absent entirely).
func (p *argoCDAppStuckCheck) oldestRepoServerPod(ctx context.Context,
	log logr.Logger, selector string) *corev1.Pod {

	pods, err := p.PodsMatching(ctx, metav1.NamespaceAll, selector)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — repo-server restart deferred",
			"error", err)
		return nil
	}
	var oldest *corev1.Pod
	for i := range pods {
		pod := pods[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		// A non-Running repo-server pod (Pending/PodInitializing or
		// a phase-stuck remnant) has no cache to flush — restarting
		// it spends the heal on a pod that cannot hold stale repo
		// state.
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if selector == "" &&
			pod.Labels["app.kubernetes.io/name"] != "argocd-repo-server" &&
			pod.Labels["app.kubernetes.io/component"] != "repo-server" &&
			!strings.HasPrefix(pod.Name, "argocd-repo-server-") {
			continue
		}
		if oldest == nil ||
			pod.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = pod
		}
	}
	return oldest
}
