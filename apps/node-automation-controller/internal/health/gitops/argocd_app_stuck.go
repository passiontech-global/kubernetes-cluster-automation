// argocd_app_stuck.go — the argocd-app-stuck check (W10-CP6):
// ArgoCD Applications stuck Progressing or carrying
// ComparisonError/InvalidSpecError conditions get a
// refresh=hard patch; >=2 simultaneous ComparisonErrors
// additionally restart the oldest argocd-repo-server pod.
package gitops

import (
	"context"
	"errors"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// argoCDAppStuckCheck is the ArgoCD stuck-application watchdog with
// repo-server restart heal.
type argoCDAppStuckCheck struct {
	*probefw.Deps

	// seen tracks each stuck signature's first-seen sweep — the
	// persistence clock for health/condition shapes that carry no
	// timestamp of their own; pruned when the signature resolves so
	// a later stall re-arms the window.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
}

// newArgoCDAppStuckCheck builds the W10-CP6 check — its state is the
// seen/emitted ledgers (zero value usable); heal cooldowns ride the
// shared Deps.Heals set.
func NewArgoCDAppStuckCheck(d *probefw.Deps) probefw.Check {
	return &argoCDAppStuckCheck{Deps: d}
}

const (
	CheckNameArgoCDAppStuck = "argocd-app-stuck"

	// W10-CP6 — argocd-app-stuck knobs.
	argocdAppProgressingMinAge = 45 * time.Minute
	argocdConditionMinAge      = 5 * time.Minute
	argocdRefreshCooldown      = 30 * time.Minute
	argocdRepoServerCool       = 30 * time.Minute
	argocdRefreshAnno          = "argocd.argoproj.io/refresh"
)

// argocdAppGVR is the Application CRD the W10-CP6 auditor reads —
// argoproj.io/v1alpha1 (distinct from the argoproj.io/v1beta1
// ArgoCD cluster CR the operator watchdog already scans).
var argocdAppGVR = kube.GVRArgoCDApplication

var (
	// W10-CP6 — ArgoCD Application stuck.
	argoCDAppStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_argocd_app_stuck",
		Help: "1 while the ArgoCD Application reports Progressing >45m or an error condition — W10-CP6.",
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
	if p.Dyn == nil {
		return probefw.Result{Infra: errors.New(
			"no dynamic client — argocd app check unverifiable")}
	}
	now := p.Now()
	apps, err := p.Dyn.Resource(argocdAppGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return probefw.Result{Pass: true} // CRD absent — ArgoCD not installed
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list applications: %w", err)}
	}

	current := map[string][]string{}
	seenKeep := map[string]bool{}
	var stuck []string
	comparisonErrors := 0
	for i := range apps.Items {
		app := &apps.Items[i]
		ns, name := app.GetNamespace(), app.GetName()
		var reasons []string

		health, _ := kube.NestedString(app.Object,
			"status", "health", "status")
		// A Progressing roll-up whose only non-Healthy managed
		// workloads are ones the go-kube-downscaler parked at
		// replicas:0 is sleep, not stuck evidence — the downscaler
		// wakes them on schedule.
		if health == "Progressing" && !p.argocdAppOnlyDownscaled(ctx, app) {
			sig := "prog/" + ns + "/" + name
			seenKeep[sig] = true
			first, _ := p.seen.Observe(sig, now)
			if now.Sub(first) >= argocdAppProgressingMinAge {
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
			// absent/malformed falls back to first-seen.
			age := time.Duration(0)
			known := false
			if !c.LastTransitionTime.IsZero() {
				age = now.Sub(c.LastTransitionTime)
				known = true
			}
			if !known {
				first, _ := p.seen.Observe(sig, now)
				age = now.Sub(first)
			}
			if age < argocdConditionMinAge {
				continue
			}
			if isCmp {
				reasonSet["comparison_error"] = true
				hasComparisonError = true
			} else {
				reasonSet["invalid_spec_error"] = true
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
		lv := []string{ns, name, reason}
		current[ns+"/"+name+"/"+reason] = lv
		argoCDAppStuckGauge.WithLabelValues(lv...).Set(1)
		stuck = append(stuck, fmt.Sprintf("%s/%s(%s)", ns, name, reason))
		p.refreshArgoCDApp(ctx, log, app, now)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	p.emitted.Reconcile(current, argoCDAppStuckGauge.DeleteLabelValues)

	// >=2 simultaneous ComparisonErrors = shared stale repo-server
	// cache — restart the oldest repo-server pod to flush it.
	if comparisonErrors >= 2 {
		p.restartArgoCDRepoServer(ctx, log, now)
	}
	if len(stuck) == 0 {
		return probefw.Result{Pass: true}
	}
	sort.Strings(stuck)
	return probefw.Result{Why: "argocd applications stuck: " + strings.Join(stuck, ", ")}
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
// that is not a Deployment/StatefulSet pinned at replicas:0 with
// downscaler/* annotations counts as real stuck evidence.
func (p *argoCDAppStuckCheck) argocdWorkloadDownscaled(ctx context.Context,
	kind, ns, name string) bool {
	switch kind {
	case "Deployment":
		d, err := p.CS.AppsV1().Deployments(ns).
			Get(ctx, name, metav1.GetOptions{})
		return err == nil &&
			kube.IsIntentionallyDownscaled(d.Annotations, d.Spec.Replicas)
	case "StatefulSet":
		s, err := p.CS.AppsV1().StatefulSets(ns).
			Get(ctx, name, metav1.GetOptions{})
		return err == nil &&
			kube.IsIntentionallyDownscaled(s.Annotations, s.Spec.Replicas)
	}
	return false
}

// refreshArgoCDApp patches argocd.argoproj.io/refresh=hard on a
// stuck Application — 30m per-app cooldown on the shared ledger.
func (p *argoCDAppStuckCheck) refreshArgoCDApp(ctx context.Context,
	log logr.Logger, app *unstructured.Unstructured, now time.Time) {

	ck := "selfheal/" + CheckNameArgoCDAppStuck + "/refresh/" +
		app.GetNamespace() + "/" + app.GetName()
	if p.Heals.CooledDown(ck, argocdRefreshCooldown, now) {
		return
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		argocdRefreshAnno: "hard",
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
	p.DeletePodHeal(ctx, log, CheckNameArgoCDAppStuck,
		"repo-server/"+oldest.Namespace+"/"+oldest.Name,
		oldest, argocdRepoServerCool, now)
}

// oldestRepoServerPod returns the oldest non-terminating
// argocd-repo-server pod cluster-wide. selector=="" is the
// label-less fallback pass that matches on the name prefix plus the
// component label (an install shape where the canonical
// app.kubernetes.io/name label is absent entirely).
func (p *argoCDAppStuckCheck) oldestRepoServerPod(ctx context.Context,
	log logr.Logger, selector string) *corev1.Pod {

	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — repo-server restart deferred",
			"error", err)
		return nil
	}
	var oldest *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
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
