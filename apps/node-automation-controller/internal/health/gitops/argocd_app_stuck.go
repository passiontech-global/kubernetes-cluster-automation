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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// argoCDAppStuckCheck is the ArgoCD stuck-application watchdog with
// repo-server restart heal.
type argoCDAppStuckCheck struct {
	*probefw.Deps

	// seen tracks each stuck signature's first-seen sweep — the
	// persistence clock for health/condition shapes that carry no
	// timestamp of their own; pruned when the signature resolves so
	// a later stall re-arms the window.
	seen shared.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted shared.GaugeLedger[string]
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
var argocdAppGVR = shared.GVRArgoCDApplication

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
// argocd-repo-server pod — the shared stale-cache signature. An
// absent Application CRD is a clean pass (ArgoCD not installed).
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

		health, _ := shared.NestedString(app.Object,
			"status", "health", "status")
		if health == "Progressing" {
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
		for _, c := range shared.Conditions(app.Object, "status", "conditions") {
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

// refreshArgoCDApp patches argocd.argoproj.io/refresh=hard on a
// stuck Application — 30m per-app cooldown on the shared ledger.
func (p *argoCDAppStuckCheck) refreshArgoCDApp(ctx context.Context,
	log logr.Logger, app *unstructured.Unstructured, now time.Time) {

	ck := "selfheal/" + CheckNameArgoCDAppStuck + "/refresh/" +
		app.GetNamespace() + "/" + app.GetName()
	if p.Heals.CooledDown(ck, argocdRefreshCooldown, now) {
		return
	}
	payload := []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"hard"}}}`, argocdRefreshAnno))
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
// is the stale-cache signature and one restart flushes it. Matched
// by the argocd-operator label scheme (app.kubernetes.io/name or
// component) with a name-prefix fallback.
func (p *argoCDAppStuckCheck) restartArgoCDRepoServer(ctx context.Context,
	log logr.Logger, now time.Time) {

	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: list pods failed — repo-server restart deferred",
			"error", err)
		return
	}
	var oldest *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Labels["app.kubernetes.io/name"] != "argocd-repo-server" &&
			pod.Labels["app.kubernetes.io/component"] != "repo-server" &&
			!strings.HasPrefix(pod.Name, "argocd-repo-server-") {
			continue
		}
		if oldest == nil ||
			pod.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = pod
		}
	}
	if oldest == nil {
		log.Info("argocd repo-server restart requested but no repo-server pod found")
		return
	}
	p.DeletePodHeal(ctx, log, CheckNameArgoCDAppStuck,
		"repo-server/"+oldest.Namespace+"/"+oldest.Name,
		oldest, argocdRepoServerCool, now)
}
