// argocd_app_stuck.go — the argocd-app-stuck check (argocd-app-stuck):
// ArgoCD Applications stuck Progressing or carrying
// ComparisonError/InvalidSpecError conditions get a
// refresh=hard patch; >=2 simultaneous ComparisonErrors
// additionally restart the oldest argocd-repo-server pod.
//
// File layout: this file holds the module contract, the check struct
// and the Run sweep pipeline; argocd_app_stuck_downscaled.go the
// downscaler-excuse verdict over the workload censuses,
// argocd_app_stuck_heal.go the refresh patch and the repo-server
// restart.
package gitops

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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
			probefw.MergeAnnoPatchLocally(ctx, app, data)
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
		for sig := range argoPersistedFirstSeen(ctx, app) {
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
		slices.Sort(reasons)
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
