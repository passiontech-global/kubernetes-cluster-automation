// k8s_upgrade_gang_guard.go — health check "k8s-upgrade-gang-guard":
// detect-only pre-upgrade and gang-scheduling guard detecting:
//  1. Live Pods or Workloads (Deployment/StatefulSet/DaemonSet/CronJob)
//     declaring deprecated/removed Kubernetes 1.36 spec.volumes[].gitRepo
//     ("deprecated_gitrepo_volume").
//  2. Gang Scheduling PodGroups (scheduling.k8s.io/v1alpha2 or v1alpha1) or
//     Kueue Workloads (kueue.x-k8s.io/v1beta1) stuck in PreEnqueue or
//     Inadmissible for >= 15m (skipping cleanly on 404/CRD-absent or 403).
//
// Emits node_automation_k8s_upgrade_gang_issue{namespace,kind,name,reason}
// and cooldown-deduped Warning Events (K8sUpgradeGangIssue).
package watchdogs

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameK8sUpgradeGangGuard is the registry check name for k8s-upgrade-gang-guard.
	CheckNameK8sUpgradeGangGuard = "k8s-upgrade-gang-guard"

	gangStuckMinAge           = 15 * time.Minute
	upgradeGangEventCooldown  = 30 * time.Minute
	upgradeGangMaxEventsSweep = 20
	upgradeGangEventReason    = "K8sUpgradeGangIssue"
	reasonDeprecatedGitRepo   = "deprecated_gitrepo_volume"
	reasonGangPodGroupStuck   = "gang_podgroup_stuck"
	reasonKueueWorkloadStuck  = "kueue_workload_stuck"
)

var (
	gvrPodGroupV1Alpha2 = schema.GroupVersionResource{Group: "scheduling.k8s.io", Version: "v1alpha2", Resource: "podgroups"}
	gvrPodGroupV1Alpha1 = schema.GroupVersionResource{Group: "scheduling.k8s.io", Version: "v1alpha1", Resource: "podgroups"}
	podGroupGVRs        = []schema.GroupVersionResource{gvrPodGroupV1Alpha2, gvrPodGroupV1Alpha1}
	gvrKueueWorkload    = schema.GroupVersionResource{Group: "kueue.x-k8s.io", Version: "v1beta1", Resource: "workloads"}
)

var k8sUpgradeGangIssueGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_k8s_upgrade_gang_issue",
	Help: "1 while a Pod/Workload declares deprecated gitRepo volumes or a PodGroup/Kueue Workload is stuck PreEnqueue/Inadmissible >=15m.",
}, []string{"namespace", "kind", "name", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(k8sUpgradeGangIssueGauge)
}

type k8sUpgradeGangGuardCheck struct {
	*probefw.Deps

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewK8sUpgradeGangGuardCheck constructs the k8s-upgrade-gang-guard check.
func NewK8sUpgradeGangGuardCheck(d *probefw.Deps) probefw.Check {
	return &k8sUpgradeGangGuardCheck{Deps: d}
}

type upgradeGangFinding struct {
	apiVersion string
	kind       string
	ns         string
	name       string
	uid        types.UID
	reason     string
	detail     string
}

func (c *k8sUpgradeGangGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, upgradeGangEventCooldown)

	var rep probefw.SweepReport
	var findings []upgradeGangFinding

	gitFindings, err := c.scanDeprecatedGitRepo(ctx)
	if err != nil {
		return probefw.Result{Infra: err}
	}
	findings = append(findings, gitFindings...)

	liveFirstSeen := map[string]bool{}
	if c.Dyn != nil {
		pgFindings, pgErr := c.scanPodGroups(ctx, log, now, liveFirstSeen)
		if pgErr != nil {
			rep.InfraErr(pgErr)
		}
		findings = append(findings, pgFindings...)

		kwFindings, kwErr := c.scanKueueWorkloads(ctx, log, now, liveFirstSeen)
		if kwErr != nil {
			rep.InfraErr(kwErr)
		}
		findings = append(findings, kwFindings...)
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b upgradeGangFinding) int {
		if x := cmp.Compare(a.ns, b.ns); x != 0 {
			return x
		}
		if x := cmp.Compare(a.kind, b.kind); x != 0 {
			return x
		}
		if x := cmp.Compare(a.name, b.name); x != 0 {
			return x
		}
		return cmp.Compare(a.reason, b.reason)
	})

	for _, f := range findings {
		tupleKey := f.ns + "/" + f.kind + "/" + f.name + "/" + f.reason
		rep.Emit(k8sUpgradeGangIssueGauge, tupleKey,
			[]string{f.ns, f.kind, f.name, f.reason},
			fmt.Sprintf("%s/%s/%s (%s)", f.ns, f.kind, f.name, f.reason))
	}

	c.emitEvents(ctx, log, now, findings)

	return rep.Result(&c.emitted, k8sUpgradeGangIssueGauge.DeleteLabelValues,
		"k8s upgrade/gang issue: ", ", ")
}

func (c *k8sUpgradeGangGuardCheck) scanDeprecatedGitRepo(ctx context.Context) ([]upgradeGangFinding, error) {
	var out []upgradeGangFinding

	pods, err := c.AllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if hasGitRepoVolume(pod.Spec.Volumes) {
			out = append(out, upgradeGangFinding{
				apiVersion: "v1",
				kind:       "Pod",
				ns:         pod.Namespace,
				name:       pod.Name,
				uid:        pod.UID,
				reason:     reasonDeprecatedGitRepo,
				detail:     fmt.Sprintf("Pod %s/%s declares deprecated/removed spec.volumes[].gitRepo", pod.Namespace, pod.Name),
			})
		}
	}

	deps, err := c.AllDeployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deps {
		d := &deps[i]
		if d.DeletionTimestamp == nil && hasGitRepoVolume(d.Spec.Template.Spec.Volumes) {
			out = append(out, upgradeGangFinding{
				apiVersion: "apps/v1",
				kind:       "Deployment",
				ns:         d.Namespace,
				name:       d.Name,
				uid:        d.UID,
				reason:     reasonDeprecatedGitRepo,
				detail:     fmt.Sprintf("Deployment %s/%s declares deprecated/removed spec.volumes[].gitRepo", d.Namespace, d.Name),
			})
		}
	}

	stsList, err := c.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range stsList {
		s := &stsList[i]
		if s.DeletionTimestamp == nil && hasGitRepoVolume(s.Spec.Template.Spec.Volumes) {
			out = append(out, upgradeGangFinding{
				apiVersion: "apps/v1",
				kind:       "StatefulSet",
				ns:         s.Namespace,
				name:       s.Name,
				uid:        s.UID,
				reason:     reasonDeprecatedGitRepo,
				detail:     fmt.Sprintf("StatefulSet %s/%s declares deprecated/removed spec.volumes[].gitRepo", s.Namespace, s.Name),
			})
		}
	}

	dsList, err := c.AllDaemonSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range dsList {
		ds := &dsList[i]
		if ds.DeletionTimestamp == nil && hasGitRepoVolume(ds.Spec.Template.Spec.Volumes) {
			out = append(out, upgradeGangFinding{
				apiVersion: "apps/v1",
				kind:       "DaemonSet",
				ns:         ds.Namespace,
				name:       ds.Name,
				uid:        ds.UID,
				reason:     reasonDeprecatedGitRepo,
				detail:     fmt.Sprintf("DaemonSet %s/%s declares deprecated/removed spec.volumes[].gitRepo", ds.Namespace, ds.Name),
			})
		}
	}

	cjList, err := c.AllCronJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cronjobs: %w", err)
	}
	for i := range cjList {
		cj := &cjList[i]
		if cj.DeletionTimestamp == nil && hasGitRepoVolume(cj.Spec.JobTemplate.Spec.Template.Spec.Volumes) {
			out = append(out, upgradeGangFinding{
				apiVersion: "batch/v1",
				kind:       "CronJob",
				ns:         cj.Namespace,
				name:       cj.Name,
				uid:        cj.UID,
				reason:     reasonDeprecatedGitRepo,
				detail:     fmt.Sprintf("CronJob %s/%s declares deprecated/removed spec.volumes[].gitRepo", cj.Namespace, cj.Name),
			})
		}
	}

	return out, nil
}

func hasGitRepoVolume(volumes []corev1.Volume) bool {
	for i := range volumes {
		if volumes[i].GitRepo != nil {
			return true
		}
	}
	return false
}

func (c *k8sUpgradeGangGuardCheck) scanPodGroups(ctx context.Context, log logr.Logger, now time.Time, liveFirstSeen map[string]bool) ([]upgradeGangFinding, error) {
	items, gvr, err := kube.ListFirstGVR(ctx, podGroupGVRs, func(lctx context.Context, g schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
		return c.safeAllUnstructured(lctx, g)
	})
	if err != nil {
		if kube.IsCRDAbsent(err) || apierrors.IsForbidden(err) {
			log.V(1).Info("PodGroup list skipped", "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("list podgroups: %w", err)
	}

	apiVersion := gvr.Group + "/" + gvr.Version
	var out []upgradeGangFinding
	for i := range items {
		u := &items[i]
		if u.GetDeletionTimestamp() != nil {
			continue
		}
		stuck, since, detail := isPodGroupStuck(u)
		if !stuck {
			continue
		}
		if !c.gangAgedAtLeast(since, u, "podgroup", now, liveFirstSeen, log) {
			continue
		}
		out = append(out, upgradeGangFinding{
			apiVersion: apiVersion,
			kind:       "PodGroup",
			ns:         u.GetNamespace(),
			name:       u.GetName(),
			uid:        u.GetUID(),
			reason:     reasonGangPodGroupStuck,
			detail:     fmt.Sprintf("PodGroup %s/%s stuck >=%s (%s)", u.GetNamespace(), u.GetName(), gangStuckMinAge, detail),
		})
	}
	return out, nil
}

func (c *k8sUpgradeGangGuardCheck) scanKueueWorkloads(ctx context.Context, log logr.Logger, now time.Time, liveFirstSeen map[string]bool) ([]upgradeGangFinding, error) {
	items, err := c.safeAllUnstructured(ctx, gvrKueueWorkload)
	if err != nil {
		if kube.IsCRDAbsent(err) || apierrors.IsForbidden(err) {
			log.V(1).Info("Kueue Workload list skipped", "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("list kueue workloads: %w", err)
	}

	var out []upgradeGangFinding
	for i := range items {
		u := &items[i]
		if u.GetDeletionTimestamp() != nil {
			continue
		}
		stuck, since, detail := isKueueWorkloadStuck(u)
		if !stuck {
			continue
		}
		if !c.gangAgedAtLeast(since, u, "kueue", now, liveFirstSeen, log) {
			continue
		}
		out = append(out, upgradeGangFinding{
			apiVersion: gvrKueueWorkload.Group + "/" + gvrKueueWorkload.Version,
			kind:       "Workload",
			ns:         u.GetNamespace(),
			name:       u.GetName(),
			uid:        u.GetUID(),
			reason:     reasonKueueWorkloadStuck,
			detail:     fmt.Sprintf("Kueue Workload %s/%s stuck >=%s (%s)", u.GetNamespace(), u.GetName(), gangStuckMinAge, detail),
		})
	}
	return out, nil
}

// safeAllUnstructured wraps c.AllUnstructured so fake dynamic clients that panic
// on unregistered GVRs map cleanly to NotFound (kube.IsCRDAbsent). Production
// dynamic clients never panic and return real 404/NoMatch/403/5xx errors.
func (c *k8sUpgradeGangGuardCheck) safeAllUnstructured(ctx context.Context, gvr schema.GroupVersionResource) (items []unstructured.Unstructured, err error) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprint(r)
			if strings.Contains(msg, "register") || strings.Contains(msg, "not found") {
				items = nil
				err = apierrors.NewNotFound(schema.GroupResource{Group: gvr.Group, Resource: gvr.Resource}, "")
				return
			}
			panic(r)
		}
	}()
	return c.AllUnstructured(ctx, gvr)
}

func (c *k8sUpgradeGangGuardCheck) gangAgedAtLeast(since time.Time, u *unstructured.Unstructured, prefix string, now time.Time, liveFirstSeen map[string]bool, log logr.Logger) bool {
	if since.IsZero() {
		since = u.GetCreationTimestamp().Time
	}
	if !since.IsZero() {
		return kube.AgeAtLeast(since, now, gangStuckMinAge)
	}
	fsKey := prefix + "/" + u.GetNamespace() + "/" + u.GetName() + "/" + string(u.GetUID())
	liveFirstSeen[fsKey] = true
	return probefw.Persisted(&c.firstSeen, fsKey, now, gangStuckMinAge, log)
}

func isPodGroupStuck(u *unstructured.Unstructured) (bool, time.Time, string) {
	phase, _ := kube.NestedString(u.Object, "status", "phase")
	var stuck bool
	var since time.Time
	var detail string

	kube.ForEachCondition(u.Object, func(cond kube.Condition) bool {
		switch {
		case (cond.Type == "PreEnqueue" || cond.Type == "Inadmissible") && strings.EqualFold(cond.Status, "True"):
			stuck = true
			since = cond.LastTransitionTime
			detail = cmp.Or(cond.Reason, cond.Type)
			return false
		case (cond.Type == "PodGroupScheduled" || cond.Type == "Scheduled") && strings.EqualFold(cond.Status, "False") &&
			(cond.Reason == "PreEnqueue" || cond.Reason == "Inadmissible" || cond.Reason == "Unschedulable"):
			stuck = true
			since = cond.LastTransitionTime
			detail = cond.Reason
			return false
		}
		return true
	}, "status", "conditions")

	if stuck {
		return true, since, detail
	}
	if phase == "PreEnqueue" || phase == "Inadmissible" {
		return true, time.Time{}, phase
	}
	return false, time.Time{}, ""
}

func isKueueWorkloadStuck(u *unstructured.Unstructured) (bool, time.Time, string) {
	var finished, stuck bool
	var since time.Time
	var detail string

	kube.ForEachCondition(u.Object, func(cond kube.Condition) bool {
		if cond.Type == "Finished" && strings.EqualFold(cond.Status, "True") {
			finished = true
			return false
		}
		switch {
		case (cond.Type == "PreEnqueue" || cond.Type == "Inadmissible") && strings.EqualFold(cond.Status, "True"):
			stuck = true
			since = cond.LastTransitionTime
			detail = cmp.Or(cond.Reason, cond.Type)
		case (cond.Type == "QuotaReserved" || cond.Type == "Admitted") && strings.EqualFold(cond.Status, "False") &&
			(cond.Reason == "PreEnqueue" || cond.Reason == "Inadmissible"):
			stuck = true
			since = cond.LastTransitionTime
			detail = cond.Reason
		}
		return true
	}, "status", "conditions")

	if finished {
		return false, time.Time{}, ""
	}
	return stuck, since, detail
}

func (c *k8sUpgradeGangGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []upgradeGangFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= upgradeGangMaxEventsSweep {
			log.Info("SKIP rest: k8s-upgrade-gang-guard event cap reached",
				"cap", upgradeGangMaxEventsSweep)
			break
		}
		cooldownKey := "upgradegang." + f.ns + "." + f.kind + "." + f.name + "." + f.reason
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, upgradeGangEventCooldown, now, kube.WarningEvent{
			Namespace: f.ns,
			Regarding: corev1.ObjectReference{
				APIVersion: f.apiVersion,
				Kind:       f.kind,
				Namespace:  f.ns,
				Name:       f.name,
				UID:        f.uid,
			},
			Reason:            upgradeGangEventReason,
			Note:              f.detail,
			ReportingInstance: cmp.Or(c.Name, CheckNameK8sUpgradeGangGuard),
		}) {
			emitted++
		}
	}
}
