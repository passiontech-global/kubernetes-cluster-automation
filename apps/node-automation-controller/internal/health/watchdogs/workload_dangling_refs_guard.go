// workload_dangling_refs_guard.go — health check "workload-dangling-refs-guard":
// heavy-cadence (probefw.HeavyScanCycles, ~30m) pre-rollout guardrail detecting
// active Deployments, StatefulSets, DaemonSets, and non-suspended CronJobs
// (skipping replicas==0 and intentionally downscaled workloads) that reference
// missing ServiceAccounts, PriorityClasses, RuntimeClasses, or non-optional
// ConfigMaps/Secrets (envFrom, env.valueFrom, volumes, projected volumes).
//
// Uses metadata-only lists (kube.ListPartialOrFallback) for ConfigMaps and
// Secrets, and skips any ref kind gracefully on 403 Forbidden.
// Emits node_automation_workload_dangling_ref{namespace,kind,name,ref_kind}
// and cooldown-deduped Warning Events (WorkloadDanglingRef). Detect-only.
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
	nodev1 "k8s.io/api/node/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameWorkloadDanglingRefsGuard is the registry check name for workload-dangling-refs-guard.
	CheckNameWorkloadDanglingRefsGuard = "workload-dangling-refs-guard"

	danglingRefsEventCooldown  = 6 * time.Hour
	danglingRefsMaxEventsSweep = 20
	danglingRefsEventReason    = "WorkloadDanglingRef"
)

var workloadDanglingRefGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_workload_dangling_ref",
	Help: "1 while an active Deployment, StatefulSet, DaemonSet, or CronJob references a missing ServiceAccount, PriorityClass, RuntimeClass, ConfigMap, or Secret.",
}, []string{"namespace", "kind", "name", "ref_kind"})

func init() {
	ctrlmetrics.Registry.MustRegister(workloadDanglingRefGauge)
}

type workloadDanglingRefsGuardCheck struct {
	*probefw.Deps

	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
	cycle         uint64
	lastFindings  []string
}

// NewWorkloadDanglingRefsGuardCheck constructs the workload-dangling-refs-guard check.
func NewWorkloadDanglingRefsGuardCheck(d *probefw.Deps) probefw.Check {
	return &workloadDanglingRefsGuardCheck{Deps: d}
}

type danglingRefWorkload struct {
	apiVersion string
	kind       string
	ns         string
	name       string
	uid        types.UID
	sa         string
	pc         string
	rc         string
	cms        []string
	secrets    []string
}

type danglingRefEventTarget struct {
	w       danglingRefWorkload
	refKind string
	missing []string
}

func (c *workloadDanglingRefsGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, danglingRefsEventCooldown)

	c.cycle++
	if c.cycle%probefw.HeavyScanCycles != 1 {
		var carried probefw.SweepReport
		for k, lv := range c.emitted.Last() {
			carried.Carry(k, lv)
		}
		for _, f := range c.lastFindings {
			carried.Find(f)
		}
		return carried.Result(&c.emitted, workloadDanglingRefGauge.DeleteLabelValues,
			"workload dangling refs: ", ", ")
	}

	workloads, err := c.collectActiveWorkloads(ctx)
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}

	var needSA, needPC, needRC, needCM, needSec bool
	for _, w := range workloads {
		if w.sa != "" {
			needSA = true
		}
		if w.pc != "" {
			needPC = true
		}
		if w.rc != "" {
			needRC = true
		}
		if len(w.cms) > 0 {
			needCM = true
		}
		if len(w.secrets) > 0 {
			needSec = true
		}
	}

	saSet, saSkip, err := c.loadServiceAccounts(ctx, log, needSA)
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}
	pcSet, pcSkip, err := c.loadPriorityClasses(ctx, log, needPC)
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}
	rcSet, rcSkip, err := c.loadRuntimeClasses(ctx, log, needRC)
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}
	cmSet, cmSkip, err := c.loadNamespacedMetaSet(ctx, log, needCM, "configmaps")
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}
	secSet, secSkip, err := c.loadNamespacedMetaSet(ctx, log, needSec, "secrets")
	if err != nil {
		c.cycle--
		return probefw.Result{Infra: err}
	}

	var rep probefw.SweepReport
	var events []danglingRefEventTarget

	emitMissing := func(w danglingRefWorkload, refKind string, missing []string) {
		slices.Sort(missing)
		tupleKey := w.ns + "/" + w.kind + "/" + w.name + "/" + refKind
		detail := fmt.Sprintf("%s/%s/%s missing %s [%s]", w.kind, w.ns, w.name, refKind, strings.Join(missing, ","))
		rep.Emit(workloadDanglingRefGauge, tupleKey,
			[]string{w.ns, w.kind, w.name, refKind}, detail)
		events = append(events, danglingRefEventTarget{w: w, refKind: refKind, missing: missing})
	}

	for _, w := range workloads {
		if w.sa != "" && !saSkip && !saSet[w.ns+"/"+w.sa] {
			emitMissing(w, "ServiceAccount", []string{w.sa})
		}
		if w.pc != "" && !pcSkip && !pcSet[w.pc] {
			emitMissing(w, "PriorityClass", []string{w.pc})
		}
		if w.rc != "" && !rcSkip && !rcSet[w.rc] {
			emitMissing(w, "RuntimeClass", []string{w.rc})
		}
		if len(w.cms) > 0 && !cmSkip {
			if miss := missingNamespaced(w.ns, w.cms, cmSet); len(miss) > 0 {
				emitMissing(w, "ConfigMap", miss)
			}
		}
		if len(w.secrets) > 0 && !secSkip {
			if miss := missingNamespaced(w.ns, w.secrets, secSet); len(miss) > 0 {
				emitMissing(w, "Secret", miss)
			}
		}
	}

	slices.SortFunc(events, func(a, b danglingRefEventTarget) int {
		if x := cmp.Compare(a.w.ns, b.w.ns); x != 0 {
			return x
		}
		if x := cmp.Compare(a.w.kind, b.w.kind); x != 0 {
			return x
		}
		if x := cmp.Compare(a.w.name, b.w.name); x != 0 {
			return x
		}
		return cmp.Compare(a.refKind, b.refKind)
	})

	emittedEvents := 0
	for _, ev := range events {
		if emittedEvents >= danglingRefsMaxEventsSweep {
			log.Info("SKIP rest: workload-dangling-refs-guard event cap reached",
				"cap", danglingRefsMaxEventsSweep)
			break
		}
		cooldownKey := "danglingref." + ev.w.ns + "." + ev.w.kind + "." + ev.w.name + "." + ev.refKind
		note := fmt.Sprintf("%s %s/%s references missing %s [%s]",
			ev.w.kind, ev.w.ns, ev.w.name, ev.refKind, strings.Join(ev.missing, ", "))
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, danglingRefsEventCooldown, now, kube.WarningEvent{
			Namespace: ev.w.ns,
			Regarding: corev1.ObjectReference{
				APIVersion: ev.w.apiVersion,
				Kind:       ev.w.kind,
				Namespace:  ev.w.ns,
				Name:       ev.w.name,
				UID:        ev.w.uid,
			},
			Reason:            danglingRefsEventReason,
			Note:              note,
			ReportingInstance: cmp.Or(c.Name, CheckNameWorkloadDanglingRefsGuard),
		}) {
			emittedEvents++
		}
	}

	c.lastFindings = rep.Sorted()
	return rep.Result(&c.emitted, workloadDanglingRefGauge.DeleteLabelValues,
		"workload dangling refs: ", ", ")
}

func (c *workloadDanglingRefsGuardCheck) collectActiveWorkloads(ctx context.Context) ([]danglingRefWorkload, error) {
	var out []danglingRefWorkload

	deps, err := c.AllDeployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deps {
		d := &deps[i]
		if d.DeletionTimestamp != nil ||
			(d.Spec.Replicas != nil && *d.Spec.Replicas == 0) ||
			kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, d), d.Spec.Replicas) {
			continue
		}
		out = append(out, extractWorkloadRefs("apps/v1", "Deployment", d.Namespace, d.Name, d.UID, &d.Spec.Template.Spec))
	}

	stsList, err := c.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range stsList {
		s := &stsList[i]
		if s.DeletionTimestamp != nil ||
			(s.Spec.Replicas != nil && *s.Spec.Replicas == 0) ||
			kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, s), s.Spec.Replicas) {
			continue
		}
		out = append(out, extractWorkloadRefs("apps/v1", "StatefulSet", s.Namespace, s.Name, s.UID, &s.Spec.Template.Spec))
	}

	dsList, err := c.AllDaemonSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range dsList {
		ds := &dsList[i]
		if ds.DeletionTimestamp != nil {
			continue
		}
		out = append(out, extractWorkloadRefs("apps/v1", "DaemonSet", ds.Namespace, ds.Name, ds.UID, &ds.Spec.Template.Spec))
	}

	cjList, err := c.AllCronJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cronjobs: %w", err)
	}
	for i := range cjList {
		cj := &cjList[i]
		if cj.DeletionTimestamp != nil || (cj.Spec.Suspend != nil && *cj.Spec.Suspend) {
			continue
		}
		out = append(out, extractWorkloadRefs("batch/v1", "CronJob", cj.Namespace, cj.Name, cj.UID, &cj.Spec.JobTemplate.Spec.Template.Spec))
	}

	return out, nil
}

func extractWorkloadRefs(apiVersion, kind, ns, name string, uid types.UID, podSpec *corev1.PodSpec) danglingRefWorkload {
	w := danglingRefWorkload{
		apiVersion: apiVersion,
		kind:       kind,
		ns:         ns,
		name:       name,
		uid:        uid,
		sa:         podSpec.ServiceAccountName,
		pc:         podSpec.PriorityClassName,
	}
	if podSpec.RuntimeClassName != nil {
		w.rc = *podSpec.RuntimeClassName
	}

	cmSeen := map[string]bool{}
	secSeen := map[string]bool{}
	addCM := func(n string) {
		if n != "" && !cmSeen[n] {
			cmSeen[n] = true
			w.cms = append(w.cms, n)
		}
	}
	addSec := func(n string) {
		if n != "" && !secSeen[n] {
			secSeen[n] = true
			w.secrets = append(w.secrets, n)
		}
	}

	scanContainer := func(ct corev1.Container) {
		for _, ef := range ct.EnvFrom {
			if ef.ConfigMapRef != nil && (ef.ConfigMapRef.Optional == nil || !*ef.ConfigMapRef.Optional) {
				addCM(ef.ConfigMapRef.Name)
			}
			if ef.SecretRef != nil && (ef.SecretRef.Optional == nil || !*ef.SecretRef.Optional) {
				addSec(ef.SecretRef.Name)
			}
		}
		for _, ev := range ct.Env {
			if ev.ValueFrom == nil {
				continue
			}
			if ref := ev.ValueFrom.ConfigMapKeyRef; ref != nil && (ref.Optional == nil || !*ref.Optional) {
				addCM(ref.Name)
			}
			if ref := ev.ValueFrom.SecretKeyRef; ref != nil && (ref.Optional == nil || !*ref.Optional) {
				addSec(ref.Name)
			}
		}
	}
	for _, ic := range podSpec.InitContainers {
		scanContainer(ic)
	}
	for _, ct := range podSpec.Containers {
		scanContainer(ct)
	}
	for _, v := range podSpec.Volumes {
		if v.ConfigMap != nil && (v.ConfigMap.Optional == nil || !*v.ConfigMap.Optional) {
			addCM(v.ConfigMap.Name)
		}
		if v.Secret != nil && (v.Secret.Optional == nil || !*v.Secret.Optional) {
			addSec(v.Secret.SecretName)
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.ConfigMap != nil && (src.ConfigMap.Optional == nil || !*src.ConfigMap.Optional) {
					addCM(src.ConfigMap.Name)
				}
				if src.Secret != nil && (src.Secret.Optional == nil || !*src.Secret.Optional) {
					addSec(src.Secret.Name)
				}
			}
		}
	}

	return w
}

func (c *workloadDanglingRefsGuardCheck) loadServiceAccounts(ctx context.Context, log logr.Logger, needed bool) (map[string]bool, bool, error) {
	if !needed {
		return nil, true, nil
	}
	sas, err := c.AllServiceAccounts(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("ServiceAccount list skipped (403)", "error", err)
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("list serviceaccounts: %w", err)
	}
	out := make(map[string]bool, len(sas))
	for i := range sas {
		out[sas[i].Namespace+"/"+sas[i].Name] = true
	}
	return out, false, nil
}

func (c *workloadDanglingRefsGuardCheck) loadPriorityClasses(ctx context.Context, log logr.Logger, needed bool) (map[string]bool, bool, error) {
	if !needed {
		return nil, true, nil
	}
	pcs, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit:           probefw.HealthListPageSize,
		ResourceVersion: "0",
	}, func(lctx context.Context, opts metav1.ListOptions) ([]schedulingv1.PriorityClass, string, error) {
		list, lerr := c.CS.SchedulingV1().PriorityClasses().List(lctx, opts)
		if lerr != nil {
			return nil, "", lerr
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("PriorityClass list skipped", "error", err)
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("list priorityclasses: %w", err)
	}
	out := make(map[string]bool, len(pcs))
	for i := range pcs {
		out[pcs[i].Name] = true
	}
	return out, false, nil
}

func (c *workloadDanglingRefsGuardCheck) loadRuntimeClasses(ctx context.Context, log logr.Logger, needed bool) (map[string]bool, bool, error) {
	if !needed {
		return nil, true, nil
	}
	rcs, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit:           probefw.HealthListPageSize,
		ResourceVersion: "0",
	}, func(lctx context.Context, opts metav1.ListOptions) ([]nodev1.RuntimeClass, string, error) {
		list, lerr := c.CS.NodeV1().RuntimeClasses().List(lctx, opts)
		if lerr != nil {
			return nil, "", lerr
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		if apierrors.IsForbidden(err) || kube.IsCRDAbsent(err) {
			log.V(1).Info("RuntimeClass list skipped", "error", err)
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("list runtimeclasses: %w", err)
	}
	out := make(map[string]bool, len(rcs))
	for i := range rcs {
		out[rcs[i].Name] = true
	}
	return out, false, nil
}

func (c *workloadDanglingRefsGuardCheck) loadNamespacedMetaSet(ctx context.Context, log logr.Logger, needed bool, resource string) (map[string]bool, bool, error) {
	if !needed {
		return nil, true, nil
	}
	// Pass nil for fallbackDyn: configmaps and secrets are always covered by
	// typedMetaListers on c.CS, so a 403 from c.CS must surface rather than
	// falling through to an un-reactored dynamic client in tests.
	items, err := kube.ListPartialOrFallback(ctx, c.Meta, c.CS, nil,
		corev1.SchemeGroupVersion.WithResource(resource),
		metav1.NamespaceAll,
		metav1.ListOptions{
			Limit:           probefw.HealthListPageSize,
			ResourceVersion: "0",
		})
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("metadata list skipped (403)", "resource", resource, "error", err)
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("list %s: %w", resource, err)
	}
	out := make(map[string]bool, len(items))
	for i := range items {
		out[items[i].Namespace+"/"+items[i].Name] = true
	}
	return out, false, nil
}

func missingNamespaced(ns string, names []string, exists map[string]bool) []string {
	var missing []string
	for _, n := range names {
		if !exists[ns+"/"+n] {
			missing = append(missing, n)
		}
	}
	return missing
}
