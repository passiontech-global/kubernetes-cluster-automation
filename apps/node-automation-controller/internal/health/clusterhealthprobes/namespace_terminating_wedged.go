// namespace_terminating_wedged.go — the
// namespace-terminating-wedged check (W10-CP1): Namespaces stuck
// Terminating past the threshold with their content/finalizers
// conditions, plus a throttled dead-owner finalizer sweep on CRs
// whose controller workload no longer exists.
package clusterhealthprobes

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// namespaceTerminatingWedgedCheck is the namespace-terminating-wedged
// watchdog with the finalizer sweep.
type namespaceTerminatingWedgedCheck struct{ *deps }

// newNamespaceTerminatingWedgedCheck builds the W10-CP1 check —
// stateless, it reads only deps.
func newNamespaceTerminatingWedgedCheck(d *deps) checkRunner {
	return &namespaceTerminatingWedgedCheck{deps: d}
}

const (
	checkNameNamespaceWedged = "namespace-terminating-wedged"

	// W10-CP1 — namespace-terminating-wedged knobs.
	nsTerminatingMinAge      = 20 * time.Minute
	nsFinalizerSweepCooldown = 30 * time.Minute
	nsFinalizerMaxStrips     = 20
)

var (
	// W10-CP1 — namespace stuck Terminating.
	namespaceTerminatingWedgedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_namespace_terminating_wedged",
		Help: "1 while the Namespace has been Terminating past the wedge threshold — W10-CP1.",
	}, []string{"namespace"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		namespaceTerminatingWedgedGauge)
}

// checkNamespaceTerminatingWedged flags Namespaces stuck in
// Terminating >20m and reports their drain-blocking conditions
// (NamespaceContentRemaining / NamespaceFinalizersRemaining) plus
// spec.finalizers — the diagnostic payload for "what is holding
// this namespace". Once per namespace per 30m it also runs the
// conservative dead-owner finalizer sweep: CRs in the namespace
// whose controller ownerRef resolves to a workload that no longer
// exists get their non-protected finalizers stripped.
func (p *namespaceTerminatingWedgedCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	nss, err := p.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list namespaces: %w", err)}
	}
	current := map[string][]string{}
	var wedged []string
	for i := range nss.Items {
		ns := &nss.Items[i]
		if ns.DeletionTimestamp == nil ||
			now.Sub(ns.DeletionTimestamp.Time) < nsTerminatingMinAge {
			continue
		}
		lv := []string{ns.Name}
		current[ns.Name] = lv
		namespaceTerminatingWedgedGauge.WithLabelValues(lv...).Set(1)
		wedged = append(wedged, nsStuckDiagnostic(ns, now))
		p.nsFinalizerSweep(ctx, log, ns.Name, now)
	}
	sort.Strings(wedged)
	p.reconcileEmittedGauges(checkNameNamespaceWedged,
		namespaceTerminatingWedgedGauge, current)
	if len(wedged) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "namespaces wedged Terminating >" +
		nsTerminatingMinAge.String() + ": " + strings.Join(wedged, " | ")}
}

// nsStuckDiagnostic renders one wedged namespace's blocking state
// for the check's why string.
func nsStuckDiagnostic(ns *corev1.Namespace, now time.Time) string {
	var conds []string
	for _, c := range ns.Status.Conditions {
		conds = append(conds, fmt.Sprintf("%s=%s", c.Type, c.Status))
	}
	var fins []string
	for _, f := range ns.Spec.Finalizers {
		fins = append(fins, string(f))
	}
	return fmt.Sprintf("%s(terminatingFor=%s,conditions=[%s],finalizers=[%s])",
		ns.Name, now.Sub(ns.DeletionTimestamp.Time).Truncate(time.Minute),
		strings.Join(conds, ","), strings.Join(fins, ","))
}

// protectedFinalizer lists finalizer values the dead-owner
// sweep must NEVER strip: the foreground-deletion propagation
// marker, every in-tree kubernetes.io/* finalizer (pvc-protection,
// pv-protection, service-protection, ... — each has its own
// controller contract), and the CSI external-attacher finalizer
// family the volumeattachment-cleaner owns.
func protectedFinalizer(f string) bool {
	if f == "foregroundDeletion" {
		return true
	}
	return strings.HasPrefix(f, "kubernetes.io/") ||
		strings.HasPrefix(f, "external-attacher/")
}

// nsFinalizerSweep enumerates namespaced resources in a wedged
// namespace via discovery and strips strippable finalizers from
// terminating CRs whose controller owner no longer exists. Throttled
// per namespace; a discovery failure skips the sweep (detection
// already FAILed the check).
func (p *namespaceTerminatingWedgedCheck) nsFinalizerSweep(ctx context.Context,
	log logr.Logger, nsName string, now time.Time) {

	if p.dyn == nil {
		return
	}
	ck := "selfheal/" + checkNameNamespaceWedged + "/finalsweep/" + nsName
	if p.healCooledDown(ck, nsFinalizerSweepCooldown, now) {
		return
	}
	lists, err := p.cs.Discovery().ServerPreferredResources()
	if err != nil {
		log.Info("WARN: namespace finalizer sweep — discovery failed, skipping",
			"namespace", nsName, "error", err)
		return
	}
	stripped := 0
	for _, rl := range lists {
		if rl == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range rl.APIResources {
			if !r.Namespaced || strings.Contains(r.Name, "/") {
				continue // cluster-scoped or subresource
			}
			gvr := schema.GroupVersionResource{
				Group: gv.Group, Version: gv.Version, Resource: r.Name}
			items, err := p.dyn.Resource(gvr).Namespace(nsName).
				List(ctx, metav1.ListOptions{})
			if err != nil {
				continue // no permission / absent — not evidence
			}
			for i := range items.Items {
				obj := &items.Items[i]
				if obj.GetDeletionTimestamp() == nil ||
					len(obj.GetFinalizers()) == 0 {
					continue
				}
				if p.maybeStripFinalizers(ctx, log, gvr, obj) {
					stripped++
					if stripped >= nsFinalizerMaxStrips {
						p.markHealStamp(ck, now)
						log.Info("namespace finalizer sweep — strip cap reached",
							"namespace", nsName, "stripped", stripped)
						return
					}
				}
			}
		}
	}
	p.markHealStamp(ck, now)
	if stripped > 0 {
		log.Info("namespace finalizer sweep done",
			"namespace", nsName, "stripped", stripped)
	}
}

// maybeStripFinalizers removes strippable finalizers from one
// terminating object — only when its controller ownerRef resolves to
// a workload that provably no longer exists. Returns true when a
// patch was applied.
func (p *namespaceTerminatingWedgedCheck) maybeStripFinalizers(ctx context.Context,
	log logr.Logger, gvr schema.GroupVersionResource,
	obj *unstructured.Unstructured) bool {

	var keep []string
	var strip []string
	for _, f := range obj.GetFinalizers() {
		if protectedFinalizer(f) {
			keep = append(keep, f)
		} else {
			strip = append(strip, f)
		}
	}
	if len(strip) == 0 {
		return false
	}
	if !p.ownerGone(ctx, obj) {
		return false
	}
	var fin any
	if len(keep) > 0 {
		fin = keep
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": obj.GetResourceVersion(),
			"finalizers":      fin,
		},
	})
	if err != nil {
		return false
	}
	if _, err := p.dyn.Resource(gvr).Namespace(obj.GetNamespace()).Patch(ctx,
		obj.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		if apierrors.IsForbidden(err) {
			// Expected until the RBAC wave grants patch on the CR —
			// not an apiserver failure, don't count a run error.
			log.Info("WARN: finalizer strip forbidden (RBAC pending)",
				"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName())
			return false
		}
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "finalizer strip failed",
			"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName())
		return false
	}
	log.Info("PATCH-FINALIZERS: dead-owner CR in terminating namespace — stripped finalizers",
		"gvr", gvr.String(), "object", obj.GetNamespace()+"/"+obj.GetName(),
		"stripped", strip, "kept", keep)
	return true
}

// ownerGone reports whether the object's controller ownerRef
// points at a workload that no longer exists — the "dead operator"
// proof required before stripping. Unknown kinds and lookup errors
// fail closed (owner presumed alive).
func (p *namespaceTerminatingWedgedCheck) ownerGone(ctx context.Context,
	obj *unstructured.Unstructured) bool {

	ref := metav1.GetControllerOf(obj)
	if ref == nil {
		return false
	}
	ns := obj.GetNamespace()
	get := func(kind, name string) error {
		switch kind {
		case "Deployment":
			_, err := p.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "StatefulSet":
			_, err := p.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "DaemonSet":
			_, err := p.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "ReplicaSet":
			_, err := p.cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "Job":
			_, err := p.cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		case "CronJob":
			_, err := p.cs.BatchV1().CronJobs(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		}
		return fmt.Errorf("unresolvable owner kind %q", kind)
	}
	err := get(ref.Kind, ref.Name)
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil {
		return false // lookup failed or unknown kind — fail closed
	}
	// Owner object exists — except a ReplicaSet whose own Deployment
	// is gone: the RS is GC-pending garbage, so its finalizers are
	// just as dead.
	if ref.Kind == "ReplicaSet" {
		rs, err := p.cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		if dref := metav1.GetControllerOf(rs); dref != nil && dref.Kind == "Deployment" {
			_, err := p.cs.AppsV1().Deployments(ns).Get(ctx, dref.Name, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}
	}
	return false
}
