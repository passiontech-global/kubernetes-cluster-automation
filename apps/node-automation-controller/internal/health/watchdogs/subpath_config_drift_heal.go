// subpath_config_drift_heal.go — subPath mount object extraction, fresh-pod
// detection, restart-template nudge, and Warning Event emission for
// subpath-config-drift.
// Split from subpath_config_drift.go.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

func subPathReferencedObjects(podSpec *corev1.PodSpec) (cms, secs []string) {
	volKind := map[string]string{}
	volName := map[string]string{}
	for _, v := range podSpec.Volumes {
		switch {
		case v.ConfigMap != nil && v.ConfigMap.Name != "":
			volKind[v.Name] = "cm"
			volName[v.Name] = v.ConfigMap.Name
		case v.Secret != nil && v.Secret.SecretName != "":
			volKind[v.Name] = "sec"
			volName[v.Name] = v.Secret.SecretName
		}
	}
	for _, m := range allMounts(podSpec) {
		if m.SubPath == "" {
			continue
		}
		switch volKind[m.Name] {
		case "cm":
			cms = append(cms, volName[m.Name])
		case "sec":
			secs = append(secs, volName[m.Name])
		}
	}
	return cms, secs
}

func subPathFreshPods(w subPathWorkload, pods []*corev1.Pod,
	driftStart time.Time) (bool, int) {

	if len(w.template) == 0 {
		return false, 0
	}
	sel := labels.SelectorFromSet(w.template)
	total, fresh := 0, 0
	for _, p := range pods {
		if p.Namespace != w.ns || p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		if !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		total++
		if !p.Status.StartTime.IsZero() &&
			p.Status.StartTime.Time.After(driftStart) {
			fresh++
		}
	}
	return total > 0 && fresh == total, total
}

func subPathGateKind(kind string) string {
	switch kind {
	case "Deployment":
		return "deployment"
	case "StatefulSet":
		return "statefulset"
	case "DaemonSet":
		return "daemonset"
	}
	return strings.ToLower(kind)
}

func (p *subpathConfigDriftCheck) reloadWorkload(ctx context.Context,
	log logr.Logger, w subPathWorkload, pods []*corev1.Pod,
	driftStart, now time.Time, mayPatch bool) (bool, bool) {

	key := w.kind + "/" + w.ns + "/" + w.name
	if fresh, total := subPathFreshPods(w, pods, driftStart); fresh {
		log.Info("subpath drift self-resolved — all pods restarted post-drift",
			"workload", key, "pods", total)
		return true, false
	}
	if !mayPatch {
		return false, false
	}
	ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, key)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.reloadHeals, w.obj, kube.AnnoLastSubPathReload, ck,
		subPathReloadCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return false, false
	}
	if !proceed {
		return false, false
	}
	wKey := w.ns + "/" + w.kind + "/" + w.name
	if !kube.TryReserveWorkloadKey(ctx, wKey) {
		heal.RefundGrant(now)
		log.Info("SKIP: subpath drift nudge — workload already disrupted this sweep",
			"workload", key)
		return false, false
	}
	if !heal.FluxPatchGate(subPathGateKind(w.kind), w.obj, CheckNameSubPathConfigDrift+":"+key, now) {
		kube.ReleaseWorkloadKey(ctx, wKey)
		heal.RefundGrant(now)
		log.Info("SKIP: subpath drift nudge — Flux Heal-Revert Loop",
			"workload", key)
		return false, false
	}
	patch := kube.RestartTemplatePatch(now)
	var err error
	switch w.kind {
	case "Deployment":
		_, err = p.CS.AppsV1().Deployments(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			p.InvalidateDeployments(ctx)
		}
	case "StatefulSet":
		_, err = p.CS.AppsV1().StatefulSets(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			p.InvalidateStatefulSets(ctx)
		}
	case "DaemonSet":
		_, err = p.CS.AppsV1().DaemonSets(w.ns).Patch(ctx, w.name,
			types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			p.InvalidateDaemonSets(ctx)
		}
	}
	if err != nil {
		kube.ReleaseWorkloadKey(ctx, wKey)
		metrics.IncError(p.Name)
		log.Error(err, "subpath drift restart-template patch failed",
			"workload", key)
		return false, true
	}
	if err := heal.StampPersisted(ctx, w.obj,
		func(ctx context.Context, data []byte) error {
			return p.stampSubPathReload(ctx, w, data)
		}, kube.AnnoLastSubPathReload, &p.reloadHeals, ck, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "subpath drift reload stamp failed",
			"workload", key)
	}
	log.Info("ACTION: subpath config drift — restart template nudge",
		"workload", key)
	return true, true
}

func (p *subpathConfigDriftCheck) stampSubPathReload(ctx context.Context,
	w subPathWorkload, data []byte) error {

	var err error
	switch w.kind {
	case "Deployment":
		_, err = p.CS.AppsV1().Deployments(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	case "StatefulSet":
		_, err = p.CS.AppsV1().StatefulSets(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	case "DaemonSet":
		_, err = p.CS.AppsV1().DaemonSets(w.ns).Patch(ctx, w.name,
			types.MergePatchType, data, metav1.PatchOptions{})
	}
	if err == nil {
		kube.RecordAnnoPatch(ctx, w.obj, data)
	}
	return err
}

func (p *subpathConfigDriftCheck) emitDriftEvent(ctx context.Context,
	log logr.Logger, findings []string, now time.Time) {

	if len(findings) == 0 {
		return
	}
	ck := probefw.SelfHealKey(CheckNameSubPathConfigDrift, "event")
	if p.eventHealed.CooledDown(ck, subPathEventCooldown, now) {
		return
	}
	msg := fmt.Sprintf("subpath config drift: %d workload(s) (%s)",
		len(findings), findings[0])
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "subpath-config-drift-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "SubPathConfigDrift",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: subpath drift event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: SubPathConfigDrift", "detail", msg)
}
