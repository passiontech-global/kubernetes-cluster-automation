// live_socket_rollout.go — guarded workload rollout restarts for Check 5
// (live_socket_audit.go): enforces system-namespace and DB-quorum exemptions,
// persisted/in-RAM cooldown, maintenance mutex + heal budget, FluxPatchGate,
// and sweep-overlay workload reservation before patching the pod template.
package certdriftauditor

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

var liveDriftSystemNamespaces = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"flux-system":      true,
	"node-ops":         true,
	"cert-manager":     true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"external-secrets": true,
	// Operators/platform tenants whose TLS workloads are shared
	// infrastructure: an automatic rollout there has a wide blast
	// radius, so drift is still reported but the restart is skipped.
	"k0s-system":        true,
	"gatekeeper-system": true,
	"metallb-system":    true,
	"tigera-operator":   true,
}

var liveDriftDBQuorumLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
	"scylla.scylladb.com/cluster",
	"apps.rabbitmq.com/cluster",
	// Legacy/parallel operator labels seen on stateful DB workloads.
	"postgresql.cnpg.io/cluster",
	"operator.crunchydata.com/cluster",
	// Keep parity with the watchdogs' DB-quorum label sets — restarting a
	// member of one of these clusters can breach quorum.
	"pxc.percona.com/cluster",
	"psmdb.percona.com/cluster",
	"dragonflydb.io/cluster",
	"nats_cluster",
}

func (a *certDriftAuditor) maybeRolloutWorkload(ctx context.Context, log interface {
	Info(string, ...any)
	Error(error, string, ...any)
}, t *liveProbeTarget, rolled map[string]bool, now time.Time) {
	ns := t.svc.Namespace
	if liveDriftSystemNamespaces[ns] {
		return
	}
	kind, name, ok := a.resolveOwnerWorkload(ctx, t.pod)
	if !ok {
		return
	}
	wKey := ns + "/" + kind + "/" + name
	if rolled[wKey] {
		return
	}

	var obj metav1.Object
	var tplLabels map[string]string
	var fluxKind string
	var patchFn func(context.Context, []byte) error

	switch kind {
	case "Deployment":
		dep, err := a.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, dep)[kube.AnnoCertDriftReloadOptOut] == "true" {
			return
		}
		obj = dep
		tplLabels = dep.Spec.Template.Labels
		fluxKind = "deployment"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().Deployments(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	case "DaemonSet":
		ds, err := a.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, ds)[kube.AnnoCertDriftReloadOptOut] == "true" {
			return
		}
		obj = ds
		tplLabels = ds.Spec.Template.Labels
		fluxKind = "daemonset"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().DaemonSets(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	case "StatefulSet":
		sts, err := a.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			metrics.IncError(a.queue)
			return
		}
		if kube.EffectiveAnnos(ctx, sts)[kube.AnnoCertDriftReloadOptIn] != "true" {
			return
		}
		obj = sts
		tplLabels = sts.Spec.Template.Labels
		fluxKind = "statefulset"
		patchFn = func(c context.Context, data []byte) error {
			_, err := a.cs.AppsV1().StatefulSets(ns).Patch(c, name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
			return err
		}
	default:
		return
	}

	for _, lk := range liveDriftDBQuorumLabels {
		if tplLabels[lk] != "" {
			return
		}
	}

	lgr := logf.FromContext(ctx)
	proceed, unverifiable := heal.AllowedVPersisted(ctx, lgr, a.verdict, a.cs, a.dyn,
		&a.liveDriftRolloutHeals, obj, kube.AnnoLastCertDriftRollout, wKey,
		liveDriftRolloutCooldown, now)
	if !proceed {
		if unverifiable {
			metrics.IncError(a.queue)
		}
		return
	}
	if !heal.FluxPatchGate(fluxKind, obj, "live-socket-audit:"+wKey, now) {
		heal.RefundGrant(now)
		return
	}
	if !kube.TryReserveWorkloadKey(ctx, wKey) {
		heal.RefundGrant(now)
		return
	}
	if err := patchFn(ctx, kube.RestartTemplatePatch(now)); err != nil {
		kube.ReleaseWorkloadKey(ctx, wKey)
		if apierrors.IsNotFound(err) {
			heal.RefundGrant(now)
			log.Info("skip tls live-socket drift rollout: workload vanished mid-patch — grant refunded",
				"workload", wKey, "secret", t.secret.name)
			return
		}
		metrics.IncError(a.queue)
		log.Error(err, "tls live-socket drift rollout failed", "workload", wKey, "secret", t.secret.name)
		return
	}
	rolled[wKey] = true
	a.liveDriftRolloutHeals.Stamp(wKey, now)
	log.Info("ACTION: restarted workload due to stale live TLS certificate near expiry",
		"workload", wKey, "service", t.svc.Namespace+"/"+t.svc.Name, "secret", t.secret.name)
	if err := heal.StampPersisted(ctx, obj, patchFn, kube.AnnoLastCertDriftRollout,
		&a.liveDriftRolloutHeals, wKey, now); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "tls live-socket drift persisted cooldown stamp failed", "workload", wKey)
	}
}

func (a *certDriftAuditor) resolveOwnerWorkload(ctx context.Context, pod *corev1.Pod) (kind, name string, ok bool) {
	for i := range pod.OwnerReferences {
		ref := &pod.OwnerReferences[i]
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "DaemonSet", "StatefulSet":
			return ref.Kind, ref.Name, true
		case "ReplicaSet":
			rs, err := a.cs.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			if err != nil {
				return "", "", false
			}
			for j := range rs.OwnerReferences {
				r := &rs.OwnerReferences[j]
				if r.Controller != nil && *r.Controller && r.Kind == "Deployment" {
					return "Deployment", r.Name, true
				}
			}
		}
	}
	return "", "", false
}
