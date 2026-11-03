// fluent-bit-config-roller — port of hooks/30-fluent-bit-config-roller.sh.
//
// fluent-operator rewrites secret fluent-system/passiontech-pipeline
// when the generated config changes but NEVER restarts the pods —
// without this, GitOps applies land while fluent-bit runs stale config
// indefinitely (observed 2026-09-25).
//
// Drift signal lives entirely on that secret: fluent.io/config-hash
// (written by fluent-operator) vs passiontech.dev/rolled-config-hash
// (written by us). The secret is the only safe place for state — the
// DS metadata/spec annotations are rewritten/stripped by fluent-
// -operator within seconds, and Flux reverts anything it manages.
//
// Storm gates (bash): skip when any node is NotReady, skip while a
// previous rollout has not settled; API failure = do nothing.
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

type fluentBitRoller struct {
	cs      kubernetes.Interface
	enabled bool // FLUENTBIT_ROLLER_ENABLED — only clusters with fluentbit
}

// SetupFluentBitRoller wires the fluent-bit-config-roller reconciler.
// The informer is already field-selected to metadata.name=
// passiontech-pipeline; the predicate also pins the namespace.
// Disabled clusters (no fluentbit component) skip registration
// entirely — same pattern as SetupCertManagerReaper.
func SetupFluentBitRoller(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName("fluent-bit-config-roller").Info("disabled — module not registered")
		return nil
	}
	r := &fluentBitRoller{cs: cs, enabled: enabled}
	return ctrl.NewControllerManagedBy(mgr).
		Named("fluent-bit-config-roller").
		For(&corev1.Secret{}, builder.WithPredicates(
			predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == "fluent-system" &&
					o.GetName() == "passiontech-pipeline"
			}))).
		Complete(r)
}

func (r *fluentBitRoller) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// 30m safety net replacing the old crontab: catches a wiped
	// rolled-config-hash annotation even without a secret event.
	res := ctrl.Result{RequeueAfter: 30 * time.Minute}
	if !r.enabled {
		log.Info("skip: FLUENTBIT_ROLLER_ENABLED != true (cluster has no fluentbit component)")
		return res, nil
	}

	sec, err := r.cs.CoreV1().Secrets("fluent-system").Get(ctx, "passiontech-pipeline", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Enabled cluster but no pipeline secret — bash's set -e made
		// this an error+metric; surface it the same way.
		metrics.IncError("fluent-bit-config-roller")
		log.Info("WARN: pipeline secret fluent-system/passiontech-pipeline " +
			"missing — config drift untracked")
		return res, nil
	}
	if err != nil {
		metrics.IncError("fluent-bit-config-roller")
		return ctrl.Result{}, err
	}
	hash := sec.Annotations["fluent.io/config-hash"]
	if hash == "" {
		// Older operators lack config-hash — resourceVersion still
		// works, it just rolls on ANY secret write (bash fallback).
		hash = sec.ResourceVersion
	}
	cur := sec.Annotations["passiontech.dev/rolled-config-hash"]
	if hash == cur {
		log.Info("config already rolled — nothing to do", "hash", hash)
		return res, nil
	}
	log.Info("config drift", "hash", hash, "rolled", cur)

	// Storm gate: never restart the DS while nodes are down — adds
	// churn; positionDB guarantees resume once stable.
	notReady, err := countNotReadyNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError("fluent-bit-config-roller")
		return ctrl.Result{}, err
	}
	if notReady > 0 {
		log.Info("node(s) not Ready — skip roll, wait for cluster to stabilize", "notReady", notReady)
		return res, nil
	}

	ds, err := r.cs.AppsV1().DaemonSets("fluent-system").Get(ctx, "fluent-bit", metav1.GetOptions{})
	if err != nil {
		metrics.IncError("fluent-bit-config-roller")
		return ctrl.Result{}, err
	}
	// Bash settled check exactly: generation observed AND updated ==
	// desired. NumberReady is deliberately NOT required (bash didn't —
	// do not use daemonSetSettled, which is stricter).
	if ds.Generation != ds.Status.ObservedGeneration ||
		ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		log.Info("rollout in progress — skip",
			"generation", ds.Generation, "observed", ds.Status.ObservedGeneration,
			"updated", ds.Status.UpdatedNumberScheduled, "desired", ds.Status.DesiredNumberScheduled)
		return res, nil
	}

	// kubectl rollout restart equivalent.
	restartPatch := []byte(fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().UTC().Format(time.RFC3339)))
	if _, err := r.cs.AppsV1().DaemonSets("fluent-system").Patch(ctx, "fluent-bit",
		types.StrategicMergePatchType, restartPatch, metav1.PatchOptions{}); err != nil {
		metrics.IncError("fluent-bit-config-roller")
		return ctrl.Result{}, err
	}
	// State written only AFTER the restart succeeded (bash ordering):
	// writing first would silently swallow the drift if restart failed.
	statePatch := []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"passiontech.dev/rolled-config-hash":%q}}}`, hash))
	if _, err := r.cs.CoreV1().Secrets("fluent-system").Patch(ctx, "passiontech-pipeline",
		types.MergePatchType, statePatch, metav1.PatchOptions{}); err != nil {
		metrics.IncError("fluent-bit-config-roller")
		return ctrl.Result{}, err
	}
	log.Info("ROLL: restarted fluent-bit for config",
		"daemonset", "fluent-system/fluent-bit", "hash", hash)
	return res, nil
}
