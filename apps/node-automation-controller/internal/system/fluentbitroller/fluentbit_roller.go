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
package fluentbitroller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

type fluentBitRoller struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the rollout-restart
	// timestamp is deterministic. nil → time.Now.
	now shared.Clock
}

// onlyPipelineSecret is the exact predicate the For() watch below
// installs — a package var so the test exercises the predicate
// directly instead of introspecting controller-runtime internals.
var onlyPipelineSecret = predicate.NewPredicateFuncs(func(o client.Object) bool {
	return o.GetNamespace() == "fluent-system" &&
		o.GetName() == "passiontech-pipeline"
})

// Setup wires the fluent-bit-config-roller reconciler.
// The informer is already field-selected to metadata.name=
// passiontech-pipeline; the predicate also pins the namespace.
// Disabled clusters (no fluentbit component — FLUENTBIT_ROLLER_ENABLED
// is opt-in, resolved by setupModules into Deps.Disabled) skip
// registration entirely.
func Setup(d shared.Deps) error {
	if d.Disabled {
		return nil
	}
	r := &fluentBitRoller{cs: d.CS, queue: d.Name, now: shared.SystemClock}
	return ctrl.NewControllerManagedBy(d.Mgr).
		Named(d.Name).
		For(&corev1.Secret{}, builder.WithPredicates(onlyPipelineSecret)).
		Complete(r)
}

func (r *fluentBitRoller) Reconcile(ctx context.Context, _ reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	// 30m safety net replacing the old crontab: catches a wiped
	// rolled-config-hash annotation even without a secret event.
	res := ctrl.Result{RequeueAfter: 30 * time.Minute}

	sec, err := r.cs.CoreV1().Secrets("fluent-system").Get(ctx, "passiontech-pipeline", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Enabled cluster but no pipeline secret — bash's set -e made
		// this an error+metric; surface it the same way.
		metrics.IncError(r.queue)
		log.Info("WARN: pipeline secret fluent-system/passiontech-pipeline " +
			"missing — config drift untracked")
		return res, nil
	}
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("get secret fluent-system/passiontech-pipeline: %w", err)
	}
	hash := sec.Annotations["fluent.io/config-hash"]
	if hash == "" {
		// Older operators lack config-hash. resourceVersion is NOT a
		// usable fallback here: the rolled-config-hash stamp below is
		// itself a secret write, so it bumps the RV — the stamped RV
		// never equals the RV we read, drift never clears, and the DS
		// restarts on every ~30m requeue forever. Hash the secret
		// DATA instead: stable across stamp/annotation writes, still
		// moves when the generated config actually changes.
		hash = secretDataHash(sec)
	}
	cur := sec.Annotations["passiontech.dev/rolled-config-hash"]
	if hash == cur {
		log.Info("config already rolled — nothing to do",
			"secret", "fluent-system/passiontech-pipeline", "hash", hash)
		return res, nil
	}
	log.Info("config drift",
		"secret", "fluent-system/passiontech-pipeline", "hash", hash, "rolled", cur)

	// Storm gate: never restart the DS while nodes are down — adds
	// churn; positionDB guarantees resume once stable.
	notReady, err := shared.CountNotReadyNodes(ctx, r.cs)
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		log.Info("node(s) not Ready — skip roll, wait for cluster to stabilize",
			"daemonset", "fluent-system/fluent-bit", "notReady", notReady)
		return res, nil
	}

	ds, err := r.cs.AppsV1().DaemonSets("fluent-system").Get(ctx, "fluent-bit", metav1.GetOptions{})
	if err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("get daemonset fluent-system/fluent-bit: %w", err)
	}
	// Bash settled check exactly: generation observed AND updated ==
	// desired. NumberReady is deliberately NOT required (bash didn't —
	// do not use shared.DaemonSetSettled, which is stricter).
	if ds.Generation != ds.Status.ObservedGeneration ||
		ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		log.Info("rollout in progress — skip",
			"daemonset", "fluent-system/fluent-bit",
			"generation", ds.Generation, "observed", ds.Status.ObservedGeneration,
			"updated", ds.Status.UpdatedNumberScheduled, "desired", ds.Status.DesiredNumberScheduled)
		return res, nil
	}

	// kubectl rollout restart equivalent.
	restartPatch := []byte(fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		r.now.Now().UTC().Format(time.RFC3339)))
	if _, err := r.cs.AppsV1().DaemonSets("fluent-system").Patch(ctx, "fluent-bit",
		types.StrategicMergePatchType, restartPatch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("rollout-restart patch daemonset fluent-system/fluent-bit: %w", err)
	}
	// State written only AFTER the restart succeeded (bash ordering):
	// writing first would silently swallow the drift if restart failed.
	statePatch := []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"passiontech.dev/rolled-config-hash":%q}}}`, hash))
	if _, err := r.cs.CoreV1().Secrets("fluent-system").Patch(ctx, "passiontech-pipeline",
		types.MergePatchType, statePatch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(r.queue)
		return ctrl.Result{}, fmt.Errorf("stamp rolled-config-hash on secret fluent-system/passiontech-pipeline: %w", err)
	}
	log.Info("ROLL: restarted fluent-bit for config",
		"daemonset", "fluent-system/fluent-bit", "hash", hash)
	return res, nil
}

// secretDataHash is the drift signal for secrets whose operator never
// stamps fluent.io/config-hash: a sha256 over the sorted data entries
// (16 hex chars — drift detection needs collision resistance against
// config churn, not cryptographic strength). Unlike resourceVersion it
// ignores our own rolled-config-hash stamp and unrelated metadata
// writes, yet still changes on any real config regeneration.
func secretDataHash(sec *corev1.Secret) string {
	keys := make([]string, 0, len(sec.Data))
	for k := range sec.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		// NUL separators keep "ab"+"c" distinct from "a"+"bc".
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(sec.Data[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
