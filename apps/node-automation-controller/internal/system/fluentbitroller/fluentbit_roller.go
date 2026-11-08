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
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

type fluentBitRoller struct {
	cs kubernetes.Interface
	// dyn feeds the maintenance mutex's autopilot-Plan signal — the
	// DS rollout restart defers while a drain/k0s upgrade is in
	// flight.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the controller name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the rollout-restart
	// timestamp is deterministic. nil → time.Now.
	now shared.Clock
	// verdict memoizes the maintenance-mutex evaluation for this
	// reconcile (AllowedV stamps the result into the field so a
	// retry within the run pays no extra API reads).
	verdict kube.Verdict
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
	return shared.SetupNoConfig(d, func() error {
		r := &fluentBitRoller{cs: d.CS, dyn: d.Dyn, queue: d.Name, now: shared.SystemClock}
		return ctrl.NewControllerManagedBy(d.Mgr).
			Named(d.Name).
			For(&corev1.Secret{}, builder.WithPredicates(onlyPipelineSecret)).
			Complete(shared.CountReconcile(d.Name, r.Reconcile))
	})
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
		return ctrl.Result{}, fmt.Errorf("get secret fluent-system/passiontech-pipeline: %w", err)
	}
	hash := sec.Annotations[kube.AnnoFluentConfigHash]
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
	cur := sec.Annotations[kube.AnnoRolledConfigHash]
	if hash == cur {
		log.Info("config already rolled — nothing to do",
			"secret", "fluent-system/passiontech-pipeline", "hash", hash)
		return res, nil
	}
	log.Info("config drift",
		"secret", "fluent-system/passiontech-pipeline", "hash", hash, "rolled", cur)

	// Storm gate: never restart the DS while nodes are down — adds
	// churn; positionDB guarantees resume once stable.
	notReady, err := kube.CountNotReadyNodes(ctx, r.cs)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("count not-ready nodes (storm gate): %w", err)
	}
	if notReady > 0 {
		log.Info("node(s) not Ready — skip roll, wait for cluster to stabilize",
			"daemonset", "fluent-system/fluent-bit", "notReady", notReady)
		return res, nil
	}

	ds, err := r.cs.AppsV1().DaemonSets("fluent-system").Get(ctx, "fluent-bit", metav1.GetOptions{})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get daemonset fluent-system/fluent-bit: %w", err)
	}
	// Bash settled check exactly: generation observed AND updated ==
	// desired. NumberReady is deliberately NOT required (bash didn't —
	// do not use kube.DaemonSetSettled, which is stricter).
	if ds.Generation != ds.Status.ObservedGeneration ||
		ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		log.Info("rollout in progress — skip",
			"daemonset", "fluent-system/fluent-bit",
			"generation", ds.Generation, "observed", ds.Status.ObservedGeneration,
			"updated", ds.Status.UpdatedNumberScheduled, "desired", ds.Status.DesiredNumberScheduled)
		return res, nil
	}

	// kubectl rollout restart equivalent. The stamp must land on the
	// POD TEMPLATE — kube.MergePatchAnnos only covers top-level
	// metadata.annotations, so kube.RestartTemplatePatch renders the
	// nested doc (same shared builder stale_recover.go uses).
	//
	// Maintenance mutex — a LIVE-workload mutation (rolling every
	// fluent-bit pod), so per AGENTS.md it gates on the
	// cordon/kured/autopilot signal the NotReady storm check above
	// does not cover. heal.AllowedV with a nil heals ledger — this
	// module's pacing is the config-hash drift, not a CooldownSet —
	// sharing r.verdict. Unverifiable fails closed: IncError the
	// queue and skip; the drift clears on the next reconcile once
	// maintenance is verifiable again.
	proceed, unverifiable := heal.AllowedV(ctx, log, &r.verdict,
		r.cs, r.dyn, nil, "fluent-system/fluent-bit", 0, r.now.Now())
	if unverifiable {
		metrics.IncError(r.queue)
		log.Info("SKIP roll: maintenance mutex unverifiable",
			"daemonset", "fluent-system/fluent-bit")
		return res, nil
	}
	if !proceed {
		log.Info("SKIP roll: maintenance active (cordon/kured/autopilot)",
			"daemonset", "fluent-system/fluent-bit")
		return res, nil
	}
	restartPatch := kube.RestartTemplatePatch(r.now.Now())
	if _, err := r.cs.AppsV1().DaemonSets("fluent-system").Patch(ctx, "fluent-bit",
		types.StrategicMergePatchType, restartPatch, metav1.PatchOptions{}); err != nil {
		return ctrl.Result{}, fmt.Errorf("rollout-restart patch daemonset fluent-system/fluent-bit: %w", err)
	}
	// State written only AFTER the restart succeeded (bash ordering):
	// writing first would silently swallow the drift if restart failed.
	statePatch, err := kube.MergePatchAnnos(map[string]any{kube.AnnoRolledConfigHash: hash})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("render rolled-config-hash patch: %w", err)
	}
	if _, err := r.cs.CoreV1().Secrets("fluent-system").Patch(ctx, "passiontech-pipeline",
		types.MergePatchType, statePatch, metav1.PatchOptions{}); err != nil {
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
