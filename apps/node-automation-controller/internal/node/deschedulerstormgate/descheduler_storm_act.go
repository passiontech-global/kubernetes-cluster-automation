// descheduler_storm_act.go — the act half of the
// descheduler-storm-gate reconcile: fold the collected storm
// evidence into the scale/hold verdict, honor the manual hold
// annotation (with its stale-hold warning), re-arm the hold's
// first-seen window on release, and patch the Deployment's
// replicas + decision annotation. Split out of
// descheduler_storm_gate.go — see that file for the gate contract
// and descheduler_storm_signals.go for the evidence.
package deschedulerstormgate

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// applyVerdict computes the scale verdict from the collected
// evidence and acts on it: storm → replicas 0, clear → replicas 1.
// The verdict + evidence is recorded in annotation
// passiontech.dev/storm-gate-decision for post-incident debugging;
// passiontech.dev/storm-gate-hold=true is a manual hold (game-day/
// runbook) that skips scaling but still runs the stale-hold
// warning. Returns an error only for real actuation failures —
// every tolerated sub-failure is Warn-logged inside.
func (r *deschedulerStormGate) applyVerdict(ctx context.Context,
	deploy *appsv1.Deployment, ev *stormEvidence,
	now time.Time, log logr.Logger) error {
	want := int32(1)
	verdict := "clear"
	if ev.storming() {
		want, verdict = 0, "storm"
	}

	if deploy.Annotations[stormGateHoldAnno] == "true" {
		// maintenance-hold-stale: a hold kept "true" past the stale window is a
		// forgotten one — one MaintenanceHoldStale Warning per
		// episode. Runs before the early return so the hold path
		// never scales but still audibly complains.
		r.checkHoldStale(ctx, deploy, now, log)
		log.Info("storm-gate HOLD (annotation "+stormGateHoldAnno+
			") - verdict computed but not scaling", "verdict", verdict)
		return nil
	}

	// Hold released (or never held) — drop the persisted first-seen
	// stamp and the emitted-once marker so the NEXT hold re-arms the
	// full stale window. A failed clear is Warn-logged, never
	// returned: the annotation would only make a future warning
	// arrive early, never hold the descheduler.
	if err := heal.ClearPersistedFirstSeen(ctx, log, &r.holdSeen, deploy,
		kube.AnnoFirstSeenStormGateHold, stormHoldLedgerKey,
		r.deployAnnoPatch(deploy)); err != nil {
		log.Info("WARN: storm-gate hold first-seen clear failed — "+
			"a stale stamp could warn early on the next hold",
			"error", err)
	}
	r.holdWarned.Forget(stormHoldLedgerKey)

	// The apiserver defaults spec.replicas to 1 when unset — mirror
	// that default here instead of leaking a sentinel: the old
	// cur=-1 read a nil-replicas deployment as "wrong" on every
	// clear reconcile, forcing a redundant scale patch, and its ""
	// evidence rendered `cur=` in the decision annotation.
	cur := int32(1)
	if deploy.Spec.Replicas != nil {
		cur = *deploy.Spec.Replicas
	}
	curStr := strconv.Itoa(int(cur))
	decision := fmt.Sprintf("%s verdict=%s want=%d cur=%s not_ready=[%s] bad=[%s] tainted=[%s] cordoned=[%s] maintenance=[%s] preempted=[%s] imagepull=[%s]",
		r.now.Now().UTC().Format(time.RFC3339), verdict, want, curStr,
		strings.Join(ev.notReady, "\n"), strings.Join(ev.bad, "\n"),
		strings.Join(ev.tainted, "\n"), strings.Join(ev.cordoned, "\n"),
		strings.Join(ev.maintenance, "\n"), strings.Join(ev.preempted, "\n"),
		strings.Join(ev.imagePull, "\n"))

	switch {
	case cur != want:
		log.Info("storm-gate: scaling replicas",
			"verdict", verdict, "from", curStr, "to", want,
			"notReady", ev.notReady, "bad", ev.bad, "tainted", ev.tainted,
			"cordoned", ev.cordoned, "maintenance", ev.maintenance,
			"preempted", ev.preempted, "imagePull", ev.imagePull)
		// One merge patch carries spec.replicas AND the decision
		// annotation — two back-to-back merge patches on the same
		// Deployment would pay two API writes for one logical act.
		// Merge-patch only (never a full-object Update): a cached
		// Get races any concurrent spec edit (HPA, gitops) and
		// would clobber it or fail on resourceVersion.
		// metadata.resourceVersion inside the merge patch is the
		// apiserver's test-and-set: everything this verdict read —
		// hold annotation, replicas, the evidence — was observed at
		// that RV, and three cluster-wide scans run between the Get
		// and this patch. An operator setting the hold mid-sweep
		// (or any other concurrent edit) bumps the RV, the apiserver
		// rejects with 409, and the patch can never silently
		// overwrite the hold.
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{"replicas": want},
			"metadata": map[string]any{
				"resourceVersion": deploy.ResourceVersion,
				"annotations": map[string]string{
					stormGateDecisionAnno: decision,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("marshal replicas patch: %w", err)
		}
		if _, err := r.cs.AppsV1().Deployments("kube-system").
			Patch(ctx, "descheduler", types.MergePatchType, patch,
				metav1.PatchOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				// The deployment changed since the Get — a hold set
				// mid-sweep is exactly the dangerous case. Defer the
				// whole verdict: no scale, no annotation, the regular
				// cadence re-reads everything next sweep. A conflict
				// is a lost race, not an actuation failure.
				log.Info("DEFER: descheduler deployment changed mid-sweep — re-reading next sweep",
					"observedResourceVersion", deploy.ResourceVersion)
				return nil
			}
			return fmt.Errorf(
				"scale deployment kube-system/descheduler to %d replicas: %w",
				want, err)
		}
	case deploy.Annotations[stormGateDecisionAnno] == "":
		// Replicas already right but no decision recorded yet —
		// annotate anyway so the verdict is auditable (bash elif).
		if err := annotateStormDecision(ctx, r.cs, decision); err != nil {
			return err
		}
	default:
		log.Info("storm-gate: nothing to do",
			"verdict", verdict, "replicas", want)
	}
	return nil
}
