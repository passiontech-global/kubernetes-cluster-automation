// persisted.go — the "wider of two clocks" cooldown helpers for
// heals that persist their stamp on the object they acted on (the
// passiontech.dev/last-* annotations: last-operator-heal on the
// leader-election Lease, last-dragonfly-*-heal on the StatefulSet,
// flux's reconcile requestedAt). Three call sites hand-roll the same
// shape: read kube.AnnoTime off the object -> combine with the in-RAM
// CooldownSet (the ledger survives a failed patch, the annotation
// survives an operator restart — the cooldown is the WIDER of the
// two) -> act -> kube.MergePatchAnnos + typed/dyn Patch -> stamp the
// ledger only when the patch landed.
package heal

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// PersistedCooledDown reports whether ledgerKey is still inside
// cooldown on EITHER clock — the in-RAM ledger stamp OR the object's
// persisted annotation (RFC3339 or legacy unix seconds, via
// kube.AnnoTime). Both halves must be checked: the annotation alone
// misses a stamp whose patch never landed (in-RAM-only heal), the
// ledger alone forgets across operator restarts. A nil ledger
// collapses to annotation-only, mirroring AllowedV's nil-ledger
// contract. Callers log the specific defer reason in their own
// wording — this helper only answers the verdict.
func PersistedCooledDown(ledger *state.CooldownSet, obj metav1.Object,
	annoKey, ledgerKey string, cooldown time.Duration, now time.Time) bool {
	if ledger != nil && ledger.CooledDown(ledgerKey, cooldown, now) {
		return true
	}
	if t, ok := kube.AnnoTime(obj, annoKey); ok && now.Sub(t) < cooldown {
		return true
	}
	return false
}

// StampPersisted issues the annotation stamp half of a persisted
// cooldown: builds the {"metadata":{"annotations":{annoKey: now}}}
// merge patch via kube.MergePatchAnnos (RFC3339 — the contract every
// writer shares) and delivers it through patch, which the caller
// closes over its typed/dyn Patch call. The ledger is stamped ONLY
// when patch returns nil — the delivered-only contract DeletePod
// carries: a failed patch must not let one transient error suppress
// the heal for the whole cooldown window. A nil ledger skips the
// in-RAM half (the annotation alone persists).
func StampPersisted(ctx context.Context,
	patch func(ctx context.Context, data []byte) error,
	annoKey string, ledger *state.CooldownSet, ledgerKey string,
	now time.Time) error {
	data, err := kube.MergePatchAnnos(map[string]any{
		annoKey: now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if err := patch(ctx, data); err != nil {
		return err
	}
	if ledger != nil {
		ledger.Stamp(ledgerKey, now)
	}
	return nil
}
