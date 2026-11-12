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

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// PersistedCooledDown reports whether ledgerKey is still inside
// cooldown on EITHER clock — the in-RAM ledger stamp OR the object's
// persisted annotation (RFC3339 or legacy unix seconds, via
// kube.AnnoTimeCtx — the sweep-overlay read, so a stamp recorded
// mid-sweep by a sibling check is visible). Both halves must be
// checked: the annotation alone misses a stamp whose patch never
// landed (in-RAM-only heal), the ledger alone forgets across
// operator restarts. A nil ledger collapses to annotation-only,
// mirroring AllowedV's nil-ledger contract. Callers log the
// specific defer reason in their own wording — this helper only
// answers the verdict.
func PersistedCooledDown(ctx context.Context,
	ledger *state.CooldownSet, obj metav1.Object,
	annoKey, ledgerKey string, cooldown time.Duration,
	now time.Time) bool {
	if ledger != nil && ledger.CooledDown(ledgerKey, cooldown, now) {
		return true
	}
	if t, ok := kube.AnnoTimeCtx(ctx, obj, annoKey); ok && now.Sub(t) < cooldown {
		return true
	}
	return false
}

// StampPersisted issues the annotation stamp half of a persisted
// cooldown: builds the {"metadata":{"annotations":{annoKey: now}}}
// merge patch via kube.MergePatchAnnos (RFC3339 — the contract every
// writer shares) and delivers it through patch, which the caller
// closes over its typed/dyn Patch call. On a landed patch the
// stamp is also recorded on the sweep overlay (kube.RecordAnnoPatch
// against obj) so later checks in the same sweep read it through
// EffectiveAnno/AnnoTimeCtx instead of the pre-patch snapshot copy —
// and the shared object itself is never mutated (the P0-1 race).
// The ledger is stamped ONLY when patch returns nil — the
// delivered-only contract DeletePod carries: a failed patch must
// not let one transient error suppress the heal for the whole
// cooldown window. A nil ledger skips the in-RAM half (the
// annotation alone persists).
func StampPersisted(ctx context.Context, obj metav1.Object,
	patch func(ctx context.Context, data []byte) error,
	annoKey string, ledger *state.CooldownSet, ledgerKey string,
	now time.Time) error {
	return StampPersistedMulti(ctx, obj, patch,
		[]string{annoKey}, ledger, ledgerKey, now)
}

// StampPersistedMulti is StampPersisted for heals that must stamp
// SEVERAL annotations in one atomic merge patch — the flux source
// nudge writes reconcile.fluxcd.io/requestedAt (its persisted
// cooldown) AND passiontech.dev/last-source-nudge (the in-flight
// signal helmrelease-unlocker and the consumer-side deferral guard
// read); stamping only the first left every sibling re-nudging the
// same source each cooldown window and burning the shared heal
// budget. Every key receives the same `now` stamp; the
// delivered-only ledger contract is unchanged.
func StampPersistedMulti(ctx context.Context, obj metav1.Object,
	patch func(ctx context.Context, data []byte) error,
	annoKeys []string, ledger *state.CooldownSet, ledgerKey string,
	now time.Time) error {
	annos := make(map[string]any, len(annoKeys))
	stamp := now.UTC().Format(time.RFC3339)
	for _, k := range annoKeys {
		annos[k] = stamp
	}
	data, err := kube.MergePatchAnnos(annos)
	if err != nil {
		return err
	}
	if err := patch(ctx, data); err != nil {
		return err
	}
	kube.RecordAnnoPatch(ctx, obj, data)
	if ledger != nil {
		ledger.Stamp(ledgerKey, now)
	}
	return nil
}

// AllowedVPersisted is AllowedV with the cooldown gate widened to
// the persisted stamp — the preamble the "persisted cooldown →
// mutex → act → stamp" heals hand-roll (watchdogs'
// healOperatorLeader, datastore's dragonfly heals, gitops'
// kustomization nudge, externalsecretnudge's connect bounce): the
// cooldown is the wider of the in-RAM ledger stamp AND the object's
// persisted annotation (PersistedCooledDown), and only after it
// clears does the maintenance mutex + heal budget evaluate.
//
// A nil obj (or empty annoKey — nothing to read off the object)
// collapses to plain AllowedV: the ledger-only cooldown plus the
// mutex, byte-identical verdicts. This is the leaseOptional
// operator's shape — no Lease object means no annotation half, so
// the gate degrades to the in-RAM ledger without changing the
// mutex contract.
//
// obj must be a literal nil or a non-nil metav1.Object — a typed nil
// pointer (*appsv1.StatefulSet)(nil) wrapped in the interface would
// panic inside AnnoTime, same as every PersistedCooledDown caller
// today. Callers with an optionally-absent object keep the
// `var obj metav1.Object; if x != nil { obj = x }` fold
// healOperatorLeader uses.
//
// v, cs, dyn, heals, key, cooldown and now carry AllowedV's contract
// unchanged (nil heals skips the in-RAM half, nil v means no
// memoization, unverifiable=true is fail-closed and the CALLER
// IncErrors its queue).
func AllowedVPersisted(ctx context.Context, log logr.Logger,
	v *maintenance.Verdict, cs kubernetes.Interface, dyn dynamic.Interface,
	heals *state.CooldownSet, obj metav1.Object, annoKey, key string,
	cooldown time.Duration, now time.Time) (proceed, unverifiable bool) {
	if obj == nil || annoKey == "" {
		return AllowedV(ctx, log, v, cs, dyn, heals, key, cooldown, now)
	}
	if PersistedCooledDown(ctx, heals, obj, annoKey, key, cooldown, now) {
		log.Info("skip heal: persisted stamp inside cooldown", "target", key)
		return false, false
	}
	// The ledger half is already checked — pass a nil heals so
	// AllowedV runs only its mutex + budget gates.
	return AllowedV(ctx, log, v, cs, dyn, nil, key, cooldown, now)
}
