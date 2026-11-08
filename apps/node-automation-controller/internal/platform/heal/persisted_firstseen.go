// persisted_firstseen.go — the "wider of two clocks" persistence
// window for signatures that must hold >= minAge before the
// remediation they gate may fire (the first-seen twin of
// persisted.go's cooldown pair).
//
// The in-RAM state.FirstSeenLedger loses every window on operator
// restart: a signature that held 9m of a 10m window re-arms from
// zero, delaying the heal it gates by a full window. These helpers
// stamp the first-seen time on the object the signature is
// evaluated against — a JSON map {"<ledger-key>": "<rfc3339>"}
// under a per-check passiontech.dev/first-seen-* annotation — so
// the restart resumes the window instead of restarting it. Only
// windows that gate a destructive/remediation action (pod deletes,
// untaints, scale-ups, operator bounces) get a persisted variant;
// alert-only signatures keep the pure in-RAM probefw.Persisted —
// their restart cost is a delayed alert, the safe direction.
//
// One annotation per check (kube.AnnoFirstSeen*) holding a per-key
// map: checks whose ledger keys share an object (OLM's per-reason
// keys on one Subscription, ArgoCD's per-condition keys on one
// Application) write independent entries, and one check's map is
// never written by a sibling module — the serial sweep has no
// lost-update race. The stamp dies with the object (a bounced pod
// or deleted CR carries no cleanup cost); a live object whose
// signature resolved is cleared via ClearPersistedFirstSeen on the
// healthy path so a later recurrence re-arms the full window.
package heal

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// firstSeenEntries decodes the per-key first-seen map an
// AnnoFirstSeen* annotation carries. Absent/garbage annotations
// read as an empty map — a stamp that cannot be parsed cannot
// prove an older window (same "unparseable = absent" posture as
// kube.ParseAnnoTime).
func firstSeenEntries(obj metav1.Object, annoKey string) map[string]string {
	raw := obj.GetAnnotations()[annoKey]
	if raw == "" {
		return map[string]string{}
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return map[string]string{}
	}
	return m
}

// firstSeenValue encodes the map back for the merge patch — an
// empty map marshals as nil so MergePatchAnnos' nil-deletes-key
// contract removes the annotation once its last entry clears.
func firstSeenValue(m map[string]string) any {
	if len(m) == 0 {
		return nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return string(data)
}

// stampFirstSeen merge-patches the first-seen map with key stamped
// at first (the EFFECTIVE first-seen — stamping `now` when the
// ledger already counts an older window would make the durable
// half younger than the truth and shorten the post-restart
// window). Delivered through the caller's patch closure like
// StampPersisted.
func stampFirstSeen(ctx context.Context, obj metav1.Object,
	annoKey string, m map[string]string, key string,
	first time.Time,
	patch func(ctx context.Context, data []byte) error) error {

	m[key] = first.UTC().Format(time.RFC3339)
	data, err := kube.MergePatchAnnos(map[string]any{
		annoKey: firstSeenValue(m),
	})
	if err != nil {
		return err
	}
	return patch(ctx, data)
}

// FirstSeenPersisted is the persisted variant of the first-seen
// window every "signature must hold >= minAge before acting" check
// shares (probefw.Persisted's durable twin). The verdict reads the
// WIDER of two clocks — the in-RAM ledger stamp OR the object's
// persisted annotation, whichever is EARLIER (for a persistence
// window the wider clock is the longer-held one): the ledger
// survives a failed patch, the annotation survives an operator
// restart. A restarted controller finding the annotation seeds the
// ledger back via fs.Seed, so subsequent sweeps keep one stamp.
//
// Stamping is best-effort and self-converging: whenever the
// annotation lacks the key (or carries a younger stamp than the
// effective first-seen — e.g. a stamp that landed late), the
// effective first-seen is merge-patched onto obj through patch. A
// patch failure is Warn-logged, never returned — signature
// tracking must not fail the sweep; the ledger still counts the
// window and the stamp retries next sweep while the signature
// stays live. A nil patch degrades to in-RAM-only tracking; a nil
// fs degrades to annotation-only tracking (same nil posture
// ClearPersistedFirstSeen honors).
//
// Returns true once the effective first-seen is >= minAge old —
// including the first post-restart sweep when the annotation
// already proves the window (the signature DID hold continuously;
// making it wait out a fresh window is what this exists to avoid).
// The resolution twin is ClearPersistedFirstSeen, called on the
// healthy path so a resolved signature re-arms.
func FirstSeenPersisted(ctx context.Context, log logr.Logger,
	fs *state.FirstSeenLedger, obj metav1.Object,
	annoKey, key string, minAge time.Duration, now time.Time,
	patch func(ctx context.Context, data []byte) error) bool {

	// A nil ledger degrades to annotation-only tracking — the same
	// nil posture ClearPersistedFirstSeen honors: the window lives
	// entirely in the object's stamp, `first` starts at now (nothing
	// tracked yet) and converges to the persisted stamp below.
	first, tracked := now, false
	if fs != nil {
		first, tracked = fs.Observe(key, now)
	}
	m := firstSeenEntries(obj, annoKey)
	annoT, annoOK := kube.ParseAnnoTime(m[key])
	switch {
	case annoOK && annoT.Before(first):
		// The persisted stamp is older — a window carried across a
		// restart. Restore it into RAM (Seed only moves the stamp
		// earlier) so the ledger and the annotation converge.
		first = annoT
		if fs != nil {
			fs.Seed(key, annoT)
		}
	case annoOK:
		// Annotation exists but is younger — the ledger's stamp is
		// the wider window; fall through to the restamp check so
		// the durable half converges to it.
	case !tracked:
		log.Info("signature — tracking first-seen", "key", key)
	}
	if !tracked && annoOK {
		log.Info("signature — resumed persisted first-seen",
			"key", key, "since", annoT.Format(time.RFC3339))
	}
	if patch != nil && (!annoOK || first.Before(annoT)) {
		if err := stampFirstSeen(ctx, obj, annoKey, m, key, first,
			patch); err != nil {
			log.Info("WARN: first-seen annotation stamp failed — in-RAM window only",
				"key", key, "anno", annoKey, "error", err)
		}
	}
	if !tracked && !annoOK {
		return false
	}
	return now.Sub(first) >= minAge
}

// ClearPersistedFirstSeen is the resolution twin of
// FirstSeenPersisted: the signature evaluated healthy this sweep,
// so the key must not keep a stamp either clock could inherit —
// the ledger Forgets it and the annotation map drops it (empty map
// removes the anno entirely). Call it on the healthy path for
// objects that OUTLIVE their signature (nodes, CRs, Services); an
// object about to be deleted needs no clear — the stamp dies with
// it.
//
// No-op (nil) when the key carries neither a ledger entry nor an
// annotation entry — the healthy path pays no write for an object
// that was never tracked. The ledger Forget happens regardless of
// the patch result so the in-RAM window never inherits a stale
// stamp; the patch error IS returned so the caller can Warn or
// IncError it — a stamp that survives its signature lets a later
// recurrence trip the window early (premature remediation), the
// dangerous direction of losing it.
func ClearPersistedFirstSeen(ctx context.Context, log logr.Logger,
	fs *state.FirstSeenLedger, obj metav1.Object,
	annoKey, key string,
	patch func(ctx context.Context, data []byte) error) error {

	if fs != nil {
		fs.Forget(key)
	}
	m := firstSeenEntries(obj, annoKey)
	if _, ok := m[key]; !ok {
		return nil // never stamped on the object — nothing persisted
	}
	delete(m, key)
	if patch == nil {
		return nil
	}
	data, err := kube.MergePatchAnnos(map[string]any{
		annoKey: firstSeenValue(m),
	})
	if err != nil {
		return err
	}
	if err := patch(ctx, data); err != nil {
		log.Info("WARN: first-seen annotation clear failed — "+
			"a stale stamp could fast-trip the next occurrence",
			"key", key, "anno", annoKey, "error", err)
		return err
	}
	return nil
}
