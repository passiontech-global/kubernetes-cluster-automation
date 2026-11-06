// persisted.go — the first-seen→min-age persistence-window pattern
// ~14 checks hand-roll: ledger.Observe stamps the signature key on
// first sight, the check logs "tracking first-seen" and waits out a
// min-age window before the signature counts, and a per-sweep Prune
// against the live-key set drops resolved keys so a flap re-arms.
// Persisted is the Observe+window half; the Prune stays per site
// (each check's live-key set is shaped differently) — see
// kcm_workqueue_watchdog / stateful_masterless_services /
// image_pull_storm / argocd_app_stuck for the reference shapes.
package probefw

import (
	"time"

	"github.com/go-logr/logr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// Persisted implements the first-seen persistence window every
// "signature must hold for >N before it counts" check shares. It
// observes key on the ledger: a key NOT already tracked is stamped
// now, logged ("tracking first-seen" — the wording every logging
// site uses), and reported inside the window (false); a tracked key
// reports now.Sub(first) >= minAge. Two reference sites
// (image_pull_storm, argocd_app_stuck) ignore `tracked` and never
// log — the early false is observation-identical whenever
// minAge > 0 (age reads 0 on first sight either way), so callers
// that must keep silence pass logr.Discard().
//
//	fs.Observe(key, now)          -> first, tracked
//	if !tracked                   -> log + return false
//	return now.Sub(first) >= minAge
func Persisted(fs *state.FirstSeenLedger, key string, now time.Time,
	minAge time.Duration, log logr.Logger) bool {

	first, tracked := fs.Observe(key, now)
	if !tracked {
		log.Info("signature — tracking first-seen", "key", key)
		return false
	}
	return now.Sub(first) >= minAge
}
