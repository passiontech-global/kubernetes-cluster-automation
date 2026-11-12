// va_missing_node_gate.go — gate 1 of the volumeattachment-cleaner:
// the missing-node orphan proof (metric reason "missing_node"). A VA
// whose spec.nodeName has no Node object is only garbage once it has
// existed at least vaMissingNodeMinAge AND was seen orphaned in a
// PRIOR cycle — a node missing from ONE List (watch-cache gap,
// apiserver blip) must never detach a volume. The pre-pass below
// records this cycle's sightings for every listed VA before any
// delete runs, so a VA past the delete cap keeps its firstSeen
// ledger instead of re-arming the two-sighting window every capped
// cycle. Split out of volumeattachment_cleaner.go — see that file
// for the sweep that consumes these verdicts.
package volumeattachmentcleaner

import (
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
)

// sightMissingNodeOrphans is the pre-pass collector: records this
// cycle's missing-node sightings for EVERY listed VA before any
// delete runs — a VA past the delete cap keeps its firstSeen ledger
// instead of re-arming the two-sighting window every capped cycle.
func (c *volumeAttachmentCleaner) sightMissingNodeOrphans(
	vas []storagev1.VolumeAttachment, nodeByName map[string]*corev1.Node,
	orphanNow, seenPrior map[string]bool, now time.Time, log logr.Logger) {
	for i := range vas {
		va := &vas[i]
		if va.DeletionTimestamp != nil {
			continue
		}
		if _, ok := nodeByName[va.Spec.NodeName]; !ok {
			orphanNow[va.Name] = true
			_, seenPrior[va.Name] = c.orphanFirstSeen.Observe(vaFirstSeenKey(va), now)
			if !seenPrior[va.Name] {
				log.Info("orphaned VA sighted — tracking for next cycle",
					"va", va.Name, "node", va.Spec.NodeName)
			}
		}
	}
}

// missingNodeReason returns the metric reason for garbage-collecting
// a VA whose node object is gone — the VA can only be garbage.
// missing_node still requires the VA to be old enough
// (vaMissingNodeMinAge: brand-new VAs legitimately race ahead of a
// node create during provisioning) AND a sighting in a PRIOR cycle
// (seenPrior), so a one-off node List gap never detaches anything.
func (c *volumeAttachmentCleaner) missingNodeReason(
	va *storagev1.VolumeAttachment, seenPrior map[string]bool,
	now time.Time) string {
	if seenPrior[va.Name] &&
		now.Sub(va.CreationTimestamp.Time) >= vaMissingNodeMinAge {
		return "missing_node"
	}
	return ""
}

// forgetReattachedOrphans re-arms the two-sighting grace window for
// every VA that stopped looking orphaned (node reappeared, or the VA
// vanished between cycles).
func (c *volumeAttachmentCleaner) forgetReattachedOrphans(
	orphanNow map[string]bool, log logr.Logger) {
	c.orphanFirstSeen.Prune(func(key string) bool {
		if orphanNow[vaLedgerName(key)] {
			return true
		}
		log.Info("orphan sighting cleared — node reappeared or VA gone", "va", vaLedgerName(key))
		return false
	})
}
