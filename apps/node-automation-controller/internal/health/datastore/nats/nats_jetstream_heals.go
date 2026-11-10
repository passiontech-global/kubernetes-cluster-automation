// nats_jetstream_heals.go — the act half of the
// nats-jetstream-health sweep: the quorum-safe member bounce. A
// pod-local wedge past the 10m first-seen window may bounce its
// member, but only under the >=2-OTHER-Ready-members-of-the-same-
// StatefulSet census — a delete that would drop the cluster under
// Raft quorum never fires. Split out of nats_jetstream_health.go —
// see that file for the check and nats_jetstream_signals.go for
// the evidence it consumes.
package nats

import (
	"context"
	"sort"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// bounceWedged deletes at most ONE wedged member per sweep even
// when several qualify — a fleet-wide wedge must heal one member at
// a time so a bad verdict can never halve the cluster in a single
// pass. Only reasons past their persistence window
// (natsHealableReasons ∩ s.past) qualify.
//
// Quorum-safe: a wedged member may still report Ready (the
// gray-failure shape), so the sibling count self-discounts — >=2
// OTHER Ready members of the SAME StatefulSet or the delete could
// drop the cluster under Raft quorum. The key sort makes WHICH
// member goes first deterministic — map order would bounce a
// random one, and the ledger stamp going from missing/stale to
// `now` is how a DELIVERED delete reads (DeletePodHeal swallows
// cooldown/mutex/delete failures).
func (s *natsSweep) bounceWedged(ctx context.Context) {
	healed := false
	bounceKeys := make([]string, 0, len(s.podReasons))
	for key := range s.podReasons {
		bounceKeys = append(bounceKeys, key)
	}
	sort.Strings(bounceKeys)
	for _, key := range bounceKeys {
		rs := s.podReasons[key]
		pod := s.census.memberByName[key]
		healable := false
		for r := range rs {
			if natsHealableReasons[r] && s.past[key][r] {
				healable = true
				break
			}
		}
		if !healable || healed {
			continue
		}
		other := s.census.readyBySTS[natsSTSKey(pod)]
		if probefw.PodRunningReady(pod) {
			other--
		}
		if other < 2 {
			s.log.Info("skip nats jetstream heal: fewer than 2 other Ready "+
				"members — a delete would break Raft quorum",
				"pod", key, "otherReady", other)
			continue
		}
		// The heal cooldown keys on the pod's CONTROLLER
		// (kube.PodControllerKey), not the pod name — the wedge
		// evidence (the Prom series and the seen ledger) outlives the
		// pod, so a member recreated under a fresh name must read as
		// the SAME heal target or the 30m window never applies and
		// the member bounces again on the very next sweep (same
		// controller-keyed shape dragonfly_replica_sync_storm keys
		// its restarts on). The pod-name key still decides WHICH
		// member goes first, and the >=2-Ready-siblings quorum census
		// stays grouped per StatefulSet.
		ck := kube.PodControllerKey(pod)
		hk := probefw.SelfHealKey(CheckNameNatsJetstreamHealth, ck)
		before, _ := s.p.Heals.Last(hk)
		s.p.DeletePodHeal(ctx, s.log, CheckNameNatsJetstreamHealth,
			ck, pod, natsHealCool, s.now)
		if stamp, ok := s.p.Heals.Last(hk); ok && stamp.After(before) {
			healed = true
		}
	}
}
