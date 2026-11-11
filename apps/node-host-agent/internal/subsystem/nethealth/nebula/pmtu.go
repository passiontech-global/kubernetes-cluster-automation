// pmtu.go — the overlay-mtu-guard PMTU probe: one 1200-byte DF ping
// against the first alive overlay target, latching
// state-nebula-pmtu-blackhole after ConsecNeeded failures. Moved
// verbatim out of the parent nethealth package's nebula_health.go.
package nebula

import (
	"context"
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
)

// checkNebulaPMTU is the overlay-mtu-guard double-encapsulation PMTU probe:
// small-packet overlay pings keep passing while a 1200-byte
// don't-fragment probe blackholes — the signature of a path MTU
// below the overlay's (nebula-in-nebula / wg-in-overlay double
// encapsulation leaves less headroom than the overlay MTU
// advertises). The probe only runs when at least one overlay
// target answered the normal small pings — total overlay failure
// is the isolated/degraded verdict's job, not a PMTU latch.
// ConsecNeeded consecutive DF failures latch
// state-nebula-pmtu-blackhole; a passing probe (or no alive
// target) clears it.
func (n *Deps) checkNebulaPMTU(ctx context.Context,
	targets []string, results map[string]PingResult) {
	target := ""
	for _, t := range targets {
		if results[t].Ok {
			target = t
			break
		}
	}
	if target == "" {
		// No alive overlay peer this cycle — the isolation /
		// degraded verdicts own the diagnosis; a PMTU streak
		// cannot be measured without a reachable target.
		n.PMTUFails = 0
		n.StateExit(latchdefs.LatchNebulaPMTUBlackhole)
		return
	}
	out, err := n.RunHostCmd(ctx, []string{
		"ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1200", target})
	if err != nil {
		n.PMTUFails++
		n.State.SuspectLog(latchdefs.LatchNebulaPMTUBlackhole, fmt.Sprintf(
			"suspect: nebula-pmtu-blackhole df_probe_failed target=%s size=1200%s: %v (%s)",
			target, checkkit.Progress(n.PMTUFails, n.ConsecNeeded()),
			err, n.TrimRunErr(out)), suspectLogCadence)
		if n.PMTUFails >= n.ConsecNeeded() {
			n.State.Enter(latchdefs.LatchNebulaPMTUBlackhole,
				fmt.Sprintf("target=%s df_size=1200", target))
		}
		return
	}
	n.PMTUFails = 0
	n.StateExit(latchdefs.LatchNebulaPMTUBlackhole)
}
