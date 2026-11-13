// overlay.go — the nebula dataplane evaluation pipeline: parallel
// ping fanout, aggregation, path-quality latches, the
// isolated/degraded verdict, and the targeted dead-peer conntrack
// flush (nebula-conntrack-flush). Moved verbatim out of the parent
// nethealth package's nebula_health.go.
package nebula

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	yaml3 "go.yaml.in/yaml/v3"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

const (
	// nebulaDegradedCTFlushInterval is the nebula-conntrack-flush dead-peer
	// conntrack flush budget — often enough to unstick a
	// recovered underlay promptly, rare enough that a permanently
	// dead peer can't make `conntrack -D` spam the table every
	// cycle.
	nebulaDegradedCTFlushInterval = 5 * time.Minute
)

// PingResult bundles the per-target fanout output.
type PingResult struct {
	Ok  bool
	Rtt float64
}

// NebulaOverlayStats is the aggregated dataplane-probe outcome the
// latch/verdict/remediate phases consume: per-class alive/total
// counts, the dead-peer sets (nebula-conntrack-flush evicts only
// these), and the slowpath/siteedge evidence strings.
type NebulaOverlayStats struct {
	dpAlive, dpTotal int
	mkAlive, mkTotal int
	deadUnderlay     []string
	deadOverlay      []string
	slowpath         []string
	siteedge         []string
}

// ProbeNebulaOverlay runs the parallel dataplane fanout — serial
// pings would blow the check budget on a large mesh (wd_ping_fanout
// parity). Returns the probed target list (PMTU consumes it) and
// the per-target PingResult map.
func (n *Deps) ProbeNebulaOverlay(ctx context.Context,
	wd *watchdogconf.Config) ([]string, map[string]PingResult) {

	count := wd.OverlayProbeCount
	if count <= 0 {
		count = 3
	}
	wait := wd.OverlayProbeWait
	if wait <= 0 {
		wait = 4
	}
	targets := append(append(append([]string{},
		wd.OverlayProbeTargets...),
		wd.OverlayProbeMarkers...),
		wd.OverlaySiteMarkers...)
	results := map[string]PingResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Go(func() {
			ok, rtt := n.Ping(ctx, t, count, wait, false)
			mu.Lock()
			results[t] = PingResult{ok, rtt}
			mu.Unlock()
		})
	}
	wg.Wait()
	return targets, results
}

// AggregateNebulaOverlay folds the fanout results into per-class
// counts + dead-peer sets + the slowpath/siteedge evidence lists.
// Exported: the parent's tests drive the aggregation directly.
func AggregateNebulaOverlay(wd *watchdogconf.Config,
	results map[string]PingResult) *NebulaOverlayStats {

	st := &NebulaOverlayStats{}
	for _, t := range wd.OverlayProbeTargets {
		st.dpTotal++
		if results[t].Ok {
			st.dpAlive++
		} else {
			st.deadUnderlay = append(st.deadUnderlay, t)
		}
	}
	slowSet := map[string]bool{}
	for _, t := range wd.OverlaySlowpathMarkers {
		slowSet[t] = true
	}
	for _, t := range wd.OverlayProbeMarkers {
		st.mkTotal++
		r := results[t]
		if !r.Ok {
			st.deadOverlay = append(st.deadOverlay, t)
			continue
		}
		st.mkAlive++
		if slowSet[t] && r.Rtt >= 0 && r.Rtt > wd.OverlaySlowpathRTTms {
			st.slowpath = append(st.slowpath,
				fmt.Sprintf("%s=%.1fms", t, r.Rtt))
		}
	}
	for _, t := range wd.OverlaySiteMarkers {
		r := results[t]
		if !r.Ok {
			st.siteedge = append(st.siteedge, t+"=dead")
			st.deadOverlay = append(st.deadOverlay, t)
			continue
		}
		if r.Rtt >= 0 && r.Rtt > wd.OverlaySiteedgeRTTms {
			st.siteedge = append(st.siteedge,
				fmt.Sprintf("%s=%.1fms", t, r.Rtt))
		}
	}
	return st
}

// LatchNebulaOverlayPaths applies the path-quality evidence
// latches — slowpath and siteedge arm on first detection (a lost
// site edge is urgent evidence) while the degraded/isolated
// verdicts live in nebulaOverlayVerdict.
func (n *Deps) LatchNebulaOverlayPaths(wd *watchdogconf.Config,
	st *NebulaOverlayStats) {

	if len(st.slowpath) > 0 {
		n.State.SuspectLog(latchdefs.LatchNebulaSlowpath, "suspect: "+
			latchdefs.ReasonNebulaDataplaneSlowpath+" (reroute via remote site) "+
			strings.Join(st.slowpath, " "), suspectLogCadence)
		n.State.Enter(latchdefs.LatchNebulaSlowpath, strings.Join(st.slowpath, " "))
	} else {
		n.StateExit(latchdefs.LatchNebulaSlowpath)
	}
	if len(wd.OverlaySiteMarkers) > 0 {
		if len(st.siteedge) > 0 {
			// SiteedgeRun is the nebula-conntrack-flush confirmation
			// counter the per-peer flush waits on — same
			// ConsecNeeded gate the degraded path carries.
			n.SiteedgeRun++
			n.State.SuspectLog(latchdefs.LatchNebulaSiteedge, "suspect: "+
				latchdefs.ReasonNebulaSiteedgeDegraded+" (site-mesh edge lost) "+
				strings.Join(st.siteedge, " "), suspectLogCadence)
			n.State.Enter(latchdefs.LatchNebulaSiteedge, strings.Join(st.siteedge, " "))
		} else {
			n.SiteedgeRun = 0
			n.StateExit(latchdefs.LatchNebulaSiteedge)
		}
	} else {
		n.SiteedgeRun = 0
	}
}

// NebulaOverlayVerdict is the isolated/degraded/healthy switch —
// returns the failure reason + dpFail flag (which failure counter
// owns the streak) + whether the dataplane is fully isolated (the
// dead-peer flush gate).
func (n *Deps) NebulaOverlayVerdict(ctx context.Context,
	wd *watchdogconf.Config, st *NebulaOverlayStats) (reason string,
	dpFail, isolated bool) {

	switch {
	case (st.dpTotal > 0 && st.dpAlive == 0) ||
		(st.mkTotal > 0 && st.mkAlive == 0):
		reason = fmt.Sprintf("nebula-dataplane-dead pub=%d/%d marker=%d/%d",
			st.dpAlive, st.dpTotal, st.mkAlive, st.mkTotal)
		dpFail = true
		isolated = true
		n.NebulaDeg = 0
		n.StateExit(latchdefs.LatchNebulaDegraded)
		if !n.State.Exists(latchdefs.LatchNebulaIsolated) {
			// B3: on the isolation edge the conntrack entries
			// learned on the dead path keep the tunnel blackholed
			// — drop each affected peer's udp/<nebula-port>
			// entries to force re-handshake immediately. The peer
			// set is the FULL known set on purpose: whole-node
			// isolation means every peer's conntrack is stale.
			// NB: the disk latch means the edge won't refire
			// after an agent restart while already isolated —
			// acceptable (restart clears in-memory state but the
			// stale flows have long expired by then).
			n.FlushPeerNebulaConntrack(ctx, checkNebula, nebulaPeerUnderlayIPs(wd)...)
		}
		n.State.Enter(latchdefs.LatchNebulaIsolated, "dataplane dead")
	case st.dpTotal-st.dpAlive >= 2 || st.mkTotal-st.mkAlive >= 2:
		n.NebulaDeg++
		need := wd.NebulaDegradedConsec
		if need <= 0 {
			need = 2
		}
		n.State.SuspectLog(latchdefs.LatchNebulaDegraded, fmt.Sprintf(
			"suspect: "+latchdefs.ReasonNebulaDataplaneDegraded+
				" pub=%d/%d marker=%d/%d (run %d/%d)",
			st.dpAlive, st.dpTotal, st.mkAlive, st.mkTotal,
			n.NebulaDeg, need), suspectLogCadence)
		if n.NebulaDeg >= need {
			n.State.Enter(latchdefs.LatchNebulaDegraded, fmt.Sprintf(
				"pub=%d/%d marker=%d/%d",
				st.dpAlive, st.dpTotal, st.mkAlive, st.mkTotal))
		}
	default:
		n.NebulaDeg = 0
		n.StateExit(latchdefs.LatchNebulaDegraded)
		n.StateExit(latchdefs.LatchNebulaIsolated)
	}
	return reason, dpFail, isolated
}

// remediateNebulaOverlay runs the partial-death remediation —
// nebula-conntrack-flush evicts ONLY the dead peers' udp/<port>
// tuples (a live peer's flows are never touched), and the
// overlay-mtu-guard PMTU probe runs only when at least one
// overlay target answered the small pings.
func (n *Deps) remediateNebulaOverlay(ctx context.Context,
	wd *watchdogconf.Config, targets []string,
	results map[string]PingResult, st *NebulaOverlayStats,
	isolated bool) {

	// Only the degraded/siteedge (partial death) case applies
	// here — the dataplane-dead branch owns the all-dead
	// full-set flush already.
	if !isolated {
		n.flushDeadNebulaPeers(ctx, wd, st.deadUnderlay, st.deadOverlay)
	}
	// overlay-mtu-guard: small-packet pings can pass while a DF
	// probe at near-MTU size blackholes — the double-encap path
	// MTU sits below the overlay's. Total overlay failure belongs
	// to the isolated/degraded verdicts above, not to a PMTU latch.
	n.checkNebulaPMTU(ctx, targets, results)
}

// evalNebulaOverlay is the dataplane evaluation pipeline:
// aggregate → path latches → isolated/degraded verdict →
// partial-death remediation. Returns the failure reason + dpFail
// flag for the caller's restart/suspect tail.
func (n *Deps) evalNebulaOverlay(ctx context.Context,
	wd *watchdogconf.Config, targets []string,
	results map[string]PingResult) (reason string, dpFail bool) {

	st := AggregateNebulaOverlay(wd, results)
	n.LatchNebulaOverlayPaths(wd, st)
	reason, dpFail, isolated := n.NebulaOverlayVerdict(ctx, wd, st)
	n.remediateNebulaOverlay(ctx, wd, targets, results, st, isolated)
	return reason, dpFail
}

// flushDeadNebulaPeers — nebula-conntrack-flush: the targeted per-peer conntrack
// eviction for the degraded/siteedge verdicts. Dead
// OVERLAY_PROBE_TARGETS are already underlay/public IPs (the -d/-s
// tuples conntrack records); dead markers are overlay addresses
// conntrack never sees — they must be resolved through the
// static_host_map before eviction, and an unresolvable marker is
// skipped rather than guessed (flushing an overlay IP would hit
// nothing anyway, but guessing wrong could evict a LIVE peer's
// flows — the exact harm this remediation exists to avoid).
//
// The flush only fires on a CONFIRMED verdict — the degraded latch
// (which carries its own NebulaDegradedConsec gate) or
// SiteedgeRun >= ConsecNeeded — under the 5m
// last-nebula-degraded-ct-flush budget. nebula.service is never
// restarted here: a half-alive mesh must not lose its working
// tunnels.
func (n *Deps) flushDeadNebulaPeers(ctx context.Context,
	wd *watchdogconf.Config, deadUnderlay, deadOverlay []string) {
	confirmed := n.State.Exists(latchdefs.LatchNebulaDegraded) ||
		n.SiteedgeRun >= n.ConsecNeeded()
	if !confirmed || (len(deadUnderlay) == 0 && len(deadOverlay) == 0) {
		return
	}
	peers := append([]string{}, deadUnderlay...)
	staticMap := n.NebulaUnderlayPeers(wd.NebulaNet)
	var unresolved []string
	for _, ov := range deadOverlay {
		if under, ok := staticMap[ov]; ok && len(under) > 0 {
			peers = append(peers, under...)
		} else {
			unresolved = append(unresolved, ov)
		}
	}
	if len(unresolved) > 0 {
		n.State.SuspectLog("nebula-dead-peer-resolve", fmt.Sprintf(
			"suspect: dead overlay peers %s have no static_host_map underlay — conntrack flush skipped for them",
			strings.Join(unresolved, " ")), suspectLogCadence)
	}
	if len(peers) == 0 {
		return
	}
	if !n.State.RateTrySpend("last-nebula-degraded-ct-flush",
		nebulaDegradedCTFlushInterval) {
		n.State.SuspectLog("nebula-degraded-ct-flush",
			"suspect: dead-peer conntrack flush in cooldown (<5m), skip",
			suspectLogCadence)
		return
	}
	// FlushPeerNebulaConntrack does the per-peer -d AND -s delete
	// and logs the ACTION line per peer.
	n.FlushPeerNebulaConntrack(ctx, checkNebula, peers...)
}

// nebulaPeerUnderlayIPs returns the peer underlay IPs the watchdog
// conf knows about — OVERLAY_PROBE_TARGETS (remote public IPs probed
// through the tunnel) plus OVERLAY_EGRESS_RELAYS (relay peers). These
// are the -d destinations conntrack records for udp/<nebula-port>
// flows; marker IPs are overlay addresses conntrack never sees.
func nebulaPeerUnderlayIPs(wd *watchdogconf.Config) []string {
	out := append([]string{}, wd.OverlayProbeTargets...)
	return append(out, wd.OverlayEgressRelays...)
}

// NebulaUnderlayPeers maps overlay marker IPs to the underlay IPs
// declared for them in /etc/nebula/<net>/*.yaml static_host_map —
// the '"10.8.x.y": ["1.2.3.4:45670"]' entries. Conntrack records only
// the underlay tuple, so a dead overlay peer must be resolved
// through this table before its udp/<port> entries can be evicted.
// Unreadable/missing files yield an empty map — markers stay
// unresolved, never guessed.
func (n *Deps) NebulaUnderlayPeers(netName string) map[string][]string {
	out := map[string][]string{}
	if netName == "" {
		return out
	}
	files, err := filepath.Glob(filepath.Join(
		n.HostRoot(), "etc/nebula", netName, "*.yaml"))
	if err != nil {
		return out
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			StaticHostMap map[string][]string `yaml:"static_host_map"`
		}
		if err := yaml3.Unmarshal(data, &doc); err != nil {
			n.State.SuspectLog("nebula-staticmap-parse", fmt.Sprintf(
				"nebula-health: %s static_host_map parse failed: %v — dead-marker conntrack flush partially blind",
				f, err), suspectLogCadence)
			continue
		}
		for overlay, addrs := range doc.StaticHostMap {
			for _, a := range addrs {
				if ip := UnderlayHost(a); ip != "" {
					out[overlay] = append(out[overlay], ip)
				}
			}
		}
	}
	return out
}

// UnderlayHost extracts the IP half of a static_host_map endpoint
// ("1.2.3.4:45670", "[v6]:port", or a bare IP) — the host part is
// all the conntrack -d/-s selectors need.
func UnderlayHost(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	// No port (or an unbracketed IPv6): treat the token as the
	// host itself.
	return strings.Trim(a, "[]")
}
