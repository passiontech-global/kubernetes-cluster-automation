// nic_health.go — nic-health updateNICHealth (self-healing P1-#7):
// the physical-uplink degradation detector behind
// state-host-network-problems.
//
// Virtual interfaces (cilium/cali/veth/docker/nebula/wg/...) flap
// for mundane reasons — pod churn, overlay reconfiguration — so the
// check pins itself to the PHYSICAL default-route iface picked from
// /proc/net/route (lowest-metric non-virtual "00000000" destination
// entry). On that iface it tracks three signatures over sliding
// windows:
//
//   - carrier_changes delta >= NICCarrierFlapThreshold (default 4)
//     per 5m — the link itself is bouncing (cable/NIC/driver).
//   - NETDEV WATCHDOG "transmit queue N timed out" records >=
//     NICTxTimeoutThreshold (default 2) per 10m — the driver stopped
//     draining TX; the classic pre-failure of a dying NIC.
//   - rx_crc_errors + rx_frame_errors growth >= NICCRErrorThreshold
//     (default 50) in EACH of two consecutive 5m windows — sustained
//     physical-layer corruption, not a one-off burst.
//
// Any signature Enters state-host-network-problems with the firing
// detail as evidence; the latch Exits only after nicCleanHold (10m
// = two clean 5m windows) with no signature — a single quiet window
// never clears a real flap. Unresolvable inputs (no default route,
// unreadable counters) are inconclusive: they neither arm nor clear
// the latch.
package kernelfail

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// Path + window defaults (Deps seam values — tests re-point the
// paths at the fixture tree).
const (
	defaultSysClassNetDir = "/sys/class/net"

	// nicCarrierWindow is the trailing window carrier_changes and
	// the CRC/frame counters are diffed over.
	nicCarrierWindow = 5 * time.Minute
	// nicTxWindow is the trailing window NETDEV WATCHDOG TX-timeout
	// records are counted over.
	nicTxWindow = 10 * time.Minute
	// nicSampleRetention keeps enough counter history to diff the
	// two 5m CRC windows plus tick jitter.
	nicSampleRetention = 12 * time.Minute
	// nicCleanHold is the no-signature dwell before the latch Exits
	// — two consecutive clean 5m windows.
	nicCleanHold = 10 * time.Minute
)

// Exported so hostmetrics' ConfigFromEnv can bind the env knobs to
// the same compiled defaults New() falls back to.
const (
	DefaultNICCarrierFlapThreshold = 4
	DefaultNICTxTimeoutThreshold   = 2
	DefaultNICCRErrorThreshold     = 50
)

// nicState is the Runner-held cross-tick NIC evidence — the
// resolved uplink, its counter sample ring, the TX-timeout event
// stamps and the last signature time that drives the clean-hold
// exit.
type nicState struct {
	iface   string       // resolved physical uplink ("" = none)
	samples []nicSample  // (at, carrier, crcFrame) ring
	tx      []nicTxEvent // NETDEV WATCHDOG stamps per iface
	lastSig time.Time    // last tick a signature fired (zero = never)
}

// nicSample is one counter snapshot of the uplink iface.
type nicSample struct {
	at       time.Time
	carrier  uint64 // carrier_changes
	crcFrame uint64 // rx_crc_errors + rx_frame_errors
}

// nicTxEvent is one NETDEV WATCHDOG TX-timeout kmsg record.
type nicTxEvent struct {
	iface string
	at    time.Time
}

// nicVirtualPrefixes are the interface-name prefixes that mark a
// virtual datapath — overlay tunnels, CNI veth pairs, bridges and
// tunnels never carry the physical uplink's hardware evidence.
// "lo" is an exact match, handled separately.
var nicVirtualPrefixes = []string{
	"cilium_", "lxc", "cali", "veth", "nebula", "neb", "wg",
	"docker", "cni", "virbr", "flannel", "tailscale",
}

// isVirtualIface reports whether name is a virtual datapath — the
// physical-uplink pick must never land on one.
func isVirtualIface(name string) bool {
	if name == "lo" || name == "" {
		return true
	}
	for _, p := range nicVirtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// physicalUplinkIface picks the physical default-route iface from
// the host route table — the lowest-metric entry whose Destination
// is "00000000" (0.0.0.0) and whose name isn't virtual. "" when no
// physical uplink is visible (unparseable table, virt-only host) —
// inconclusive, never a latch verdict.
func physicalUplinkIface(routeFile string) string {
	f, err := os.Open(routeFile)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	best := ""
	bestMetric := int(^uint(0) >> 1)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// /proc/net/route columns: Iface Destination Gateway Flags
		// RefCnt Use Metric Mask MTU Window IRTT — hex fields.
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || fields[1] != "00000000" {
			continue
		}
		iface := fields[0]
		if isVirtualIface(iface) {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = iface, metric
		}
	}
	return best
}

// readNICCounters reads the uplink's carrier_changes and the summed
// rx_crc_errors+rx_frame_errors. ok=false when ANY source is
// unreadable — a partial read would fabricate a delta.
func readNICCounters(sysClassNetDir, iface string) (carrier, crcFrame uint64, ok bool) {
	c, okC := fsx.ReadUintFile(filepath.Join(sysClassNetDir, iface, "carrier_changes"))
	rc, okR := fsx.ReadUintFile(filepath.Join(sysClassNetDir, iface,
		"statistics", "rx_crc_errors"))
	rf, okF := fsx.ReadUintFile(filepath.Join(sysClassNetDir, iface,
		"statistics", "rx_frame_errors"))
	if !okC || !okR || !okF {
		return 0, 0, false
	}
	return c, rc + rf, true
}

// counterAtOrBefore returns the counter value of the newest sample
// at-or-before t — the window-base lookup. ok=false when no sample
// covers t (insufficient history — the signature stays unevaluated
// rather than reading as a false clean).
func counterAtOrBefore(samples []nicSample, t time.Time, pick func(nicSample) uint64) (uint64, bool) {
	var v uint64
	found := false
	for _, s := range samples {
		if s.at.After(t) {
			break
		}
		v, found = pick(s), true
	}
	return v, found
}

// nicSignature evaluates the three flap signatures at now and
// returns the evidence string of the first that fires ("" = clean).
// Insufficient sample history skips the counter signatures — a
// fresh agent must not read "no data" as "no flap".
func (r *Runner) nicSignature(now time.Time) string {
	nic := &r.nic
	if len(nic.samples) == 0 {
		return ""
	}
	cur := nic.samples[len(nic.samples)-1]

	// carrier_changes over the trailing 5m.
	if base, ok := counterAtOrBefore(nic.samples,
		now.Add(-nicCarrierWindow), func(s nicSample) uint64 { return s.carrier }); ok {
		if delta := int64(cur.carrier) - int64(base); delta >= 0 &&
			uint64(delta) >= uint64(r.deps.NICCarrierFlapThreshold) {
			return "carrier_changes delta " + strconv.FormatInt(delta, 10) +
				" per 5m on " + nic.iface
		}
	}
	// rx_crc+rx_frame: the delta must reach the threshold in EACH of
	// the two consecutive 5m windows — sustained corruption, not a
	// single burst.
	midT := now.Add(-nicCarrierWindow)
	oldT := now.Add(-2 * nicCarrierWindow)
	mid, okM := counterAtOrBefore(nic.samples, midT,
		func(s nicSample) uint64 { return s.crcFrame })
	old, okO := counterAtOrBefore(nic.samples, oldT,
		func(s nicSample) uint64 { return s.crcFrame })
	if okM && okO {
		d1 := int64(mid) - int64(old)
		d2 := int64(cur.crcFrame) - int64(mid)
		thr := int64(r.deps.NICCRErrorThreshold)
		if d1 >= 0 && d2 >= 0 && d1 >= thr && d2 >= thr {
			return "rx_crc+rx_frame errors " + strconv.FormatInt(d1+d2, 10) +
				" over 10m on " + nic.iface
		}
	}
	// NETDEV WATCHDOG TX timeouts on THIS iface within 10m.
	txCount := 0
	for _, ev := range nic.tx {
		if ev.iface == nic.iface && now.Sub(ev.at) <= nicTxWindow {
			txCount++
		}
	}
	if txCount >= r.deps.NICTxTimeoutThreshold {
		return "NETDEV WATCHDOG TX timeouts " + strconv.Itoa(txCount) +
			" per 10m on " + nic.iface
	}
	return ""
}

// nicCovered reports whether the sample ring reaches back at least
// window — the exit path requires real coverage before a quiet
// stretch may count toward the clean hold (a fresh agent's empty
// ring must not instantly "prove" the link healthy).
func (r *Runner) nicCovered(now time.Time, window time.Duration) bool {
	if len(r.nic.samples) == 0 {
		return false
	}
	return now.Sub(r.nic.samples[0].at) >= window
}

// noteNetdevTxTimeout records one NETDEV WATCHDOG TX-timeout kmsg
// record — nicSignature counts them per uplink iface. The record
// is kept even before the uplink resolves: iface matching happens
// at evaluation time.
func (r *Runner) noteNetdevTxTimeout(msg string) {
	iface := ""
	if m := netdevTxTimeoutRe.FindStringSubmatch(msg); m != nil {
		iface = m[1]
	}
	now := r.deps.Clock.Now()
	r.nic.tx = append(r.nic.tx, nicTxEvent{iface: iface, at: now})
	// Bound the ring between ticks — a TX-timeout flood must not
	// grow it unboundedly.
	cutoff := now.Add(-nicTxWindow)
	kept := r.nic.tx[:0]
	for _, ev := range r.nic.tx {
		if ev.at.After(cutoff) {
			kept = append(kept, ev)
		}
	}
	r.nic.tx = kept
}

// updateNICHealth runs one evaluation tick: resolve the physical
// uplink, append the counter sample, evaluate the signatures and
// move state-host-network-problems. Inconclusive inputs return
// early — they neither arm nor clear the latch.
func (r *Runner) updateNICHealth() {
	now := r.deps.Clock.Now()
	iface := physicalUplinkIface(r.deps.RouteFile)
	if iface == "" {
		return // no physical uplink visible — inconclusive
	}
	if r.nic.iface != iface {
		// Uplink changed — counter baselines belong to the old
		// iface; reset the ring so deltas never span the swap. The
		// TX-timeout stamps survive: they are per-iface keyed and a
		// flap onto a different uplink must not erase its watchdog
		// history.
		tx := r.nic.tx
		r.nic = nicState{iface: iface, tx: tx}
	}
	carrier, crcFrame, ok := readNICCounters(r.deps.SysClassNetDir, iface)
	if !ok {
		return // counters unreadable — inconclusive
	}
	r.nic.samples = append(r.nic.samples, nicSample{
		at: now, carrier: carrier, crcFrame: crcFrame})
	// Prune to the retention window — oldest first.
	cutoff := now.Add(-nicSampleRetention)
	first := 0
	for first < len(r.nic.samples) && r.nic.samples[first].at.Before(cutoff) {
		first++
	}
	r.nic.samples = r.nic.samples[first:]

	if sig := r.nicSignature(now); sig != "" {
		r.nic.lastSig = now
		r.deps.Store.Enter(latchdefs.LatchHostNetworkProblems, sig)
		return
	}
	if !r.deps.Store.Exists(latchdefs.LatchHostNetworkProblems) {
		return
	}
	// Exit path: the latch is held and this tick is clean. Require
	// real window coverage, then the two-clean-window hold — and a
	// first-seen latch (post-restart) gets the same hold measured
	// from now rather than an instant release.
	if !r.nicCovered(now, nicCarrierWindow) {
		return
	}
	if r.nic.lastSig.IsZero() {
		r.nic.lastSig = now
		return
	}
	if now.Sub(r.nic.lastSig) >= nicCleanHold {
		r.deps.Store.Exit(latchdefs.LatchHostNetworkProblems, nil)
	}
}
