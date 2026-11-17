// neighbor.go — neighbor-table updateNeighborTable (self-healing
// P1-#6): the ARP/IPv6-neighbor exhaustion healer.
//
// A node that churns pod IPs faster than the kernel's neighbor GC
// drains the table hits gc_thresh3 — every new neighbor allocation
// then fails and the kernel logs "neighbour: (arp|ndisc)_cache:
// neighbor table overflow", silently blackholing pod traffic. The
// healer has two triggers, either sufficient:
//
//   - Fill: live entries >= 80% of gc_thresh3, counted from the
//     host-netns proc views (Deps.NeighIPv4Table = /proc/1/net/arp
//     line count, Deps.NeighIPv6Stats = /proc/1/net/stat/
//     ndisc_cache "entries" column max).
//   - Overflow: a kmsg "neighbor table overflow" record —
//     noteNeighborOverflow marks the family pending so the next
//     tick bumps even below the fill threshold.
//
// The bump itself is rate-limited to one spend per family per 30m
// (Store.RateTrySpend — the conntrack bump parity): it doubles the
// gc_thresh{1,2,3} triplet capped at the configured ceilings
// (defaults 16384/65536/131072 — high enough for dense pod churn,
// low enough that a leaked-neighbor bug still surfaces as table
// pressure instead of unbounded memory), then flushes FAILED
// entries via `ip -4/-6 neigh flush nud failed` to hand the GC
// dead slots immediately.
//
// Linux ordering trap: the kernel EINVALs any gc_thresh write that
// breaks thresh1 <= thresh2 <= thresh3, so writes land in REVERSE
// order — gc_thresh3 first (raise the ceiling), then gc_thresh2,
// then gc_thresh1 — and each new value is additionally clamped to
// the value written before it so an odd current triplet can never
// produce an illegal intermediate state.
package kernelfail

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	// neighBumpEvery rate-limits the sysctl bump per family — table
	// pressure moves on minutes, not ticks.
	neighBumpEvery = 30 * time.Minute
	// neighFillRatio arms a bump once live entries reach 80% of
	// gc_thresh3 — early enough that the GC still has headroom.
	neighFillRatio = 0.80
	// neighPendingTTL bounds how long an overflow kmsg record stays
	// actionable. It must stay WELL under neighBumpEvery: an overflow
	// logged mid-cooldown would otherwise still be "pending" when
	// the 30m budget reopens and ratchet gc_thresh a second time for
	// pressure the table already recovered from. 10m keeps only
	// fresh overflow evidence eligible for a deferred bump — older
	// records expire and the fill-ratio path (still live) carries
	// any real ongoing pressure on its own.
	neighPendingTTL = 10 * time.Minute
	// neighFlushRatio arms the P0.4 flush pass once live entries
	// reach 85% of gc_thresh3 — later than the bump's 80% so the
	// sysctl raise gets first shot at draining pressure cheaply.
	neighFlushRatio = 0.85
	// neighFlushCeilingCooldown is the short budget for the
	// at-ceiling flush branch: once the table is AT gc_thresh3 the
	// next pod-IP recycle overflows immediately, so eviction gets a
	// 5m cadence instead of the normal flush cooldown.
	neighFlushCeilingCooldown = 5 * time.Minute
	// neighLatchEnterRatio/neighLatchExitRatio are the
	// NeighborTablePressure hysteresis band: the latch arms only
	// after two consecutive post-flush ticks still >= 92% of
	// gc_thresh3, and clears only when BOTH families read < 80%.
	neighLatchEnterRatio = 0.92
	neighLatchExitRatio  = 0.80
	// neighLatchTicks is the consecutive pinned-tick count the
	// latch needs before it arms.
	neighLatchTicks = 2
)

// Exported so hostmetrics' ConfigFromEnv can bind the env knobs to
// the same compiled defaults New() falls back to.
const (
	// P0.4 raises the whole gc_thresh triplet ceiling to
	// 16384/65536/131072 — the kernel's 1:4:8 ratio scaled past the
	// hostconfig sysctl floor (8192/32768/65536). Raising only
	// thresh3 would leave thresh1/thresh2 as "start GC early"
	// watermarks far below capacity, making the kernel churn GC on
	// every pod-IP recycle on a dense cluster.
	DefaultNeighGCThresh1Ceiling = 16384
	DefaultNeighGCThresh2Ceiling = 65536
	// DefaultNeighGCThresh3Ceiling is the P0.4 raise — dense
	// clusters churn pod IPs faster than the old 8192-entry ceiling
	// could GC, so the hard cap moves to the kernel's practical
	// maximum.
	DefaultNeighGCThresh3Ceiling = 131072
	// DefaultNeighFlushCeiling is the per-family fallback for the
	// flush-guard's gc_thresh3 override (Deps.NeighFlush*Ceiling) —
	// same 131072 the shared thresh3 ceiling now uses.
	DefaultNeighFlushCeiling = 131072
	// DefaultNeighFlushCooldown rate-limits the flush pass per
	// family — evictions are cheap but a flush storm on a genuinely
	// full table just re-fills on the next pod churn.
	DefaultNeighFlushCooldown = 30 * time.Minute
)

// neighTableView is one family's parsed proc-table evidence: the
// live entry count plus the family's table_fulls overflow counter
// (0 for families whose proc view carries no such column — IPv4
// ARP has none; its overflow evidence stays the kmsg record).
type neighTableView struct {
	entries    int
	tableFulls uint64
}

// neighFamily binds one IP family's sysctl dir, proc-table view,
// ip(8) flag and gc_thresh ceilings for the bump.
type neighFamily struct {
	name   string // "ipv4"/"ipv6" — the last-neigh-bump-<name> budget key
	ipFlag string // "-4"/"-6" for `ip neigh flush`
	sysDir string // gc_thresh{1,2,3} files (Deps.NeighIPv*Dir)
	table  string // proc table view (Deps.NeighIPv*Table/Stats)
	ceil   [3]int // gc_thresh{1,2,3} ceilings
	// entries parses the family's proc table view into the live
	// count + table_fulls (arpTableView for IPv4,
	// ndiscStatsView for IPv6).
	entries func(string) (neighTableView, bool)
	// fullsPath, when set, is a second proc view carrying the
	// family's table_fulls counter — IPv4 needs it because
	// /proc/net/arp (the NUD-state view the flush consumes)
	// exposes no overflow column; /proc/net/stat/arp_cache does.
	// IPv6 leaves it empty: its `table` IS the stat file.
	fullsPath string
}

// neighFamilies builds the per-tick family table off Deps — the
// ceilings were defaulted in New(). The flush-guard's per-family
// gc_thresh3 override (Deps.NeighFlush*Ceiling) replaces the
// shared thresh3 cap for that family only; 0 falls back to the
// shared DefaultNeighGCThresh3Ceiling.
func (r *Runner) neighFamilies() []neighFamily {
	v4ceil3, v6ceil3 := r.deps.NeighGCThresh3Ceiling,
		r.deps.NeighGCThresh3Ceiling
	if r.deps.NeighFlushArpCeiling > 0 {
		v4ceil3 = r.deps.NeighFlushArpCeiling
	}
	if r.deps.NeighFlushNdiscCeiling > 0 {
		v6ceil3 = r.deps.NeighFlushNdiscCeiling
	}
	return []neighFamily{
		{name: "ipv4", ipFlag: "-4",
			sysDir: r.deps.NeighIPv4Dir, table: r.deps.NeighIPv4Table,
			fullsPath: r.deps.NeighIPv4Stats,
			ceil: [3]int{r.deps.NeighGCThresh1Ceiling,
				r.deps.NeighGCThresh2Ceiling, v4ceil3},
			entries: arpTableView},
		{name: "ipv6", ipFlag: "-6",
			sysDir: r.deps.NeighIPv6Dir, table: r.deps.NeighIPv6Stats,
			ceil: [3]int{r.deps.NeighGCThresh1Ceiling,
				r.deps.NeighGCThresh2Ceiling, v6ceil3},
			entries: ndiscStatsView},
	}
}

// arpTableView counts live IPv4 neighbor entries — every non-header
// line of /proc/net/arp decoded through procfs.ReadARPTable (the
// NUD flags ride along for the flush guard's state-aware reads).
// INCOMPLETE entries still hold a neighbor slot, so they count too.
// ok=false when the file is unreadable — inconclusive, never a bump
// trigger.
func arpTableView(path string) (neighTableView, bool) {
	entries, ok := procfs.ReadARPTable(path)
	if !ok {
		return neighTableView{}, false
	}
	return neighTableView{entries: len(entries)}, true
}

// ndiscStatsView reads the IPv6 neighbor count AND the table_fulls
// overflow counter from /proc/net/stat/ndisc_cache via
// procfs.ReadNDISCStats — columns are located by name so kernel
// additions never shift the parse. ok=false on unreadable or
// headerless input.
func ndiscStatsView(path string) (neighTableView, bool) {
	st, ok := procfs.ReadNDISCStats(path)
	if !ok {
		return neighTableView{}, false
	}
	return neighTableView{entries: st.Entries, tableFulls: st.TableFulls}, true
}

// neighGCThresh reads one gc_thresh knob. ok=false on a missing or
// unparseable file — an unreadable sysctl dir makes the whole
// family inconclusive (never bump blind).
func neighGCThresh(dir, knob string) (uint64, bool) {
	v, ok := fsx.ReadUintFile(filepath.Join(dir, knob))
	return v, ok
}

// writeNeighGCThresh writes one gc_thresh knob — the sysctl file
// accepts a bare decimal; the kernel validates ordering on each
// write (hence the reverse-order bump in bumpNeighborGC).
func writeNeighGCThresh(dir, knob string, v uint64) error {
	return os.WriteFile(filepath.Join(dir, knob),
		[]byte(strconv.FormatUint(v, 10)+"\n"), 0o644)
}

// noteNeighborOverflow marks a family pending a bump — the kmsg
// "neighbor table overflow" record means the table is ALREADY
// full, so the next tick bumps regardless of the measured fill.
func (r *Runner) noteNeighborOverflow(msg string) {
	m := neighOverflowRe.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	fam := "ipv4"
	if m[1] == "ndisc" {
		fam = "ipv6"
	}
	if r.neigh == nil {
		r.neigh = map[string]time.Time{}
	}
	r.neigh[fam] = r.deps.Clock.Now()
	logger().Warn("hostmetrics: neighbor table overflow observed",
		"family", fam)
}

// updateNeighborTable evaluates both families once per tick: bump
// when fill >= 80% of gc_thresh3 or an overflow record is pending,
// rate-limited per family. Inconclusive reads (missing proc view,
// unreadable sysctl) skip the family entirely — never bump blind.
//
// Wave-2 (P0.4) additions on top of the bump path:
//
//   - table_fulls: the family's cumulative overflow counter (IPv6
//     via /proc/net/stat/ndisc_cache; IPv4 ARP exposes none) — a
//     positive delta marks the family pending exactly like a kmsg
//     overflow record, but the evidence persists across ticks.
//   - flush guard (Deps.NeighFlushGuard): on flush-grade evidence
//     (fill >= 85% of gc_thresh3, the table AT gc_thresh3, or fresh
//     overflow evidence), a separate last-neigh-flush-<fam> budget
//     runs `ip neigh flush nud {failed,stale,reachable}` per the
//     evict knobs — the at-ceiling branch on a 5m budget, the rest
//     on NeighFlushCooldown — then re-reads the table for the
//     latch hysteresis (updateNeighborLatch).
func (r *Runner) updateNeighborTable(ctx context.Context) {
	now := r.deps.Clock.Now()
	fills := map[string]float64{}
	for _, fam := range r.neighFamilies() {
		view, ok := fam.entries(fam.table)
		if !ok {
			continue
		}
		// Second-source table_fulls (IPv4's arp_cache stat view):
		// bonus overflow evidence — an unreadable stats file just
		// leaves the counter at 0, never blocks the family.
		if fam.fullsPath != "" {
			if st, sok := procfs.ReadNDISCStats(fam.fullsPath); sok {
				view.tableFulls = st.TableFulls
			}
		}
		entries := view.entries
		thresh3, ok := neighGCThresh(fam.sysDir, "gc_thresh3")
		if !ok || thresh3 == 0 {
			continue
		}
		fill := float64(entries) / float64(thresh3)
		fills[fam.name] = fill
		// table_fulls delta → pending overflow evidence. The first
		// read seeds the baseline (the counter is cumulative since
		// boot — a fresh Runner must not treat the whole history
		// as one giant delta).
		fullsDelta := false
		if r.deps.NeighFlushTableFulls && view.tableFulls > 0 {
			if r.neighFulls == nil {
				r.neighFulls = map[string]uint64{}
			}
			if last, seen := r.neighFulls[fam.name]; seen &&
				view.tableFulls > last {
				fullsDelta = true
			}
			r.neighFulls[fam.name] = view.tableFulls
		}
		// Pending overflow evidence expires after neighPendingTTL —
		// an overflow logged mid-cooldown must not arm a bump once
		// the table has had a full window to recover on its own.
		pendingAt, pending := r.neigh[fam.name]
		if pending && now.Sub(pendingAt) >= neighPendingTTL {
			delete(r.neigh, fam.name)
			pending = false
		}
		if fullsDelta {
			// Mark pending like noteNeighborOverflow does — the
			// delta is fresh evidence, so re-stamp the timestamp.
			if r.neigh == nil {
				r.neigh = map[string]time.Time{}
			}
			r.neigh[fam.name] = now
			pending = true
		}
		pressured := fill >= neighFillRatio || pending
		if pressured {
			// RateTrySpend not RateOK+RateSpend: check-and-spend must
			// be one atomic budget decision (the conntrack parity).
			if r.deps.Store.RateTrySpend("last-neigh-bump-"+fam.name, neighBumpEvery) {
				r.bumpNeighborGC(ctx, fam, entries, thresh3)
				delete(r.neigh, fam.name)
			}
		}
		// P0.4 flush guard — returns the post-flush fill (or -1
		// when no flush ran / the re-read was inconclusive) so the
		// latch hysteresis below sees post-eviction evidence.
		if postFill := r.maybeFlushNeighbor(ctx, fam, view, fill,
			pending, thresh3); postFill >= 0 {
			fills[fam.name] = postFill
			fill = postFill
		}
		if r.neighPinned == nil {
			r.neighPinned = map[string]int{}
		}
		if fill >= neighLatchEnterRatio {
			r.neighPinned[fam.name]++
		} else {
			r.neighPinned[fam.name] = 0
		}
	}
	r.updateNeighborLatch(fills)
}

// updateNeighborLatch applies the P0.4 hysteresis to the shared
// NeighborTablePressure latch: arm after neighLatchTicks
// consecutive ticks with a family still >= neighLatchEnterRatio
// of gc_thresh3, clear only when EVERY readable family sits below
// neighLatchExitRatio — the band between the two ratios keeps the
// prior state so a borderline table cannot flap the condition.
// fills only carries families whose proc view AND gc_thresh3 read
// succeeded this tick; an all-inconclusive sweep keeps state.
func (r *Runner) updateNeighborLatch(fills map[string]float64) {
	if !r.deps.NeighFlushGuard {
		// Guard off → the latch must still clear (an operator who
		// disables the guard shouldn't inherit a stuck condition).
		r.deps.Store.Exit(latchdefs.LatchNeighborPressure, nil)
		return
	}
	if len(fills) == 0 {
		return
	}
	pinned := false
	for _, n := range r.neighPinned {
		if n >= neighLatchTicks {
			pinned = true
			break
		}
	}
	low := true
	for _, f := range fills {
		if f >= neighLatchExitRatio {
			low = false
			break
		}
	}
	switch {
	case pinned:
		r.deps.Store.Enter(latchdefs.LatchNeighborPressure, "pinned")
	case low:
		r.deps.Store.Exit(latchdefs.LatchNeighborPressure, nil)
	}
}

// maybeFlushNeighbor is the P0.4 flush guard: it spends the
// last-neigh-flush-<fam> budget and evicts the configured NUD
// states — `nud failed` and `nud stale` by default, `nud reachable`
// only on explicit opt-in (it drops live neighbors) — when the
// family shows flush-grade evidence: fill >= neighFlushRatio (85%
// of gc_thresh3), the table sitting AT gc_thresh3, or fresh
// overflow evidence (pending kmsg / table_fulls delta). The
// at-ceiling branch runs on the short neighFlushCeilingCooldown
// budget; every other branch uses the configured
// NeighFlushCooldown. Returns the post-flush fill ratio, or -1
// when no flush ran or the re-read was inconclusive — the caller
// feeds it into the latch hysteresis.
func (r *Runner) maybeFlushNeighbor(ctx context.Context, fam neighFamily,
	view neighTableView, fill float64, pending bool, thresh3 uint64) float64 {

	if !r.deps.NeighFlushGuard {
		return -1
	}
	atCeiling := float64(view.entries) >= float64(thresh3)
	if fill < neighFlushRatio && !atCeiling && !pending {
		return -1 // below flush grade — nothing to evict for
	}
	cooldown := r.deps.NeighFlushCooldown
	if cooldown <= 0 {
		cooldown = DefaultNeighFlushCooldown
	}
	if atCeiling && cooldown > neighFlushCeilingCooldown {
		cooldown = neighFlushCeilingCooldown
	}
	if !r.deps.Store.RateTrySpend("last-neigh-flush-"+fam.name, cooldown) {
		return -1 // flush on cooldown — caller keeps prior fill
	}
	var flushed []string
	for _, spec := range []struct {
		on  bool
		nud string
	}{
		{r.deps.NeighFlushEvictNudFailed, "failed"},
		{r.deps.NeighFlushEvictStale, "stale"},
		{r.deps.NeighFlushEvictReachable, "reachable"},
	} {
		if !spec.on {
			continue
		}
		if _, err := r.deps.RunHostCmd(ctx,
			"ip", fam.ipFlag, "neigh", "flush", "nud", spec.nud); err != nil {
			logger().Warn("neighbor: ip neigh flush failed",
				"family", fam.name, "nud", spec.nud, "error", err)
			continue
		}
		flushed = append(flushed, spec.nud)
	}
	if len(flushed) == 0 {
		return -1
	}
	logger().Info("neighbor: flush guard evicted entries",
		"family", fam.name, "nud", strings.Join(flushed, ","))
	// Post-flush re-read — the caller's latch hysteresis needs the
	// post-eviction fill, not the pre-flush one.
	post, ok := fam.entries(fam.table)
	if !ok {
		return -1 // inconclusive — keep prior fill
	}
	post3, ok := neighGCThresh(fam.sysDir, "gc_thresh3")
	if !ok || post3 == 0 {
		return -1
	}
	postFill := float64(post.entries) / float64(post3)
	if postFill >= neighLatchEnterRatio {
		logger().Warn("hostmetrics: neighbor table still pinned after flush",
			"family", fam.name, "entries", post.entries, "thresh3", post3)
	}
	return postFill
}

// neighBumpTriplet computes the doubled gc_thresh{1,2,3} values —
// each knob doubles capped at BOTH its own ceiling and the value
// computed for the knob above it, so the result always satisfies
// thresh1 <= thresh2 <= thresh3 even on an odd current triplet.
// Index order is [thresh1, thresh2, thresh3]; the caller writes in
// reverse (thresh3 first) per the kernel's ordering constraint.
func neighBumpTriplet(cur [3]uint64, ceil [3]int) [3]uint64 {
	next := [3]uint64{0, 0, 0}
	for i := 2; i >= 0; i-- {
		limit := uint64(ceil[i])
		if i < 2 && next[i+1] < limit {
			limit = next[i+1]
		}
		doubled := cur[i] * 2
		if doubled > limit {
			doubled = limit
		}
		if doubled < cur[i] {
			doubled = cur[i] // never shrink a knob
		}
		next[i] = doubled
	}
	return next
}

// bumpNeighborGC doubles the gc_thresh{1,2,3} triplet up to the
// family ceilings — writes land gc_thresh3 → gc_thresh2 → gc_thresh1
// so no intermediate state can violate thresh1 <= thresh2 <=
// thresh3 — then flushes FAILED neighbor entries so the GC reclaims
// dead slots immediately instead of waiting out reachable_time.
func (r *Runner) bumpNeighborGC(ctx context.Context, fam neighFamily,
	entries int, thresh3 uint64) {
	cur := [3]uint64{}
	knobs := [3]string{"gc_thresh1", "gc_thresh2", "gc_thresh3"}
	for i, knob := range knobs {
		v, ok := neighGCThresh(fam.sysDir, knob)
		if !ok {
			logger().Debug("neighbor: gc_thresh unreadable — bump skipped",
				"family", fam.name, "knob", knob)
			return
		}
		cur[i] = v
	}
	next := neighBumpTriplet(cur, fam.ceil)
	// Write order: thresh3 → thresh2 → thresh1 (knobs[2..0]).
	changed := false
	for i := 2; i >= 0; i-- {
		if next[i] == cur[i] {
			continue
		}
		if err := writeNeighGCThresh(fam.sysDir, knobs[i], next[i]); err != nil {
			logger().Warn("neighbor: gc_thresh write failed",
				"family", fam.name, "knob", knobs[i], "error", err)
			return
		}
		changed = true
	}
	// Flush FAILED entries — dead slots return to the free pool
	// now. A failed flush is a Warn, never fatal: the sysctl bump
	// already landed and still helps.
	if out, err := r.deps.RunHostCmd(ctx,
		"ip", fam.ipFlag, "neigh", "flush", "nud", "failed"); err != nil {
		logger().Warn("neighbor: ip neigh flush failed",
			"family", fam.name, "error", err)
	} else if strings.TrimSpace(out) != "" {
		logger().Info("neighbor: flushed FAILED entries",
			"family", fam.name, "output", strings.TrimSpace(out))
	}
	if changed {
		logger().Warn("hostmetrics: neighbor table pressure — bumped gc_thresh",
			"family", fam.name,
			"entries", entries, "thresh3", thresh3,
			"gc_thresh1", next[0], "gc_thresh2", next[1], "gc_thresh3", next[2])
	} else {
		logger().Info("neighbor: gc_thresh at ceiling — flush only",
			"family", fam.name, "entries", entries, "thresh3", thresh3)
	}
}
