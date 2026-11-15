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
// (defaults 1024/4096/8192 — high enough for dense pod churn, low
// enough that a leaked-neighbor bug still surfaces as table
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
)

// Exported so hostmetrics' ConfigFromEnv can bind the env knobs to
// the same compiled defaults New() falls back to.
const (
	DefaultNeighGCThresh1Ceiling = 1024
	DefaultNeighGCThresh2Ceiling = 4096
	DefaultNeighGCThresh3Ceiling = 8192
)

// neighFamily binds one IP family's sysctl dir, proc-table view,
// ip(8) flag and gc_thresh ceilings for the bump.
type neighFamily struct {
	name   string // "ipv4"/"ipv6" — the last-neigh-bump-<name> budget key
	ipFlag string // "-4"/"-6" for `ip neigh flush`
	sysDir string // gc_thresh{1,2,3} files (Deps.NeighIPv*Dir)
	table  string // proc table view (Deps.NeighIPv*Table/Stats)
	ceil   [3]int // gc_thresh{1,2,3} ceilings
	// entries parses the family's proc table view into a live-entry
	// count (arpTableEntries for IPv4, ndiscCacheEntries for IPv6).
	entries func(string) (int, bool)
}

// neighFamilies builds the per-tick family table off Deps — the
// ceilings were defaulted in New().
func (r *Runner) neighFamilies() []neighFamily {
	return []neighFamily{
		{name: "ipv4", ipFlag: "-4",
			sysDir: r.deps.NeighIPv4Dir, table: r.deps.NeighIPv4Table,
			ceil: [3]int{r.deps.NeighGCThresh1Ceiling,
				r.deps.NeighGCThresh2Ceiling, r.deps.NeighGCThresh3Ceiling},
			entries: arpTableEntries},
		{name: "ipv6", ipFlag: "-6",
			sysDir: r.deps.NeighIPv6Dir, table: r.deps.NeighIPv6Stats,
			ceil: [3]int{r.deps.NeighGCThresh1Ceiling,
				r.deps.NeighGCThresh2Ceiling, r.deps.NeighGCThresh3Ceiling},
			entries: ndiscCacheEntries},
	}
}

// arpTableEntries counts live IPv4 neighbor entries — every
// non-header line of /proc/net/arp (INCOMPLETE entries still hold
// a neighbor slot, so they count too). ok=false when the file is
// unreadable — inconclusive, never a bump trigger.
func arpTableEntries(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 {
		return 0, false
	}
	// First line is the column header.
	return len(lines) - 1, true
}

// ndiscCacheEntries reads the IPv6 neighbor count from
// /proc/net/stat/ndisc_cache — a header line then one row of hex
// counters per CPU/histogram bucket whose FIRST column ("entries")
// carries the table size. Rows disagree only transiently, so the
// max is the safe read. ok=false on unreadable/unparseable input.
func ndiscCacheEntries(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var maxEntries int
	seenHeader := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !seenHeader {
			seenHeader = true // the "entries allocs ..." header row
			continue
		}
		v, err := strconv.ParseUint(f[0], 16, 32)
		if err != nil {
			continue
		}
		if int(v) > maxEntries {
			maxEntries = int(v)
		}
	}
	return maxEntries, seenHeader
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
func (r *Runner) updateNeighborTable(ctx context.Context) {
	now := r.deps.Clock.Now()
	for _, fam := range r.neighFamilies() {
		entries, ok := fam.entries(fam.table)
		if !ok {
			continue
		}
		thresh3, ok := neighGCThresh(fam.sysDir, "gc_thresh3")
		if !ok || thresh3 == 0 {
			continue
		}
		fill := float64(entries) / float64(thresh3)
		// Pending overflow evidence expires after neighPendingTTL —
		// an overflow logged mid-cooldown must not arm a bump once
		// the table has had a full window to recover on its own.
		pendingAt, pending := r.neigh[fam.name]
		if pending && now.Sub(pendingAt) >= neighPendingTTL {
			delete(r.neigh, fam.name)
			pending = false
		}
		if fill < neighFillRatio && !pending {
			continue
		}
		// RateTrySpend not RateOK+RateSpend: check-and-spend must
		// be one atomic budget decision (the conntrack parity).
		if !r.deps.Store.RateTrySpend("last-neigh-bump-"+fam.name, neighBumpEvery) {
			continue
		}
		r.bumpNeighborGC(ctx, fam, entries, thresh3)
		delete(r.neigh, fam.name)
	}
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
