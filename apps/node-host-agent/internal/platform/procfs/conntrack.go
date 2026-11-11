// conntrack.go — the /proc/net/stat/nf_conntrack per-CPU counter
// parser shared by its two consumers: nethealth's conntrack-port-
// pressure spike detector (per-cycle insert_failed/drop deltas) and
// hostmetrics' conntrack-arp-pressure gauges. One read + one parse
// feeds both; the twin parsers this replaces (nethealth's
// conntrackStatSum, hostmetrics' conntrackStatCounters) differed
// only in return shape, so both collapsed into this one — and the
// nethealth cycle, which used to read the file twice per pass
// (combined pressure sum, then insert_failed alone), now reads it
// once.
package procfs

import (
	"os"
	"strconv"
	"strings"
)

// ConntrackStat is one parsed nf_conntrack stat table: the named
// columns summed across all CPU rows (the kernel writes HEX values,
// one row per CPU, under a header of column names).
//
// A column absent from the header (older kernel) leaves its sum at 0
// AND its Has* flag false — consumers gate emission on the flag: a
// fabricated 0 would read as "counter never fired" on a kernel that
// never counted it.
type ConntrackStat struct {
	InsertFailed  uint64 // refused NEW flow inserts (tuple collisions)
	Drop          uint64 // packets conntrack refused outright
	EarlyDrop     uint64 // LRU evictions that still lost the flow
	SearchRestart uint64 // hash-chain contention lookups restarted
	Invalid       uint64 // packets rejected by protocol-state checks

	HasInsertFailed  bool
	HasDrop          bool
	HasEarlyDrop     bool
	HasSearchRestart bool
	HasInvalid       bool
}

// ReadConntrackStat reads + parses path — ok=false when the file is
// unreadable, too short to be a per-CPU table (header + rows), or
// its header carries none of the tracked columns (conntrack module
// absent → detector idles / gauges stay absent, never a fake 0). A
// malformed CPU row (field count ≠ header) is skipped whole — never
// count junk; a cell that doesn't parse as HEX contributes nothing.
func ReadConntrackStat(path string) (ConntrackStat, bool) {
	var s ConntrackStat
	data, err := os.ReadFile(path)
	if err != nil {
		return s, false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return s, false
	}
	header := strings.Fields(lines[0])
	// Column → index map, scanned for the fixed column set — the
	// LAST header occurrence wins (same overwrite walk the twin
	// parsers ran for their caller-supplied key lists).
	idx := map[string]int{}
	for _, want := range [...]string{
		"insert_failed", "drop", "early_drop", "search_restart", "invalid",
	} {
		for i, name := range header {
			if name == want {
				idx[want] = i
			}
		}
	}
	if len(idx) == 0 {
		return s, false
	}
	sums := map[string]uint64{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != len(header) {
			continue // malformed CPU row — skip, never count junk
		}
		for name, i := range idx {
			if v, err := strconv.ParseUint(f[i], 16, 64); err == nil {
				sums[name] += v
			}
		}
	}
	s.InsertFailed = sums["insert_failed"]
	s.Drop = sums["drop"]
	s.EarlyDrop = sums["early_drop"]
	s.SearchRestart = sums["search_restart"]
	s.Invalid = sums["invalid"]
	// Presence = the header carried the column — set from idx, NOT
	// from parse success (a column of unparseable cells still
	// existed; the twins likewise reported ok with a zero sum).
	_, s.HasInsertFailed = idx["insert_failed"]
	_, s.HasDrop = idx["drop"]
	_, s.HasEarlyDrop = idx["early_drop"]
	_, s.HasSearchRestart = idx["search_restart"]
	_, s.HasInvalid = idx["invalid"]
	return s, true
}
