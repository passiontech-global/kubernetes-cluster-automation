// neighbor.go — the /proc/net neighbor-table views the
// kernelfail neighbor-pressure healer (P0.4) reads: the IPv4 ARP
// table (/proc/<pid>/net/arp — or the host-netns /proc/1/net/arp
// the agent's hostPID view exposes) with per-entry flags decoded
// into NUD states, and the ndisc_cache statistics file
// (/proc/<pid>/net/stat/ndisc_cache) carrying the IPv6 table size
// plus the table_fulls overflow counter.
//
// Column layout contracts (stable since 2.6):
//
//	arp:      IP address  HW type  Flags  HW address  Mask  Device
//	ndisc:    one header row naming the hex counter columns
//	          (entries … table_fulls), then one row per CPU/bucket
//
// The parsers are deliberately tolerant — a truncated or
// headerless file returns ok=false (inconclusive), never a
// fabricated zero the healer could bump sysctls against.
package procfs

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"
)

// NUDState is the flags bitmask decoded from /proc/net/arp's Flags column
// (include/uapi/linux/if_arp.h ATF_* values: 0x02=ATF_COM complete,
// 0x04=ATF_PERM permanent, 0x08=ATF_PUBL published — note /proc/net/arp does
// not distinguish REACHABLE vs STALE, so netlink or `ip neigh` owns NUD_*).
type NUDState uint8

const (
	NUDNone       NUDState = 0x00 // incomplete / no ATF_COM flag
	NUDIncomplete NUDState = 0x01
	NUDReachable  NUDState = 0x02 // ATF_COM (0x02): resolved ARP entry
	NUDStale      NUDState = 0x04 // ATF_PERM alias kept for caller compat
	NUDDelay      NUDState = 0x08 // ATF_PUBL alias kept for caller compat
	NUDProbe      NUDState = 0x10
	NUDFailed     NUDState = 0x20
	NUDNoARP      NUDState = 0x40
	NUDPermanent  NUDState = 0x80

	// Accurate /proc/net/arp ATF_* flag constants (if_arp.h).
	ATFComplete  NUDState = 0x02 // ATF_COM
	ATFPermanent NUDState = 0x04 // ATF_PERM
	ATFPublished NUDState = 0x08 // ATF_PUBL
)

// ARPEntry is one /proc/net/arp row decoded far enough for the
// neighbor healer: the address, device and the raw ATF flags word
// (the NUD bits sit in the low byte).
type ARPEntry struct {
	IP     string
	HWType string
	Flags  uint64 // raw ATF_* flags as printed (hex)
	HWAddr string
	Mask   string
	Device string
	NUD    NUDState // Flags & 0xFF decoded
}

// ReadARPTable parses a /proc/net/arp-format file into entries.
// The header row is skipped; rows with fewer than 6 fields are
// dropped (never counted). ok=false when the file is unreadable or
// holds no header — an empty-but-valid table returns ok=true with
// zero entries.
func ReadARPTable(path string) ([]ARPEntry, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		// Header-only or empty — readable but no entries.
		return nil, len(lines) == 1
	}
	// Skip the header — the first line names the columns.
	out := make([]ARPEntry, 0, len(lines)-1)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 64)
		if err != nil {
			continue // unparseable flags → not evidence
		}
		out = append(out, ARPEntry{
			IP: f[0], HWType: f[1], Flags: flags,
			HWAddr: f[3], Mask: f[4], Device: f[5],
			NUD: NUDState(flags & 0xFF),
		})
	}
	return out, true
}

// NDISCStats is the IPv6 neighbor-table evidence row parsed out of
// /proc/net/stat/ndisc_cache: the live entry count (max across the
// per-bucket rows — rows disagree only transiently) and the
// cumulative table_fulls overflow counter (summed — each row is a
// per-CPU bucket).
type NDISCStats struct {
	Entries    int
	TableFulls uint64
}

// ReadNDISCStats parses /proc/net/stat/ndisc_cache. The file may
// carry one flat header or per-family sections ("arp_cache" /
// "ndisc_cache" name lines each followed by a named-column header
// and hex rows); columns are located BY NAME on whichever header
// line carries both "entries" and "table_fulls", and rows are
// accumulated under the most recent header's indices — kernel-
// added columns and section churn never shift the parse. Entries
// takes the max (a live gauge); table_fulls sums (a monotonic
// counter). ok=false on unreadable input or no usable header.
func ReadNDISCStats(path string) (NDISCStats, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NDISCStats{}, false
	}
	var st NDISCStats
	entIdx, fullIdx := -1, -1
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		// A header row names its columns — re-arm the indices on
		// every one so a second family's section re-bases the parse.
		ei, fi := -1, -1
		for i, name := range f {
			switch name {
			case "entries":
				ei = i
			case "table_fulls":
				fi = i
			}
		}
		if ei >= 0 && fi >= 0 {
			entIdx, fullIdx = ei, fi
			continue
		}
		if entIdx < 0 || fullIdx < 0 {
			continue // section-name / pre-header line
		}
		if entIdx < len(f) {
			if v, err := strconv.ParseUint(f[entIdx], 16, 32); err == nil &&
				int(v) > st.Entries {
				st.Entries = int(v)
			}
		}
		if fullIdx < len(f) {
			if v, err := strconv.ParseUint(f[fullIdx], 16, 64); err == nil {
				st.TableFulls += v
			}
		}
	}
	return st, entIdx >= 0 && fullIdx >= 0
}

// HexDecode is a small helper kept for callers that need raw hex
// column decoding outside the stats parser (tests, future NUD
// detail reads).
func HexDecode(s string) (uint64, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}
