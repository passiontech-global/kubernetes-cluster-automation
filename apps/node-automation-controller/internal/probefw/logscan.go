// logscan.go — shared per-target log-scan watermark helpers so
// overlapping pod log tails across sweeps never re-flag or double-count
// log lines already scanned in a previous sweep.
package probefw

import "time"

// ReadLogScanAt returns the previously recorded scan watermark for key
// without modifying the map.
func ReadLogScanAt(m map[string]time.Time, key string) (prev time.Time, scanned bool) {
	if m == nil {
		return time.Time{}, false
	}
	prev, scanned = m[key]
	return prev, scanned
}

// AdvanceLogScanAt reads the previous scan boundary for key and
// advances the stored watermark to streamNewest (or fallbackNow when
// streamNewest is zero — e.g., when a tail carried no parseable
// timestamp). Call only after a successful log fetch so outages do
// not advance the watermark past unread log lines.
func AdvanceLogScanAt(m *map[string]time.Time, key string, streamNewest, fallbackNow time.Time) (prev time.Time, scanned bool) {
	if *m == nil {
		*m = map[string]time.Time{}
	}
	prev, scanned = (*m)[key]
	if streamNewest.IsZero() {
		(*m)[key] = fallbackNow
	} else {
		(*m)[key] = streamNewest
	}
	return prev, scanned
}

// PruneLogScanAt drops watermarks for keys no longer present in keep.
func PruneLogScanAt(m map[string]time.Time, keep map[string]bool) {
	for k := range m {
		if !keep[k] {
			delete(m, k)
		}
	}
}

// LogLineFresh reports whether a matched log line timestamp post-dates
// prevScan (or cannot be proven stale because scanned is false or
// lineTS is zero, failing toward alerting).
func LogLineFresh(scanned bool, lineTS, prevScan time.Time) bool {
	return !scanned || lineTS.IsZero() || lineTS.After(prevScan)
}
