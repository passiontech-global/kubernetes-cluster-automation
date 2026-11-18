// runtime_inotify_kcmp_internal_test.go — package-internal coverage for
// the KCMP_FILE OFD dedup's hard-cap regression: a RUID holding more
// than 512 distinct inotify open file descriptions must still dedup a
// fork-shared duplicate of any keeper, and the watch-count bucket must
// stay a sound pre-filter (same OFD ⇒ same fdinfo watch count).
package runtime

import "testing"

// TestDedupRUIDEntriesKCMPBeyond512 pins the >512-OFD dedup: 600
// distinct OFDs plus a fork-duplicate of one PAST the old 512-keeper
// cut must collapse to 600, not 601. The old flat cap stopped
// comparing at 512 keepers, so the late duplicate slipped through and
// inflated the per-RUID instance count.
func TestDedupRUIDEntriesKCMPBeyond512(t *testing.T) {
	const unique = 600
	const dupPID = 9999
	// The duplicate shares the OFD of the 550th unique entry (index
	// 549) — deliberately beyond the retired 512-keeper limit.
	dupOfPID := 200 + 549

	entries := make([]inotifyRUIDEntry, 0, unique+1)
	for i := 0; i < unique; i++ {
		entries = append(entries, inotifyRUIDEntry{
			pid: 200 + i, fdNum: 3, watches: 0,
		})
	}
	entries = append(entries, inotifyRUIDEntry{
		pid: dupPID, fdNum: 3, watches: 0,
	})

	// OFD identity is the pid, except the fork duplicate maps onto
	// dupOfPID — kcmp would report equality for that pair alone.
	ofdPID := func(pid int) int {
		if pid == dupPID {
			return dupOfPID
		}
		return pid
	}
	sameOFD := func(pidA, fdA, pidB, fdB int) bool {
		return ofdPID(pidA) == ofdPID(pidB)
	}

	got := dedupRUIDEntriesKCMP(entries, sameOFD)
	if len(got) != unique {
		t.Fatalf("deduped=%d want %d (duplicate past the 512 cut was missed)",
			len(got), unique)
	}

	// The bucketing pre-filter must never merge DISTINCT OFDs that
	// merely share a watch count.
	allDistinct := dedupRUIDEntriesKCMP(entries,
		func(_, _, _, _ int) bool { return false })
	if len(allDistinct) != unique+1 {
		t.Fatalf("distinct-OFD dedup=%d want %d", len(allDistinct), unique+1)
	}
}

// TestDedupRUIDEntriesKCMPSkipsOtherWatchBuckets proves the
// watch-count pre-filter: entries with different watch counts cannot
// be the same OFD, so sameOFD is never called for them.
func TestDedupRUIDEntriesKCMPSkipsOtherWatchBuckets(t *testing.T) {
	calls := 0
	got := dedupRUIDEntriesKCMP([]inotifyRUIDEntry{
		{pid: 1, fdNum: 3, watches: 2},
		{pid: 2, fdNum: 3, watches: 7},
	}, func(_, _, _, _ int) bool {
		calls++
		return true
	})
	if calls != 0 {
		t.Fatalf("sameOFD called %d times across distinct watch buckets", calls)
	}
	if len(got) != 2 {
		t.Fatalf("dedup across buckets=%d want 2", len(got))
	}
}
