// etcdguard_internal_test.go — in-package coverage for the unexported
// premaint-snapshot dir scan: the timestamp sort (files without a
// parsable unix stamp sort last) and the malformed-glob bail-out.
// External tests can't reach the unexported helper.
package etcd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The retention/verify code keys on premaintSnapshots order — the
// newest unix stamp must come first and a non-numeric stamp must
// never outrank a real one.
func TestPremaintSnapshotsNewestFirstJunkStampLast(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"premaint-100.db", "premaint-200.db", "premaint-notanumber.db",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("snap"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	for _, p := range premaintSnapshots(dir) {
		names = append(names, filepath.Base(p))
	}
	want := []string{"premaint-200.db", "premaint-100.db", "premaint-notanumber.db"}
	if !slices.Equal(names, want) {
		t.Fatalf("premaintSnapshots=%v want %v — unparsable stamps must sort last",
			names, want)
	}
}

// A dir name whose trailing '[' never closes the glob character class
// makes filepath.Glob report ErrBadPattern — the scan must return nil
// instead of panicking or inventing candidates.
func TestPremaintSnapshotsBadGlobPattern(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "odd[")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := premaintSnapshots(dir); got != nil {
		t.Fatalf("premaintSnapshots=%v want nil on a malformed glob pattern", got)
	}
}
