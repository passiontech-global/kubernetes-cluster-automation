// walk.go — bounded regular-file byte walk shared across apps.
package fsx

import (
	"io/fs"
	"path/filepath"
)

// WalkBytesBounded sums regular-file sizes under root via
// filepath.WalkDir. Symlinks are never followed or counted (only
// regular files contribute bytes), and missing or unreadable entries
// are skipped cleanly rather than failing the walk.
//
// Bounding:
//   - If maxEntries > 0, the walk stops and returns truncated=true once
//     more than maxEntries entries (including directories) are visited.
//   - If budget != nil, each visited entry decrements *budget; when
//     *budget <= 0 (either on entry or mid-walk), the walk stops
//     immediately and returns truncated=true. Callers running many
//     walks in a cycle can share one *budget across them.
func WalkBytesBounded(root string, budget *int, maxEntries int) (bytes int64, truncated bool, err error) {
	if budget != nil && *budget <= 0 {
		return 0, true, nil
	}
	entries := 0
	err = filepath.WalkDir(root, func(_ string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // missing/unreadable entries are skipped best-effort
		}
		entries++
		if maxEntries > 0 && entries > maxEntries {
			truncated = true
			return fs.SkipAll
		}
		if budget != nil {
			if *budget <= 0 {
				truncated = true
				return fs.SkipAll
			}
			*budget--
		}
		if de.Type().IsRegular() {
			if fi, ierr := de.Info(); ierr == nil {
				bytes += fi.Size()
			}
		}
		return nil
	})
	return bytes, truncated, err
}
