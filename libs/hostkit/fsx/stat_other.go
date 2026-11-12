//go:build !unix

// stat_other.go — the !unix half of the platform split: no
// EBUSY/EXDEV bind-mount semantics and no syscall.Stat_t, so the
// rename fallback never triggers and FileStatKey fails loudly
// instead of returning a bogus fingerprint.
package fsx

import "fmt"

// isBindMountRenameErr is always false off unix — the EBUSY/EXDEV
// fallback exists for Linux bind mounts only.
func isBindMountRenameErr(error) bool { return false }

// FileStatKey has no syscall.Stat_t to fingerprint on this
// platform; failing loudly beats a key that cannot detect change.
func FileStatKey(path string) (string, error) {
	return "", fmt.Errorf("stat %s: FileStatKey unsupported on this platform", path)
}
