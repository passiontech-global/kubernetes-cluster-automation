//go:build linux

package pagecache

import (
	"os"

	"golang.org/x/sys/unix"
)

// dontNeed issues POSIX_FADV_DONTNEED for the whole file — offset 0
// with len 0 means "to end of file". The kernel drops only clean
// pages; dirty pages are scheduled for writeback first, so callers
// that just wrote must fsync BEFORE calling (writeManaged,
// downloadFile, untarInstall all do).
func dontNeed(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
