//go:build linux

package wdeps

import "golang.org/x/sys/unix"

const kcmpFile = 0

func inotifySameOFD(pid1, fd1, pid2, fd2 int) bool {
	r1, _, errno := unix.Syscall6(unix.SYS_KCMP, uintptr(pid1), uintptr(pid2),
		kcmpFile, uintptr(fd1), uintptr(fd2), 0)
	return errno == 0 && r1 == 0
}
