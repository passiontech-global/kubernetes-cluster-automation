//go:build linux

package wdeps

import "golang.org/x/sys/unix"

// ioniceIdle puts one pid in the idle I/O scheduling class — the
// `ionice -c 3 -p <pid>` equivalent via ioprio_set(2), so the
// io-pressure throttler needs no ionice binary inside the agent
// image (x/sys has no IoprioSet wrapper; SYS_IOPRIO_SET is called
// directly).
func ioniceIdle(pid int) error {
	const (
		ioprioWhoProcess = 1
		ioprioClassShift = 13
		ioprioClassIdle  = 3
	)
	ioprio := uintptr(ioprioClassIdle << ioprioClassShift)
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET,
		uintptr(ioprioWhoProcess), uintptr(pid), ioprio)
	if errno != 0 {
		return errno
	}
	return nil
}
