//go:build linux

package wdeps

import (
	"os"

	"golang.org/x/sys/unix"
)

// detachLoop detaches a loop device via LOOP_CLR_FD on Linux.
func detachLoop(devPath string) error {
	f, err := os.Open(devPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return unix.IoctlSetInt(int(f.Fd()), unix.LOOP_CLR_FD, 0)
}
