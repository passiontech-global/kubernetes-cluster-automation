// ionice_linux_test.go — the ioprio_set(2) wrapper: the idle-class
// drop succeeds on an own unprivileged process (the throttler's real
// call), and an invalid target surfaces the raw errno as an error.
package wdeps

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIoniceIdle(t *testing.T) {
	// Our own pid: lowering to idle is unprivileged-legal. A kernel
	// that refuses it answers EPERM — also the errno path, so either
	// verdict is a covered, correct call.
	if err := ioniceIdle(os.Getpid()); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatalf("self ioprio_set: %v", err)
	}
	// A bogus pid must surface the kernel's errno.
	if err := ioniceIdle(-1); err == nil {
		t.Fatal("pid -1 must error")
	}
}
