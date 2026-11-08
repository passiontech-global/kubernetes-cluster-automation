// sigctx_test.go — SIGHUP must not kill the agent: the helper ignores
// the hangup signal explicitly (the terminal-drop default disposition
// silently terminated daemons) while SIGINT/SIGTERM still cancel the
// context.
package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSignalContextIgnoresSIGHUP(t *testing.T) {
	ctx, stop := signalContext()
	defer stop()

	// Deliver SIGHUP to ourselves — with the ignore registered the
	// runtime drops it; without, the default disposition would kill
	// the test process outright (failing the whole run, which is
	// precisely the bug).
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	// Give the signal machinery a beat; an unignored SIGHUP would
	// have terminated us before this line.
	time.Sleep(100 * time.Millisecond)
	if err := ctx.Err(); err != nil {
		t.Fatalf("SIGHUP cancelled the context: %v", err)
	}

	// The paired shutdown signals still work.
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("SIGINT did not cancel the context")
	}
}
