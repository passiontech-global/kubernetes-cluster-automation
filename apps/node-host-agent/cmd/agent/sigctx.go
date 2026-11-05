// sigctx.go — the one place SIGINT/SIGTERM cancellation is wired.
// main() and dispatch() both ran signal.NotifyContext on the same
// signal pair; the helper keeps the two call sites from drifting.
package main

import (
	"context"
	"os/signal"
	"syscall"
)

// signalContext cancels on SIGINT or SIGTERM — the daemon's graceful
// shutdown trigger and the subcommands' interrupt path.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
}
