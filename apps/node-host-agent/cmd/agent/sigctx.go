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
// shutdown trigger and the subcommands' interrupt path. SIGHUP is
// explicitly IGNORED: its terminal-hangup default disposition would
// kill a long-running daemon silently the moment an ssh session /
// serial console / tmux pane dropped. There is no SIGHUP reload
// contract to honor — config is re-read per Get on every use — so
// ignoring is the correct disposition, and idempotent here (both
// main() and the subcommands route through this one helper).
func signalContext() (context.Context, context.CancelFunc) {
	signal.Ignore(syscall.SIGHUP)
	return signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
}
