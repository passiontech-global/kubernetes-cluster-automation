// poll.go — the bounded fixed-cadence poll behind the wait loops
// that used to hand-roll "try N times, sleep between, bail on ctx".
//
// This is deliberately NOT cycle.Runner: Runner runs forever on a
// ticker; Poll runs a bounded number of attempts and returns. The
// injected sleep keeps existing seams working — etcdmaint passes its
// cfg.SleepFn (tests stub it to a no-op) — nil means time.Sleep.
package cycle

import (
	"context"
	"time"
)

// Poll runs check up to tries times, interval apart, and reports
// whether any attempt succeeded. The per-attempt order is the one
// every converted loop kept verbatim: check first, then a ctx
// cancellation check (a cancelled ctx fails the poll without a
// final sleep), then sleep(interval) — including after the LAST
// failed attempt, matching the original loops that slept before
// returning their timeout error. sleep may be nil (time.Sleep
// default) or an injected seam such as etcdmaint's cfg.SleepFn.
func Poll(ctx context.Context, tries int, interval time.Duration,
	check func() bool, sleep func(time.Duration)) bool {
	if sleep == nil {
		sleep = time.Sleep
	}
	for range tries {
		if check() {
			return true
		}
		if err := ctx.Err(); err != nil {
			return false
		}
		sleep(interval)
	}
	return false
}
