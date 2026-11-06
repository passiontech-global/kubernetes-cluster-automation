// clock.go — the Clock seam, re-exported from libs/hostkit/timex.
// Every module carries the same `nowFn func() time.Time` field so
// tests pin "now" instead of sleeping; the seam itself now lives in
// hostkit because node-host-agent re-implements the identical
// shape — hostkit is the single home, shared.Clock stays as the
// app-local spelling so ~30 module consumers keep their imports.
// The alias (= not a defined type) keeps Clock, SystemClock and
// NewClock interchangeable with timex's in both directions.
package shared

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Clock is a clock seam — the standard `nowFn func() time.Time`
// shape every sweep module carries for tests. A nil Clock still
// answers with system time, so `var now Clock` needs no constructor.
type Clock = timex.Clock

// SystemClock is the production clock — what every module's nowFn
// defaults to.
var SystemClock Clock = timex.SystemClock

// NewClock wraps fn as a Clock, mapping nil to SystemClock so a
// struct field can be assigned unconditionally (`now: NewClock(fn)`)
// without a separate nil check.
func NewClock(fn func() time.Time) Clock {
	return timex.NewClock(fn)
}
