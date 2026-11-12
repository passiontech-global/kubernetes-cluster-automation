// aliases.go — type aliases onto libs/hostkit/ledger. The ledger
// implementations moved to the shared leaf module so
// node-host-agent consumes the same CooldownSet/FirstSeenLedger/
// SeenSet/StreakLedger shapes; every call site in this package
// keeps compiling unchanged. Concurrency and zero-value contracts
// live in libs/hostkit/ledger (see its package doc): CooldownSet
// locks (Deps.Heals is shared across the worker pool),
// FirstSeenLedger stays lock-free per-check state.
package state

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

// CooldownSet tracks the last action stamp per key.
type CooldownSet = ledger.CooldownSet

// FirstSeenLedger tracks when each key was first observed.
type FirstSeenLedger = ledger.FirstSeenLedger

// SeenSet tracks which keys have already been noted.
type SeenSet = ledger.SeenSet

// StreakLedger counts, per key, how many consecutive sweeps the
// tracked condition held.
type StreakLedger = ledger.StreakLedger
