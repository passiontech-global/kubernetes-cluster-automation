// Package hostfixture holds the scaffolding the per-subsystem
// depstest fixtures (wdepstest, cdepstest, kdepstest) share —
// today the stubbed-signal record both workerhygiene and
// controllerhygiene fixtures append to their Kills ledgers.
//
// The domain fixtures themselves stay separate packages: each
// builds a DIFFERENT deps Config (wdeps.Config vs cdeps.Config vs
// kdeps.Config) and importing a sibling subsystem's config type
// would tangle the layering — only genuinely domain-free pieces
// live here.
package hostfixture

import "syscall"

// KillRecord is one stubbed signal delivery — the shape every
// depstest fixture's kill seam appends (PID + signal, no error
// channel: the seam records, it does not fail).
type KillRecord struct {
	PID int
	Sig syscall.Signal
}
