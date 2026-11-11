// dstate_scopes.go — shared guard defaults for the D-state/zombie-storm and
// systemd-scopes checks. The checks themselves were split into same-package
// files: guards_proc.go (shared /proc parsing helpers), guards_zombie_storm.go
// (ZombieStormCheck), guards_dstate_storm.go (DstateCheck), guards_scopes.go
// (ScopesCheck + scope helpers).

package guards

import (
	"time"
)

// Guard defaults (d-state-storm..H7): the D-state storm thresholds
// (total procs OR runtime-critical procs), the 30m
// systemd-scope reaper cadence, and the A2 zombie-storm
// threshold.
const (
	dStateRuntimeMin         = 2 // runtime-critical D-state procs → storm
	systemdScopeScanInterval = 30 * time.Minute
)
