// checks.go — the runtime-domain check constructors: the eight
// runtime-resource guards (runtime_<name>.go — one file per guard,
// see runtime_common.go for the family overview), the W6.3
// disk-bloat detector (disk_bloat.go) and the W10 KR1/ST2
// deep-failure guards (deep_failure_checks.go). The parent
// workerhygiene package wires them into its ordered dispatch list.
package runtime

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewCgroupDying returns the cgroup-dying-reclaim guard.
func NewCgroupDying(d *wdeps.Deps) *CgroupDyingCheck {
	return &CgroupDyingCheck{d: d}
}

// NewSystemdSession returns the logind session janitor.
func NewSystemdSession(d *wdeps.Deps) *SystemdSessionCheck {
	return &SystemdSessionCheck{d: d}
}

// NewOverlayFSStale returns the stale-overlay image healer.
func NewOverlayFSStale(d *wdeps.Deps) *OverlayFSStaleCheck {
	return &OverlayFSStaleCheck{d: d}
}

// NewIOPressure returns the diskstats + PSI io throttler.
func NewIOPressure(d *wdeps.Deps) *IOPressureCheck {
	return &IOPressureCheck{d: d, throttled: map[int]string{}}
}

// NewConntrackLiberal returns the neb1 be_liberal fixer.
func NewConntrackLiberal(d *wdeps.Deps) *ConntrackLiberalCheck {
	return &ConntrackLiberalCheck{d: d}
}

// NewClockJump returns the konn-pod clock-jump session healer.
func NewClockJump(d *wdeps.Deps) *ClockJumpCheck {
	return &ClockJumpCheck{d: d}
}

// NewUnlinkedOpenFiles returns the deleted-but-open fd space guard.
func NewUnlinkedOpenFiles(d *wdeps.Deps) *UnlinkedOpenFilesCheck {
	return &UnlinkedOpenFilesCheck{d: d}
}

// NewCgroupSwap returns the kubepods swap-leak cap guard.
func NewCgroupSwap(d *wdeps.Deps) *CgroupSwapCheck {
	return &CgroupSwapCheck{d: d}
}

// NewDiskBloat returns the W6.3 disk-bloat runaway detector.
func NewDiskBloat(d *wdeps.Deps) *DiskBloatCheck {
	return &DiskBloatCheck{d: d}
}

// NewHostOOM returns the W10-KR1 SystemOOMVictim consumer.
func NewHostOOM(d *wdeps.Deps) *HostOOMCheck { return &HostOOMCheck{d: d} }

// NewOrphanHP returns the W10-ST2 orphaned hostPath dir guard.
func NewOrphanHP(d *wdeps.Deps) *OrphanHPCheck {
	return &OrphanHPCheck{d: d}
}
