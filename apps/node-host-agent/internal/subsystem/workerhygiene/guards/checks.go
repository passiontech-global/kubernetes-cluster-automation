// checks.go — the guards-domain check constructors: the leak/storm
// detectors (dstate_scopes.go), the PSI memory-thrash evictor
// (psi_thrash.go), the journald-integrity probe (journald.go) and
// the network datapath guards (spegel.go, calico.go, cni_netns.go). The parent
// workerhygiene package wires them into its ordered dispatch list.
package guards

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// NewZombieStorm returns the A2 zombie-storm detector.
func NewZombieStorm(d *wdeps.Deps) *ZombieStormCheck {
	return &ZombieStormCheck{d: d, streaks: map[ZombieParent]int{}}
}

// NewDstate returns the W7-H1 D-state storm detector.
func NewDstate(d *wdeps.Deps) *DstateCheck { return &DstateCheck{d: d} }

// NewScopes returns the W7-H2 abandoned cri-containerd-*.scope sweep.
func NewScopes(d *wdeps.Deps) *ScopesCheck { return &ScopesCheck{d: d} }

// NewPSIThrash returns the W2 PSI memory-thrash evictor.
func NewPSIThrash(d *wdeps.Deps) *PSIThrashCheck {
	return &PSIThrashCheck{d: d}
}

// NewJournald returns the A5 journald-integrity probe.
func NewJournald(d *wdeps.Deps) *JournaldCheck {
	return &JournaldCheck{d: d, ig: newJournaldIntegrity(d)}
}

// NewSpegel returns the W7-H4 spegel-mirror guard.
func NewSpegel(d *wdeps.Deps) *SpegelCheck { return &SpegelCheck{d: d} }

// NewCalico returns the W7-H7 calico-hygiene guard.
func NewCalico(d *wdeps.Deps) *CalicoCheck { return &CalicoCheck{d: d} }

// NewCNINetns returns the W9 orphan cni-* netns reaper.
func NewCNINetns(d *wdeps.Deps) *CNINetnsCheck {
	return &CNINetnsCheck{d: d}
}
