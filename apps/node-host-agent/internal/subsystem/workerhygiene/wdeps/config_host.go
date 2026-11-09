// config_host.go — the deep-failure host-side markers: HostConfig and
// its defaults (the hostmetrics kmsg scanner's files this subsystem
// consumes and the SystemOOMVictim event sink). The marker paths
// derive from WatchdogStateDir, so the domain has no env rows of
// its own.
package wdeps

import "path/filepath"

// HostConfig groups the deep-failure host-side markers: the
// hostmetrics kmsg scanner's files this check consumes (defaults
// derive from WatchdogStateDir so both subsystems agree on the file
// contract without wiring) and the SystemOOMVictim event sink.
type HostConfig struct {
	OOMVictimFile      string // "<epoch> <comm>" latest host-level victim
	OOMCountFile       string // cumulative host-level OOM kills
	ConntrackDropsFile string // cumulative nf_conntrack table-full records
	// EventNamespace receives the SystemOOMVictim node event.
	EventNamespace string
}

// applyDefaults fills the deep-failure (KR1/KR3/ST2) defaults —
// WatchdogStateDir is already resolved by applyWiringDefaults, so
// the marker-file paths derive from the same dir hostmetrics writes
// into.
func (hc *HostConfig) applyDefaults(stateDir string) {
	if hc.OOMVictimFile == "" {
		hc.OOMVictimFile = filepath.Join(stateDir,
			"kmsg-host-oom-victim")
	}
	if hc.OOMCountFile == "" {
		hc.OOMCountFile = filepath.Join(stateDir,
			"kmsg-host-oom-count")
	}
	if hc.ConntrackDropsFile == "" {
		hc.ConntrackDropsFile = filepath.Join(stateDir,
			"kmsg-conntrack-drops")
	}
	if hc.EventNamespace == "" {
		hc.EventNamespace = "default"
	}
}
