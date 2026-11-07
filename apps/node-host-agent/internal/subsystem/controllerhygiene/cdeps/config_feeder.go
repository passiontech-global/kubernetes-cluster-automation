// config_feeder.go — the Feeder domain knobs: FeederConfig (the
// systemd watchdog feeder + remediate ordered gates) and its
// applyDefaults block lifted out of config.go — including the
// NOTIFY_SOCKET env passthrough.
package cdeps

import (
	"os"
	"time"
)

// FeederConfig is the systemd watchdog feeder — sd_notify WATCHDOG=1
// gated on apiserver liveness — plus the remediate ordered gates.
// Active only when Enabled AND (NotifySocket non-empty or a notifyFn
// seam is injected) — in a pod without NOTIFY_SOCKET the feeder is
// inert.
type FeederConfig struct {
	Enabled      bool
	NotifySocket string        // sd_notify datagram address (env NOTIFY_SOCKET)
	Interval     time.Duration // probe/feed cadence
	MaxFail      int           // consecutive fails → remediate
	GraceFails   int           // fail budget before first success
	ProbeURL     string        // readyz-ish endpoint; any HTTP code = alive
	ProbeTO      time.Duration
	// StateDir holds the remediate rate-limit file (shell
	// STATE_DIR=/var/lib/k0s-systemd-watchdog).
	StateDir            string
	RemediateMinRestart time.Duration // G5 budget
	RemediateFreshGrace time.Duration // G3 fresh-start grace
	RemediatePeerFile   string        // PEER_APISERVER= override file
}

func (c *Config) applyFeederDefaults() {
	if c.Feeder.Interval <= 0 {
		c.Feeder.Interval = defaultFeedInterval
	}
	if c.Feeder.MaxFail <= 0 {
		c.Feeder.MaxFail = defaultFeedMaxFail
	}
	if c.Feeder.GraceFails <= 0 {
		c.Feeder.GraceFails = defaultFeedGraceFails
	}
	if c.Feeder.ProbeURL == "" {
		c.Feeder.ProbeURL = defaultFeedProbeURL
	}
	if c.Feeder.ProbeTO <= 0 {
		c.Feeder.ProbeTO = defaultFeedProbeTO
	}
	if c.Feeder.StateDir == "" {
		c.Feeder.StateDir = defaultFeederStateDir
	}
	if c.Feeder.RemediateMinRestart <= 0 {
		c.Feeder.RemediateMinRestart = defaultRemediateMinRst
	}
	if c.Feeder.RemediateFreshGrace <= 0 {
		c.Feeder.RemediateFreshGrace = defaultRemediateGrace
	}
	if c.Feeder.RemediatePeerFile == "" {
		c.Feeder.RemediatePeerFile = defaultPeerFile
	}
	if c.Feeder.NotifySocket == "" {
		c.Feeder.NotifySocket = os.Getenv("NOTIFY_SOCKET")
	}
}
