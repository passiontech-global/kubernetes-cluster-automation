// config_pki.go — the PKIDrift domain knobs: PKIDriftPair and
// PKIDriftConfig (the W8-CP4 on-disk-vs-served PKI cert drift
// check — no env wiring) and the applyDefaults block lifted out
// of config.go.
package cdeps

import (
	"path/filepath"
	"strings"
	"time"
)

// PKIDriftPair is one W8-CP4 check row: the on-disk cert file, the
// TLS listener that must already serve it, and the systemd unit a
// detected drift restarts.
type PKIDriftPair struct {
	CertFile string
	Addr     string
	Unit     string
}

// PKIDriftConfig is the W8-CP4 on-disk-vs-served PKI cert drift check.
// No env wiring — package defaults unless set programmatically.
type PKIDriftConfig struct {
	// Pairs pairs an on-disk cert with the socket that must present
	// it and the unit restarted on drift; nil → the four defaults
	// (apiserver.crt→:6443, konnectivity-server.crt→:8132,
	// etcd/server.crt→:2379 — all k0scontroller.service —
	// and /etc/kine/pki/server.crt→:2379 → kine.service). Paths may
	// use the $K0SDIR placeholder, resolved against Config.K0sDir.
	Pairs []PKIDriftPair
	// Cycles is the consecutive-newer-cycle gate (default 2);
	// RestartInterval the last-cp-cert-restart budget (default 1h).
	Cycles          int
	RestartInterval time.Duration
	// KinePKIDir prefixes the default kine cert path ("" →
	// "/host/etc/kine/pki").
	KinePKIDir string
}

func (c *Config) applyPKIDriftDefaults() {
	if c.PKIDrift.KinePKIDir == "" {
		c.PKIDrift.KinePKIDir = "/host/etc/kine/pki"
	}
	if c.PKIDrift.Pairs == nil {
		k0s := c.K0sDir
		c.PKIDrift.Pairs = []PKIDriftPair{
			{filepath.Join(k0s, "pki", "apiserver.crt"),
				"127.0.0.1:6443", "k0scontroller.service"},
			{filepath.Join(k0s, "pki", "konnectivity-server.crt"),
				"127.0.0.1:8132", "k0scontroller.service"},
			{filepath.Join(k0s, "pki", "etcd", "server.crt"),
				"127.0.0.1:2379", "k0scontroller.service"},
			{filepath.Join(c.PKIDrift.KinePKIDir, "server.crt"),
				"127.0.0.1:2379", "kine.service"},
		}
	} else {
		for i := range c.PKIDrift.Pairs {
			c.PKIDrift.Pairs[i].CertFile = strings.ReplaceAll(
				c.PKIDrift.Pairs[i].CertFile, "$K0SDIR", c.K0sDir)
		}
	}
	if c.PKIDrift.Cycles <= 0 {
		c.PKIDrift.Cycles = defaultPKIDriftCycles
	}
	if c.PKIDrift.RestartInterval <= 0 {
		c.PKIDrift.RestartInterval = defaultPKIRestartInterval
	}
}
