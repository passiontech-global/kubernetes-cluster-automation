// group_resolved.go — T3 systemd-resolved fallback DNS + timesyncd NTP fallback.
package hostconfig

import "fmt"

// ---------- T3 resolved fallback DNS ----------

func (c *cyc) resolvedRunning() bool {
	return c.r.serviceState(c.ctx, "systemd-resolved.service") == "active"
}

func (c *cyc) groupResolved() {
	if !c.resolvedRunning() {
		return
	}
	_ = c.r.ensureDir("/etc/systemd/resolved.conf.d", 0o755)
	if ch, _ := c.r.writeManaged("/etc/systemd/resolved.conf.d/99-fallback.conf",
		[]byte(fmt.Sprintf(`# Managed by node-config-agent - diverse public fallback upstreams
[Resolve]
FallbackDNS=%s
Cache=yes
`, c.v("fallback_dns"))), 0o644); ch {
		c.r.restartService(c.ctx, "systemd-resolved.service")
	}
	// psi-memory-thrash: timesyncd NTP fallback — when the primary NTP source dies
	// (site upstream blocked), the public pools keep the clock
	// disciplined instead of drifting unsynced.
	if c.r.serviceState(c.ctx, "systemd-timesyncd.service") != "" ||
		c.r.fileExists("/etc/systemd/system/systemd-timesyncd.service") ||
		// Host paths — the unit lives on the HOST filesystem, so the
		// probe must go through HostRoot like every other host-side
		// fileExists in this file (fileExistsNoRoot would stat the
		// agent container's own /usr/lib and never see the host unit
		// in pod mode).
		c.r.fileExists("/usr/lib/systemd/system/systemd-timesyncd.service") ||
		c.r.fileExists("/lib/systemd/system/systemd-timesyncd.service") {
		_ = c.r.ensureDir("/etc/systemd/timesyncd.conf.d", 0o755)
		if ch, _ := c.r.writeManaged("/etc/systemd/timesyncd.conf.d/99-fallback.conf",
			[]byte(`# Managed by node-config-agent - public NTP fallbacks
[Time]
FallbackNTP=time.cloudflare.com time.google.com 0.pool.ntp.org 1.pool.ntp.org
`), 0o644); ch {
			// Restart only a RUNNING timesyncd — installed ≠ in
			// use. On chrony hosts the unit sits disabled/inactive
			// and a restart would start a second NTP daemon
			// fighting chrony for adjtimex (clock.go's
			// restartNTPDaemon enforces the same rule).
			if c.r.serviceState(c.ctx, "systemd-timesyncd.service") == "active" {
				c.r.restartService(c.ctx, "systemd-timesyncd.service")
			}
		}
	}
}
