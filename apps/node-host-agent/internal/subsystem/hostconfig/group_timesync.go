// group_timesync.go — time-sync converge (systemd-timesyncd): the
// NTP-server drop-in from cluster vars, unit state, and the
// RTC-in-UTC policy fix for the boot-skew class (cicd vmi2940967,
// 2026-11-19: the VM image stores UTC+7 local time in the RTC, boot
// came up ~5h fast, NTP stepped the kernel back mid-run and every
// wall-clock mtime written pre-step read as a future stamp). The
// skew monitor side (adjtimex/chronyc probe, makestep, latch) lives
// in hostmetrics/kernelfail clock-skew — this group converges the
// CONFIG that keeps the monitor from having anything to latch.
package hostconfig

import (
	"strings"
)

const (
	timesyncUnit      = "systemd-timesyncd.service"
	timesyncDropinDir = "/etc/systemd/timesyncd.conf.d"
	timesyncDropin    = timesyncDropinDir + "/50-node-config-agent.conf"
)

func (c *cyc) groupTimesync() {
	r, ctx := c.r, c.ctx

	// chrony owns time sync when installed — flipping timesyncd on
	// under it would put two NTP clients in one adjtimex discipline.
	// RTC policy below still applies: UTC-in-RTC is a machine-level
	// contract, not a client choice.
	chrony := r.fileExists("/etc/chrony/chrony.conf") ||
		r.fileExists("/usr/lib/systemd/system/chrony.service")
	if chrony {
		c.timesyncRTC()
		return
	}

	// Server drop-in: only what vars provide. Without vars the
	// distro config (systemd's compiled-in fallback pool) stands —
	// writing an empty NTP= would WORSEEN a working node.
	servers := c.vs("ntp_servers")
	fallback := c.vs("ntp_fallback_servers")
	if len(servers) > 0 || len(fallback) > 0 {
		var b strings.Builder
		b.WriteString("# Managed by node-config-agent — time-sync converge\n")
		b.WriteString("[Time]\n")
		if len(servers) > 0 {
			b.WriteString("NTP=" + strings.Join(servers, " ") + "\n")
		}
		if len(fallback) > 0 {
			b.WriteString("FallbackNTP=" + strings.Join(fallback, " ") + "\n")
		}
		// VPS CPU-steal tuning: cap poll interval at 256s (default 2048s =
		// 34m drifts too far under steal bursts) and raise RootDistanceMaxSec
		// from 5s to 10s so transient steal-induced RTT spikes don't drop
		// valid NTP samples and silently stall timesyncd.
		b.WriteString("PollIntervalMinSec=32\n")
		b.WriteString("PollIntervalMaxSec=256\n")
		b.WriteString("RootDistanceMaxSec=10\n")
		// timesyncd only re-reads config on start; the changed
		// drop-in is worthless until the bounce lands.
		if ch, _ := r.writeManaged(timesyncDropin, []byte(b.String()), 0o644); ch {
			r.restartService(ctx, timesyncUnit)
		}
	}

	// Unit state: an installed-but-idle timesyncd leaves a freshly
	// booted VM on its RTC (exactly the boot-skew class) — converge
	// enable+start like the systemd_service tasks did. The unit file
	// gate keeps hosts without timesyncd (containers, minimal
	// images) out of systemctl's not-found error path.
	if r.fileExists("/usr/lib/systemd/system/" + timesyncUnit) {
		if err := r.sysd().EnsureService(ctx, timesyncUnit, true, true); err != nil {
			c.err("hostconfig: timesyncd converge failed", "unit", timesyncUnit, "error", err)
		}
	}

	c.timesyncRTC()
}

// timesyncRTC enforces the RTC-holds-UTC contract — the root cause
// of the boot-skew class. set-local-rtc 0 only rewrites the POLICY
// (re-interpreting the current RTC value), so it runs only from a
// clock NTP already stepped: converting policy on a skewed clock
// would bake the skew into the RTC and every future boot.
// Opt-out with the ntp_rtc_utc var set false (default on).
func (c *cyc) timesyncRTC() {
	r, ctx := c.r, c.ctx
	if v := c.v("ntp_rtc_utc"); v != "" && !c.vb("ntp_rtc_utc") {
		return
	}
	out, _ := r.run(ctx, "timedatectl", "show", "-p", "LocalRTC", "--value")
	if strings.TrimSpace(out) != "yes" {
		return
	}
	sync, _ := r.run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if strings.TrimSpace(sync) != "yes" {
		c.err("hostconfig: RTC holds local time but clock is not NTP-synchronized — " +
			"retry after the next sync")
		return
	}
	if _, err := r.run(ctx, "timedatectl", "set-local-rtc", "0"); err != nil {
		c.err("hostconfig: set-local-rtc 0 failed", "error", err)
		return
	}
	// Bake the now-synced time into the RTC as UTC — without this the
	// corrected policy still leaves the old local-time value on disk
	// until whenever the host next writes the RTC.
	_, _ = r.run(ctx, "hwclock", "--systohc", "--utc")
	r.actions.WithLabelValues("timedatectl set-local-rtc 0").Inc()
	logger().Info("hostconfig: RTC policy converged to UTC",
		"was", "local")
}
