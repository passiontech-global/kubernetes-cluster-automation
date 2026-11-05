package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostutil"
)

const f2bRestartInterval = 30 * time.Minute

// --- Check: fail2ban (50-fail2ban.sh) ---

// jailRe extracts the jail list / banned counts from
// fail2ban-client status output.
var (
	jailListRe = regexp.MustCompile(`Jail list:\s*(.+)`)
	bannedRe   = regexp.MustCompile(`Currently banned:\s*([0-9]+)`)
)

// checkFail2ban — unit installed but service down → fail2ban-down
// latch; per-jail banned counts go to fail2ban-banned for the
// node_fail2ban_banned_ips metric.
func (n *NetHealth) checkFail2ban(ctx context.Context) {
	if n.cfg.Systemd == nil {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	// Fail closed like coredns-stub: a failed existence probe counts
	// as present (the check still runs its other evidence — the
	// banned-metrics collector below does not need systemd), and a
	// failed is-active leaves the down-latch untouched rather than
	// entering or clearing it on a guess.
	exists, err := n.cfg.Systemd.Exists(ctx, "fail2ban.service")
	if err != nil {
		logger().Warn("nethealth: fail2ban existence probe failed — "+
			"treating unit as present this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
		exists = true
	}
	if !exists {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "fail2ban.service")
	if err != nil {
		logger().Warn("nethealth: fail2ban is-active probe failed — "+
			"down-latch left unchanged this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
	} else if !active {
		n.state.SuspectLog("fail2ban-down",
			"suspect: fail2ban-down (unit exists but service inactive)",
			suspectLogCadence)
		n.state.Enter("fail2ban-down", "service=inactive")
		// A stopped jail protects nothing — restart it under the
		// last-fail2ban-restart budget (30m) instead of only latching.
		if n.state.RateOK("last-fail2ban-restart", f2bRestartInterval) {
			n.state.AppendLog("ACTION: restarting fail2ban.service - unit exists but service inactive")
			n.state.RateSpend("last-fail2ban-restart")
			if err := n.cfg.Systemd.Restart(ctx, "fail2ban.service"); err != nil {
				n.state.AppendLog(fmt.Sprintf("fail2ban.service restart failed: %v", err))
			} else {
				n.actions.WithLabelValues(checkF2B, "restart").Inc()
			}
		}
	} else {
		n.stateExit("fail2ban-down")
	}
	bannedFile := filepath.Join(n.cfg.WatchdogStateDir, "fail2ban-banned")
	out, err := n.cfg.runMountCmd(ctx, []string{"fail2ban-client", "status"})
	if err != nil {
		// Client missing/failed → remove the metric file (no stale
		// series — absent, not 0).
		n.state.SuspectLog("fail2ban-client", fmt.Sprintf(
			"fail2ban: fail2ban-client status failed: %v (%s) — banned metrics dropped",
			err, trimRunErr(out)), suspectLogCadence)
		_ = os.Remove(bannedFile)
		n.cycles.WithLabelValues(checkF2B, "ok").Inc()
		return
	}
	var pairs []string
	if m := jailListRe.FindStringSubmatch(out); m != nil {
		for _, j := range strings.Split(m[1], ",") {
			j = strings.TrimSpace(j)
			if j == "" {
				continue
			}
			cnt := "0"
			// runMountCmd (nsenter -t 1 -m -n) like the aggregate
			// call — fail2ban-client and its socket only exist on
			// the host, so runHostCmd (netns only) can never reach
			// them containerized and the jail silently read "0".
			st, err := n.cfg.runMountCmd(ctx,
				[]string{"fail2ban-client", "status", j})
			if err != nil {
				logger().Warn("nethealth: fail2ban per-jail status "+
					"failed — banned count reported as 0",
					"jail", j,
					"output", trimRunErr(st), "error", err)
			} else if b := bannedRe.FindStringSubmatch(st); b != nil {
				cnt = b[1]
			}
			pairs = append(pairs, j+"="+cnt)
		}
	}
	if len(pairs) > 0 {
		if err := hostutil.WriteFileAtomic(bannedFile,
			strings.Join(pairs, " ")+"\n"); err != nil {
			logger().Warn("nethealth: fail2ban banned-count write "+
				"failed — node_fail2ban_banned_ips stale this cycle",
				"path", bannedFile,
				"error", err)
		}
	} else {
		_ = os.Remove(bannedFile)
	}
	n.cycles.WithLabelValues(checkF2B, "ok").Inc()
}
