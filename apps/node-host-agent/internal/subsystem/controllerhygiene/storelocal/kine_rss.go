// kine_rss.go — HA-gated kine RSS leak guard.
//
// Reads VmRSS of the local kine process (embedded under k0scontroller or
// standalone under kine.service) from /proc/<pid>/status. When RSS stays
// above KineRSS.MaxRSSMiB (default 1536 MiB, 0 = disabled) for 3
// consecutive cycles:
//   - Mandatory HA Safety Gate: verifies this is NOT a single-controller
//     topology AND at least one peer controller is healthy (peer /readyz
//     responds AND quorum endpoints are not <2). Without a healthy peer,
//     logs WARN (observe-only) and NEVER kills/restarts kine.
//   - With a healthy peer and cooldown elapsed (last-kine-rss-heal, 1h):
//     sends SIGTERM to embedded kine (k0s supervisor respawns it) or
//     restarts kine.service on split hosts.
package storelocal

import (
	"context"
	"fmt"
	"strings"
	"syscall"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

const (
	kineRSSHaGateLogKey = "kine-rss-ha-gate"
	kineRSSCooldownKey  = "kine-rss-cooldown"
	kineRSSHoldKey      = "kine-rss-hold"
)

// checkKineRSS evaluates kine process RSS and heals only when the HA
// safety gate positively confirms a healthy peer controller.
func (c *PoolCheck) checkKineRSS(ctx context.Context) {
	maxRSSMiB := c.d.Cfg.KineRSS.MaxRSSMiB
	if maxRSSMiB <= 0 {
		c.d.State.ResetCounter(cdeps.FileCtrKineRSS)
		return
	}

	kpid, standalone, origStart := c.findKineForRSS()
	if kpid == 0 {
		c.d.State.ResetCounter(cdeps.FileCtrKineRSS)
		return
	}

	rssBytes, ok := c.d.ProcVMRSS(kpid)
	if !ok {
		return
	}
	if rssBytes <= uint64(maxRSSMiB)<<20 {
		c.d.State.ResetCounter(cdeps.FileCtrKineRSS)
		c.d.State.ClearSuspect(kineRSSHaGateLogKey)
		c.d.State.ClearSuspect(kineRSSCooldownKey)
		c.d.State.ClearSuspect(kineRSSHoldKey)
		return
	}

	n := c.d.State.Incr(cdeps.FileCtrKineRSS)
	rssMiB := rssBytes >> 20
	cycles := c.d.Cfg.KineRSS.Cycles
	if n < cycles {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kine pid=%d rss_mib=%d > %d%s",
			kpid, rssMiB, maxRSSMiB, checkkit.Progress(n, cycles)))
		return
	}

	// --- Mandatory HA Safety Gate (fail-closed) ---
	peer := c.d.HubConf().PeerAPI
	if c.d.SingleController() || peer == "" {
		if c.d.State.RateTrySpend("last-suspect-"+kineRSSHaGateLogKey, c.d.Cfg.SuspectLogCadence) {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"WARN: kine pid=%d rss_mib=%d > %d (%dx) on single-controller — observe-only, heal suppressed",
				kpid, rssMiB, maxRSSMiB, n))
		}
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "kine_rss_single_ctrl_skip").Inc()
		return
	}

	peerHost := strings.TrimPrefix(strings.TrimPrefix(peer, "https://"), "http://")
	peerURL := "https://" + peerHost + "/readyz"
	if !c.d.Cfg.ProbeFn(ctx, peerURL) || !c.d.ControllerQuorumReady(ctx) {
		if c.d.State.RateTrySpend("last-suspect-"+kineRSSHaGateLogKey, c.d.Cfg.SuspectLogCadence) {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"WARN: kine pid=%d rss_mib=%d > %d (%dx) but peer controller %s unhealthy — observe-only, heal suppressed",
				kpid, rssMiB, maxRSSMiB, n, peer))
		}
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "kine_rss_peer_unhealthy_skip").Inc()
		return
	}

	if !c.d.State.RateOK(cdeps.FileRateKineRSSHeal, c.d.Cfg.KineRSS.Cooldown) {
		c.d.State.SuspectLog(kineRSSCooldownKey, fmt.Sprintf(
			"suspect: kine pid=%d rss_mib=%d > %d (%dx) but in heal cooldown (<%s), skip",
			kpid, rssMiB, maxRSSMiB, n, c.d.Cfg.KineRSS.Cooldown),
			c.d.Cfg.SuspectLogCadence)
		return
	}

	if ctx.Err() != nil {
		return
	}

	if c.d.HoldEmergencyHeal(ctx) {
		c.d.State.SuspectLog(kineRSSHoldKey, fmt.Sprintf(
			"suspect: kine pid=%d rss_mib=%d > %d (%dx) but cluster maintenance in progress — holding heal",
			kpid, rssMiB, maxRSSMiB, n), c.d.Cfg.SuspectLogCadence)
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "kine_rss_maint_hold").Inc()
		return
	}

	if c.d.Cfg.KinePool.Mode == cdeps.ModeDryRun {
		if standalone {
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would restart %s (pid=%d) — kine rss_mib=%d > %d x%d peer=%s healthy",
				cdeps.KineServiceCgroupSubstr, kpid, rssMiB, maxRSSMiB, n, peer))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would terminate kine pid=%d (SIGTERM) — rss_mib=%d > %d x%d peer=%s healthy",
				kpid, rssMiB, maxRSSMiB, n, peer))
		}
		c.d.State.ResetCounter(cdeps.FileCtrKineRSS)
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "dryrun_kine_rss").Inc()
		return
	}

	if !standalone && !c.verifyKinePID(kpid, origStart) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kine pid=%d identity changed before SIGTERM — skipped", kpid))
		return
	}

	if !c.d.State.RateTrySpend(cdeps.FileRateKineRSSHeal, c.d.Cfg.KineRSS.Cooldown) {
		return
	}
	c.d.State.ResetCounter(cdeps.FileCtrKineRSS)

	if standalone {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: restarting %s (pid=%d) — kine rss_mib=%d > %d x%d peer=%s healthy",
			cdeps.KineServiceCgroupSubstr, kpid, rssMiB, maxRSSMiB, n, peer))
		if err := c.d.Restart(ctx, cdeps.KineServiceCgroupSubstr); err != nil {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", cdeps.KineServiceCgroupSubstr, err))
		}
		c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "restart_kine_rss").Inc()
		return
	}

	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: terminated kine pid=%d (SIGTERM) — rss_mib=%d > %d x%d peer=%s healthy (k0s supervisor respawns)",
		kpid, rssMiB, maxRSSMiB, n, peer))
	if err := c.d.Cfg.KillFn(kpid, syscall.SIGTERM); err != nil {
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"suspect: kill kine pid=%d failed: %v", kpid, err))
	}
	c.d.Actions.WithLabelValues(cdeps.CheckKinePool, "kill_kine_rss").Inc()
}

// findKineForRSS locates kine in k0scontroller.service (embedded) or
// kine.service (Phase-3 split standalone unit), returning its pid,
// whether it is standalone, and its /proc/<pid>/stat starttime field.
func (c *PoolCheck) findKineForRSS() (pid int, standalone bool, startTime string) {
	if kpid := c.d.Proc.FindByCommInCgroup("kine", cdeps.K0sControllerCgroupSubstr); kpid != 0 {
		if st, ok := c.d.Proc.Stat(kpid); ok && len(st.Fields) > 19 {
			startTime = st.Fields[19]
		}
		return kpid, false, startTime
	}
	if kpid := c.d.Proc.FindByCommInCgroup("kine", cdeps.KineServiceCgroupSubstr); kpid != 0 {
		if st, ok := c.d.Proc.Stat(kpid); ok && len(st.Fields) > 19 {
			startTime = st.Fields[19]
		}
		return kpid, true, startTime
	}
	return 0, false, ""
}

// verifyKinePID re-verifies cgroup and starttime before signalling an
// embedded kine pid to close any PID-reuse TOCTOU window across the peer
// health probe and maintenance hold checks.
func (c *PoolCheck) verifyKinePID(pid int, origStart string) bool {
	if !c.d.Proc.CgroupContains(pid, cdeps.K0sControllerCgroupSubstr) {
		return false
	}
	if origStart != "" {
		st, ok := c.d.Proc.Stat(pid)
		if !ok || len(st.Fields) <= 19 || st.Fields[19] != origStart {
			return false
		}
	}
	return true
}
