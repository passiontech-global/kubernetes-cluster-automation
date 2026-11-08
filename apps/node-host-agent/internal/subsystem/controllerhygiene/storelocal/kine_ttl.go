// kine_ttl.go — the module-22 kine TTL tail: the TTL-dead /
// rewedge-loop kill guard (watchdog/modules/22-apiserver-hub.sh
// tail). Signals (1:1):
//
//	kine-ttl-dead   "TTL initial list failed|TTL event watch
//	                (failed|error)" in the journal since the CURRENT
//	                kine pid booted — workqueue ShutDown forever,
//	                kine never retries.
//	kine-ttl-loop   KineTTLRewedgeCycles DISTINCT kine pids each
//	                wedged since their own boot — deterministic seed
//	                race (WAN DB + large seed list); fast-kill
//	                suppressed, only a low-cadence recovery-probe
//	                kill.
package storelocal

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// ttlErrRe is the kine TTL-dead journal grep (pkg/ttl/ttl.go
// workqueue ShutDown).
var ttlErrRe = regexp.MustCompile(`TTL initial list failed|TTL event watch (failed|error)`)

// TTLCheck is the module-22 tail as a Check — stateless: the
// rewedge streak and wedged-pid dedupe live in consecutive-ttl-
// rewedge / ttl-last-wedged-pid.
type TTLCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *TTLCheck) Name() string { return cdeps.CheckKineTTL }

// Run detects a kine process whose TTL workqueue died at boot and
// kills it so the supervisor respawns a clean one — escalating to
// the kine-ttl-loop latch (fast-kill suppressed, low-cadence probe
// kill only) when every respawned pid re-wedges from boot
// (deterministic environment race, not chance).
func (c *TTLCheck) Run(ctx context.Context) {
	kpid := c.d.Proc.FindByComm("kine")
	if kpid == 0 {
		c.d.StateExit(cdeps.StateKineTTLDead)
		c.d.StateExit(cdeps.StateKineTTLLoop)
		c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
		return
	}
	now := c.d.Cfg.Clock.Now()
	kage, err := c.d.Proc.PIDAgeSeconds(kpid, cdeps.ClkTck)
	if err != nil {
		// Age unreadable → the journal window collapses to "now"
		// and a dead TTL goes undetected — surface it.
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"suspect: kine pid=%d age unreadable: %v — TTL journal window degenerates",
			kpid, err))
		kage = 0
	}
	since := now.Add(-time.Duration(kage) * time.Second)
	ttlDead := cdeps.CountMatches(ttlErrRe, c.d.JournalText(ctx, since)) > 0
	if !ttlDead {
		// Pid living clean past the seed window → loop broken:
		// reset the counter and clear both latches.
		c.d.State.ResetCounter(cdeps.FileCtrTTLRewedge)
		c.d.State.ResetCounter(cdeps.FileTTLWedgedPID)
		c.d.StateExit(cdeps.StateKineTTLDead)
		c.d.StateExit(cdeps.StateKineTTLLoop)
		c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
		return
	}

	c.d.State.Enter(cdeps.StateKineTTLDead,
		fmt.Sprintf("pid=%d age=%ds", kpid, int(kage)))
	// Each wedged pid counts once (dedupe ttl-last-wedged-pid); a pid
	// change = respawn after kill/crash — re-wedging on the new pid
	// is "kill cannot cure" evidence → accumulate rewedge.
	rew := 0
	if strconv.Itoa(kpid) != c.d.ReadState(cdeps.FileTTLWedgedPID) {
		c.d.State.WriteEpochFile(filepath.Join(c.d.State.Dir, cdeps.FileTTLWedgedPID),
			int64(kpid))
		rew = c.d.State.Incr(cdeps.FileCtrTTLRewedge)
	} else {
		rew = c.d.State.Counter(cdeps.FileCtrTTLRewedge)
	}

	switch {
	case rew >= c.d.Cfg.KineTTL.RewedgeCycles:
		c.d.State.Enter(cdeps.StateKineTTLLoop,
			fmt.Sprintf("rewedge=%dx pid=%d", rew, kpid))
		// Held-latch dedupe (nonprod 2026-10: this line logged every
		// 60s cycle for weeks, 1600+ mentions) — first line on latch
		// entry, then one re-reminder per SuspectLogCadence. The rew
		// counter above still updates every cycle.
		c.d.State.SuspectLog(cdeps.StateKineTTLLoop, fmt.Sprintf(
			"suspect: kine-ttl-loop — %d consecutive kine pids wedged from boot; deterministic env (WAN DB + seed race), fast-kill suppressed",
			rew), c.d.Cfg.SuspectLogCadence)
		// Loop path: one recovery-probe kill per KineTTLCtlRestart —
		// faster remediation is pointless and just flaps.
		if !c.d.State.RateOK(cdeps.FileRateTTLKill, c.d.Cfg.KineTTL.CtlRestart) {
			break // low cadence not reached — stay silent
		}
		switch c.d.Cfg.KineTTL.Mode {
		case cdeps.ModeEnforce:
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — recovery probe kine-ttl-loop (rewedge=%dx, cadence %ds)",
				kpid, rew, int(c.d.Cfg.KineTTL.CtlRestart.Seconds())))
			c.d.State.RateSpend(cdeps.FileRateTTLKill)
			if err := c.d.Cfg.KillFn(kpid, syscall.SIGTERM); err != nil {
				c.d.State.AppendLogWarn(fmt.Sprintf(
					"suspect: kill kine pid=%d failed: %v", kpid, err))
			}
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "kill_kine").Inc()
		case cdeps.ModeDryRun:
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — kine-ttl-loop rewedge=%dx", kpid, rew))
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "dryrun_kill").Inc()
		}
	case kage > c.d.Cfg.KineTTL.MinProcAge.Seconds():
		// Tier 1 (chance wedge): only remediate once the instance
		// survived the seed window — never restart INTO the storm.
		if !c.d.State.RateOK(cdeps.FileRateTTLKill, c.d.Cfg.KineTTL.MinRestart) {
			c.d.State.SuspectLog(cdeps.StateKineTTLDead, fmt.Sprintf(
				"suspect: kine-ttl-dead but in restart cooldown (<%dm), skip",
				int(c.d.Cfg.KineTTL.MinRestart.Minutes())), c.d.Cfg.SuspectLogCadence)
			break
		}
		switch c.d.Cfg.KineTTL.Mode {
		case cdeps.ModeEnforce:
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: kill kine pid=%d — TTL workqueue dead — k0s supervisor respawns",
				kpid))
			c.d.State.RateSpend(cdeps.FileRateTTLKill)
			if err := c.d.Cfg.KillFn(kpid, syscall.SIGTERM); err != nil {
				c.d.State.AppendLogWarn(fmt.Sprintf(
					"suspect: kill kine pid=%d failed: %v", kpid, err))
			}
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "kill_kine").Inc()
		case cdeps.ModeDryRun:
			c.d.State.AppendLog(fmt.Sprintf(
				"DRY-RUN: would kill kine pid=%d — TTL dead", kpid))
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "dryrun_kill").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
}
