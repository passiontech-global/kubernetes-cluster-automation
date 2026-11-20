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
//	kine-down       NO kine pid anywhere (unit cgroup or
//	                kine.service) while the unit is active — the
//	                never-started signature; no kill, alert-only.
package storelocal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// ttlErrRe is the kine TTL-dead journal grep (pkg/ttl/ttl.go
// workqueue ShutDown) plus the bind-conflict death: a foreign process
// holding the kine metrics port (stray kine.service — nonprod
// 2026-11-17/18) FATALs each respawn before the TTL workqueue ever
// starts, so only the bind line is on the record.
var ttlErrRe = regexp.MustCompile(
	`TTL initial list failed|TTL event watch (failed|error)|` +
		`metrics listener: listen tcp :2380: bind: address already in use`)

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
	// cgroup-scoped lookup: a same-named process outside
	// k0scontroller.service (foreign daemon, recycled pid) must
	// never inherit the kill trust.
	kpid := c.d.Proc.FindByCommInCgroup("kine", cdeps.K0sControllerCgroupSubstr)
	if kpid == 0 {
		// Phase-3 split hosts (kine_service_hosts) run kine as the
		// standalone kine.service unit — its cgroup is not
		// k0scontroller, so an absent in-unit pid is the expected
		// shape there. Detect it by cgroup, not by a config knob, so
		// the verdict stays right if the split is re-enabled without
		// a controllerhygiene config change.
		if c.d.Proc.FindByCommInCgroup("kine", cdeps.KineServiceCgroupSubstr) != 0 {
			c.d.StateExit(cdeps.StateKineDown)
			c.exitTTLLatches()
			c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
			return
		}
		if c.isEmbeddedEtcd() {
			c.d.StateExit(cdeps.StateKineDown)
			c.exitTTLLatches()
			c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
			return
		}
		// NO kine anywhere while the unit is active (this check is
		// uptime-gated >=20m, so this is not a boot window): the
		// never-started signature. Treating absent == ok made the
		// fastest-crash failure modes invisible — a bind conflict
		// with a foreign process (stray kine.service holding :2380,
		// nonprod 2026-11-17/18, 25h silent apiserver outage) kills
		// each respawn within seconds, so the pid is almost always
		// absent when this check samples it, and no journal regex
		// ever matched. Latch kine-down instead.
		c.d.State.Enter(cdeps.StateKineDown,
			"no kine pid in k0scontroller or kine.service cgroup")
		c.d.State.SuspectLog(cdeps.StateKineDown, fmt.Sprintf(
			"suspect: kine-down - no kine process in the %s or kine.service cgroup while the unit is active; kube-apiserver cannot start without its datastore",
			cdeps.K0sControllerCgroupSubstr), c.d.Cfg.SuspectLogCadence)
		c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "kine_down").Inc()
		return
	}
	// A live in-unit pid clears the never-started latch: whatever
	// killed the previous pids is no longer winning.
	c.d.StateExit(cdeps.StateKineDown)
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
	// A pid already recorded as TTL-wedged can never un-wedge —
	// the workqueue ShutDown is permanent for that process — and
	// its single boot-time journal line ages out of the bounded
	// lookback (~25m) while kill cooldowns (state-kine-ttl-loop
	// cadence, ModeDryRun, maintenance) can hold remediation off
	// for hours. Re-scanning would then count 0 matches and run
	// the clean-pid branch below: StateExit BOTH latches AND reset
	// the rewedge counter, erasing the wedge evidence on a
	// still-dead kine. Skip the journal entirely for the recorded
	// pid — the dedupe below keeps rew and the kill cadences keep
	// applying until the supervisor hands us a new pid.
	ttlDead := c.d.ReadState(cdeps.FileTTLWedgedPID) == strconv.Itoa(kpid) &&
		c.d.State.Exists(cdeps.StateKineTTLDead)
	if !ttlDead {
		since := now.Add(-time.Duration(kage) * time.Second)
		// Bound the journalctl --since window: on a node up for
		// days a healthy long-lived kine pid would otherwise dump
		// tens of MiB of old unit logs into hostexec's 16 MiB head
		// buffer and lose the newest tail — the TTL verdict only
		// needs the boot window. While StateKineTTLDead is latched
		// FOR THIS pid the full pid-age window stays: confirming
		// the boot-time error line may still require reading back
		// to process start.
		//
		// maxLookback MUST exceed the uptime gate (MinUptimeSeconds =
		// 20m) plus one cycle of slack: this check's FIRST run
		// happens at uptime ≥20m, so a TTL error logged in the
		// first minutes of boot is already ~20m old — a 15m window
		// slid past it before the check ever ran and the wedge was
		// missed forever.
		const maxLookback = time.Duration(cdeps.MinUptimeSeconds)*time.Second +
			5*time.Minute
		// The bounded window applies to ALREADY-LATCHED pids too:
		// once StateKineTTLDead is recorded for this kinePID there
		// is no reason to keep reading back to process start — the
		// boot-window TTL lines either still sit inside maxLookback
		// (verdict unchanged) or have aged out (the wedge aged out
		// with them). Skipping the widening keeps the per-cycle
		// journalctl window small on long-uptime nodes.
		if floor := now.Add(-maxLookback); since.Before(floor) {
			since = floor
		}
		// The window must also stop at the unit's CURRENT
		// activation: journalctl --since reaches back across a
		// unit restart, so a kine pid whose age exceeds the unit's
		// active age (a leftover process the supervisor adopted, a
		// pid-namespace edge) would read TTL errors logged by the
		// PREVIOUS activation and flag a healthy respawn as wedged.
		// ActiveAge errors (unit inactive, clocks unreadable) leave
		// the pid-age window — best effort, same posture as the
		// age-unreadable note above.
		if sd := c.d.Cfg.Systemd; sd != nil {
			if uage, uerr := sd.ActiveAge(ctx, c.d.Cfg.JournalUnit); uerr == nil && uage > 0 {
				if unitStart := now.Add(-uage); since.Before(unitStart) {
					since = unitStart
				}
			}
		}
		// --grep pushes the TTL signature into journalctl itself
		// (MESSAGE =~ PCRE2, systemd ≥237): the read returns only
		// matching entries instead of the whole unit window — on a
		// chatty controller unit that is the difference between a
		// few lines and megabytes per cycle. The client-side
		// CountMatches below still applies the Go regexp to the
		// filtered output, so the verdict path is unchanged.
		jout, jerr := c.d.JournalTextGrep(ctx, since, ttlErrRe.String())
		if jerr != nil {
			// Journal unreadable → inconclusive: keep the existing
			// latch verdicts instead of clearing them on "0 hits".
			c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "ok").Inc()
			return
		}
		ttlDead = cdeps.CountMatches(ttlErrRe, jout) > 0
	}
	if !ttlDead {
		// Pid living clean past the seed window → loop broken:
		// reset the counter and clear both latches.
		c.d.State.ResetCounter(cdeps.FileCtrTTLRewedge)
		c.d.State.ResetCounter(cdeps.FileTTLWedgedPID)
		c.exitTTLLatches()
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
		if err := ctx.Err(); err != nil {
			c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "aborted").Inc()
			return
		}
		if c.d.HoldEmergencyHeal(ctx) {
			c.d.State.SuspectLog(cdeps.CheckKineTTL+"-hold",
				"suspect: kine-ttl-loop — cluster maintenance in progress — holding kill",
				c.d.Cfg.SuspectLogCadence)
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "maint_hold").Inc()
			break
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
		if err := ctx.Err(); err != nil {
			c.d.Cycles.WithLabelValues(cdeps.CheckKineTTL, "aborted").Inc()
			return
		}
		if c.d.HoldEmergencyHeal(ctx) {
			c.d.State.SuspectLog(cdeps.StateKineTTLDead+"-hold",
				"suspect: kine-ttl-dead — cluster maintenance in progress — holding kill",
				c.d.Cfg.SuspectLogCadence)
			c.d.Actions.WithLabelValues(cdeps.CheckKineTTL, "maint_hold").Inc()
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

// exitTTLLatches clears both TTL latches along with their separate
// maintenance-hold suspect dedupe keys so a subsequent episode emits
// fresh hold logs.
func (c *TTLCheck) exitTTLLatches() {
	if c.d.State.Exists(cdeps.StateKineTTLDead) {
		c.d.StateExit(cdeps.StateKineTTLDead)
		c.d.State.ClearSuspect(cdeps.StateKineTTLDead + "-hold")
	}
	if c.d.State.Exists(cdeps.StateKineTTLLoop) {
		c.d.StateExit(cdeps.StateKineTTLLoop)
		c.d.State.ClearSuspect(cdeps.CheckKineTTL + "-hold")
	}
}

// isEmbeddedEtcd reports whether this controller host runs embedded
// etcd rather than kine, so an absent kine PID does not false-latch
// StateKineDown. Explicit kine expectation markers (KineDBProbe,
// state.db, split kine.service) take precedence over on-disk etcd
// artifacts when no live etcd PID is found, so a crashed kine on a
// kine host still latches StateKineDown.
func (c *TTLCheck) isEmbeddedEtcd() bool {
	if c.d.Proc.FindByCommInCgroup("etcd", cdeps.K0sControllerCgroupSubstr) != 0 {
		return true
	}
	if c.d.Cfg.Hub.KineDBProbe != "" {
		return false
	}
	if c.d.Cfg.K0sDir != "" {
		if _, err := os.Stat(filepath.Join(c.d.Cfg.K0sDir, "db", "state.db")); err == nil {
			return false
		}
	}
	if c.d.Cfg.K0sControllerUnitFile != "" {
		if _, err := os.Stat(filepath.Join(filepath.Dir(c.d.Cfg.K0sControllerUnitFile), "kine.service")); err == nil {
			return false
		}
	}
	if c.d.Cfg.K0sDir != "" {
		if fi, err := os.Stat(filepath.Join(c.d.Cfg.K0sDir, "etcd")); err == nil && fi.IsDir() {
			return true
		}
		_, err1 := os.Stat(filepath.Join(c.d.Cfg.K0sDir, "bin", "etcdctl"))
		_, err2 := os.Stat(filepath.Join(c.d.Cfg.K0sDir, "pki", "etcd", "ca.crt"))
		if err1 == nil && err2 == nil {
			return true
		}
	}
	return false
}
