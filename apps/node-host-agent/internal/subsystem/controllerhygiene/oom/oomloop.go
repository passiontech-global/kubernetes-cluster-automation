package oom

// oomloop.go — port of scripts/k0s-oomloop-probe.sh (60s timer):
// memcg OOM-loop detector + oom_score_adj shield for k0scontroller.
//
// Incident 2026-10-09: a 5h+ OOM loop on BOTH controllers (~10-15
// kills/h) invisible to everyone until users reported pending pods.
// The wedge: kine restart → catch-up poll streams ALL rows since
// compact_rev into heap (~4-5G) + apiserver relist (~3-6G) > cgroup
// MemoryMax=7G → OOM → restart → refill → OOM again; compact_rev
// frozen because both die before compact-interval=30m.
//
// Signal: the kernel-counted `oom_kill` counter of the unit's cgroup
// v2 memory.events — no journal parse, fast, immune to journald
// overload. Loop = >= OOMLoopMinKills kills inside OOMLoopWindow.
//
// Remediate (enforce): shield kube-apiserver oom_score_adj=-800 and
// push kine to +500. Inside the loop the filler is kine, and the
// kernel picks victims by oom_badness ~ RSS + adj → kine dies first
// and apiserver SURVIVES each respawn — cutting the mass-reconnect/
// relist amplification for the whole cluster. The shield self-
// removes (adj=0) once the loop clears.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// oomKillRe matches the `oom_kill <n>` row of cgroup v2
// memory.events.
var oomKillRe = regexp.MustCompile(`^oom_kill +([0-9]+)\s*$`)

// LoopCheck is the memcg OOM-loop detector + shield as a
// Check — stateless: baseline/kills/shield bookkeeping lives in
// the oomloop-* files.
type LoopCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *LoopCheck) Name() string { return cdeps.CheckOOMLoop }

// Run executes one OOM-loop guard cycle.
func (c *LoopCheck) Run(_ context.Context) {
	events, err := os.ReadFile(c.d.Cfg.OOMLoop.CGroupEventsFile)
	if err != nil {
		// Not a cgroup-v2 controller (or path not mounted) — the
		// shell exited 0 the same way.
		c.d.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "no_events").Inc()
		return
	}
	oomNow, ok := parseOOMKill(string(events))
	if !ok {
		c.d.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "ok").Inc()
		return
	}

	dir := c.d.State.Dir
	now := c.d.Cfg.Clock.Now().Unix()

	// First run (no baseline file): seed the baseline only — the
	// counter is cumulative since cgroup creation, so counting it
	// now would latch instantly on pre-probe history. An
	// UNPARSEABLE baseline is no baseline either: prev=0 would
	// replay the whole cumulative counter as "new kills" — the
	// same false latch, so re-seed instead.
	seenPath := filepath.Join(dir, cdeps.FileOOMSeen)
	prev := int64(0)
	hadBaseline := false
	if data, rerr := os.ReadFile(seenPath); rerr == nil {
		if v, perr := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); perr == nil {
			prev, hadBaseline = v, true
		}
	}
	// "<oomNow>\n" via the Store's atomic epoch write — byte-
	// identical to the old writeState for integer content.
	c.d.State.WriteEpochFile(seenPath, oomNow)

	killsPath := filepath.Join(dir, cdeps.FileOOMKills)
	// The counter resets to 0 when the cgroup is destroyed (unit
	// fully stopped) → a negative delta means a NEW counter —
	// re-baseline rather than counting phantom kills.
	if oomNow > prev && hadBaseline {
		d := oomNow - prev
		f, ferr := os.OpenFile(killsPath,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr == nil {
			line := strconv.FormatInt(now, 10) + "\n"
			for i := int64(0); i < d; i++ {
				_, _ = f.WriteString(line)
			}
			_ = f.Close()
		} else {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"oomloop: kills file %s append failed: %v — window undercounts kills",
				killsPath, ferr))
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"oomloop-probe: %d new memcg OOM kill(s) in k0scontroller (cum=%d)",
			d, oomNow))
	}

	inWindow := c.pruneKills(killsPath, now)
	c.d.OOMWindow.Set(float64(inWindow))

	if inWindow < c.d.Cfg.OOMLoop.MinKills {
		// Loop cleared: remove the shield — apiserver must not
		// stay protected forever (a genuine runaway apiserver
		// has to remain killable).
		c.unshieldOOM(dir, "clear")
		c.d.StateExit(cdeps.StateControllerOOMLop)
		c.d.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "ok").Inc()
		return
	}

	// --- OOM loop confirmed ---
	c.d.State.Enter(cdeps.StateControllerOOMLop, fmt.Sprintf(
		"oom_kills_window=%d/%d in %ds (cum=%d)",
		inWindow, c.d.Cfg.OOMLoop.MinKills,
		int(c.d.Cfg.OOMLoop.Window.Seconds()), oomNow))

	switch c.d.Cfg.OOMLoop.Mode {
	case cdeps.ModeEnforce:
		// Idempotent: PIDs change on every respawn so the shield is
		// re-applied every cycle while the loop is latched — only
		// the LOG line is deduped to the suspect cadence (the
		// shield work + action metric stay per-cycle).
		c.d.State.SuspectLog(cdeps.StateControllerOOMLop, fmt.Sprintf(
			"ACTION: shield kube-apiserver (oom_score_adj=%d), kine %+d — window_kills=%d",
			c.d.Cfg.OOMLoop.APIServerShieldAdj, c.d.Cfg.OOMLoop.KineShieldAdj, inWindow),
			c.d.Cfg.SuspectLogCadence)
		// Latch FIRST and confirm it landed: cdeps.FileOOMShielded is the
		// only record unshieldOOM keys on, so pinning an adj before
		// the latch exists is a single-point-of-failure — a failed
		// latch write leaves a shielded process nothing can find,
		// and a later mode-off/loop-clear unshield early-returns on
		// the missing file while oom_score_adj stays pinned for the
		// process's lifetime. No latch ⇒ nothing may be pinned.
		c.d.WriteState(cdeps.FileOOMShielded, "")
		if _, err := os.Stat(filepath.Join(dir, cdeps.FileOOMShielded)); err != nil {
			c.d.State.AppendLogWarn(fmt.Sprintf(
				"oomloop: shield latch %s not persisted: %v — shielding skipped (no latch, nothing pinned)",
				filepath.Join(dir, cdeps.FileOOMShielded), err))
			break
		}
		c.reassertShields()
		c.d.Actions.WithLabelValues(cdeps.CheckOOMLoop, "shield").Inc()
	case cdeps.ModeDryRun:
		c.d.State.SuspectLog(cdeps.StateControllerOOMLop, fmt.Sprintf(
			"DRY-RUN: would shield kube-apiserver oom_score_adj=%d, kine %+d — window_kills=%d",
			c.d.Cfg.OOMLoop.APIServerShieldAdj, c.d.Cfg.OOMLoop.KineShieldAdj, inWindow),
			c.d.Cfg.SuspectLogCadence)
		c.d.Actions.WithLabelValues(cdeps.CheckOOMLoop, "dryrun_shield").Inc()
	}
	// A mode flip off enforce while the shield is latched must not
	// leave oom_score_adj pinned on the apiserver for the process's
	// lifetime — unshield on any non-enforce mode (off, dry-run, or
	// an unrecognised value). Cheap: one stat per latched cycle.
	if c.d.Cfg.OOMLoop.Mode != cdeps.ModeEnforce {
		c.unshieldOOM(dir, "mode not enforce")
	}
	c.d.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "ok").Inc()
}

// reassertShields re-applies the oom_score_adj shield — BOTH pins —
// every enforce-mode cycle. PIDs change on every respawn and a fresh
// process boots at adj=0: re-pinning only kube-apiserver (−800) and
// skipping kine's +500 would leave every respawned kine fully
// killable while the loop latch still stands — the exact crash
// spiral this loop exists to break (kine must die FIRST so the
// apiserver survives each refill).
func (c *LoopCheck) reassertShields() {
	c.setAdj("kube-apiserver", c.d.Cfg.OOMLoop.APIServerShieldAdj)
	c.setAdj("kine", c.d.Cfg.OOMLoop.KineShieldAdj)
}

// unshieldOOM drops the apiserver/kine oom_score_adj shield when the
// latch file is present — loop-clear AND every non-enforce mode (a
// mode flip must not strand an enforce-era shield on the processes
// forever). why joins the log line ("oom-loop <why> — unshield ...").
func (c *LoopCheck) unshieldOOM(dir, why string) {
	if _, err := os.Stat(filepath.Join(dir, cdeps.FileOOMShielded)); err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"oom-loop %s — unshield kube-apiserver/kine (oom_score_adj=0)", why))
	c.setAdj("kube-apiserver", 0)
	c.setAdj("kine", 0)
	c.d.State.ResetCounter(cdeps.FileOOMShielded)
	c.d.Actions.WithLabelValues(cdeps.CheckOOMLoop, "unshield").Inc()
}

// parseOOMKill extracts the `oom_kill` counter from memory.events —
// `awk '/^oom_kill /{print $2}'` parity.
func parseOOMKill(events string) (int64, bool) {
	for rest := events; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if m := oomKillRe.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// pruneKills drops timestamps outside the sliding window and returns
// the in-window count — the awk `$1 >= cutoff` + `grep -c` of the
// shell. A missing/garbage file counts as 0.
func (c *LoopCheck) pruneKills(killsPath string, now int64) int {
	data, err := os.ReadFile(killsPath)
	if err != nil {
		return 0
	}
	cutoff := now - int64(c.d.Cfg.OOMLoop.Window.Seconds())
	var kept []string
	for rest := string(data); rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		ts, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err != nil || ts < cutoff {
			continue
		}
		kept = append(kept, strconv.FormatInt(ts, 10))
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	tmp := killsPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"oomloop: kills file %s rewrite failed: %v — stale entries persist",
			killsPath, err))
	} else if err := os.Rename(tmp, killsPath); err != nil {
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"oomloop: kills file %s install failed: %v — stale entries persist",
			killsPath, err))
	}
	return len(kept)
}

// setAdj writes oom_score_adj for the first process named comm —
// `pgrep -x <comm> | head -1` + `echo adj > /proc/pid/oom_score_adj`.
// Idempotent and silent when the process is absent (the shell's
// `|| return 0` / `|| true`).
func (c *LoopCheck) setAdj(comm string, adj int) {
	pid := c.d.Proc.FindByComm(comm)
	if pid == 0 {
		return
	}
	if err := os.WriteFile(c.d.Proc.File(pid, "oom_score_adj"),
		[]byte(strconv.Itoa(adj)), 0o644); err != nil {
		// A swallowed write failure leaves the shield half-applied
		// and invisible — surface it once per call (per cycle).
		c.d.State.AppendLogWarn(fmt.Sprintf(
			"oomloop: write oom_score_adj=%d comm=%s pid=%d failed: %v",
			adj, comm, pid, err))
	}
}
