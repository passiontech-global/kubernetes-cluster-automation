package controllerhygiene

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
	"strconv"
	"strings"
)

// checkOOMLoop runs one OOM-loop guard cycle.
func (h *Hygiene) checkOOMLoop(_ context.Context) {
	events, err := os.ReadFile(h.cfg.CGroupEventsFile)
	if err != nil {
		// Not a cgroup-v2 controller (or path not mounted) — the
		// shell exited 0 the same way.
		h.cycles.WithLabelValues(checkOOMLoop, "no_events").Inc()
		return
	}
	oomNow, ok := parseOOMKill(string(events))
	if !ok {
		h.cycles.WithLabelValues(checkOOMLoop, "ok").Inc()
		return
	}

	dir := h.cfg.WatchdogStateDir
	now := h.cfg.nowFn().Unix()

	// First run (no baseline file): seed the baseline only — the
	// counter is cumulative since cgroup creation, so counting it
	// now would latch instantly on pre-probe history.
	seenPath := filepath.Join(dir, fileOOMSeen)
	_, statErr := os.Stat(seenPath)
	hadBaseline := statErr == nil
	prev := h.readEpoch(seenPath)
	h.writeState(fileOOMSeen, strconv.FormatInt(oomNow, 10))

	killsPath := filepath.Join(dir, fileOOMKills)
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
		}
		h.appendLog(fmt.Sprintf(
			"oomloop-probe: %d new memcg OOM kill(s) in k0scontroller (cum=%d)",
			d, oomNow))
	}

	inWindow := h.pruneKills(killsPath, now)
	h.oomWindow.Set(float64(inWindow))

	if inWindow < h.cfg.OOMLoopMinKills {
		if _, err := os.Stat(filepath.Join(dir, fileOOMShielded)); err == nil {
			// Loop cleared: remove the shield — apiserver must not
			// stay protected forever (a genuine runaway apiserver
			// has to remain killable).
			h.appendLog("oom-loop clear — unshield kube-apiserver/kine (oom_score_adj=0)")
			h.setAdj("kube-apiserver", 0)
			h.setAdj("kine", 0)
			_ = removeStateFile(dir, fileOOMShielded)
			h.actions.WithLabelValues(checkOOMLoop, "unshield").Inc()
		}
		h.stateExit(stateControllerOOMLop)
		h.cycles.WithLabelValues(checkOOMLoop, "ok").Inc()
		return
	}

	// --- OOM loop confirmed ---
	h.stateEnter(stateControllerOOMLop, fmt.Sprintf(
		"oom_kills_window=%d/%d in %ds (cum=%d)",
		inWindow, h.cfg.OOMLoopMinKills,
		int(h.cfg.OOMLoopWindow.Seconds()), oomNow))

	switch h.cfg.OOMLoopMode {
	case ModeEnforce:
		// Idempotent: PIDs change on every respawn so the shield is
		// re-applied every cycle while the loop is latched.
		h.appendLog(fmt.Sprintf(
			"ACTION: shield kube-apiserver (oom_score_adj=%d), kine %+d — window_kills=%d",
			h.cfg.APIServerShieldAdj, h.cfg.KineShieldAdj, inWindow))
		h.setAdj("kube-apiserver", h.cfg.APIServerShieldAdj)
		h.setAdj("kine", h.cfg.KineShieldAdj)
		h.writeState(fileOOMShielded, "")
		h.actions.WithLabelValues(checkOOMLoop, "shield").Inc()
	case ModeDryRun:
		h.appendLog(fmt.Sprintf(
			"DRY-RUN: would shield kube-apiserver oom_score_adj=%d, kine %+d — window_kills=%d",
			h.cfg.APIServerShieldAdj, h.cfg.KineShieldAdj, inWindow))
		h.actions.WithLabelValues(checkOOMLoop, "dryrun_shield").Inc()
	}
	h.cycles.WithLabelValues(checkOOMLoop, "ok").Inc()
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
func (h *Hygiene) pruneKills(killsPath string, now int64) int {
	data, err := os.ReadFile(killsPath)
	if err != nil {
		return 0
	}
	cutoff := now - int64(h.cfg.OOMLoopWindow.Seconds())
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
	if err := os.WriteFile(tmp, []byte(content), 0o644); err == nil {
		_ = os.Rename(tmp, killsPath)
	}
	return len(kept)
}

// setAdj writes oom_score_adj for the first process named comm —
// `pgrep -x <comm> | head -1` + `echo adj > /proc/pid/oom_score_adj`.
// Idempotent and silent when the process is absent (the shell's
// `|| return 0` / `|| true`).
func (h *Hygiene) setAdj(comm string, adj int) {
	pid := h.findProcByComm(comm)
	if pid == 0 {
		return
	}
	if err := os.WriteFile(h.procFile(pid, "oom_score_adj"),
		[]byte(strconv.Itoa(adj)), 0o644); err != nil {
		// A swallowed write failure leaves the shield half-applied
		// and invisible — surface it once per call (per cycle).
		h.appendLogWarn(fmt.Sprintf(
			"oomloop: write oom_score_adj=%d comm=%s pid=%d failed: %v",
			adj, comm, pid, err))
	}
}
