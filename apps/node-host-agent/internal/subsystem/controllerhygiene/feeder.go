package controllerhygiene

// feeder.go — port of scripts/k0s-systemd-watchdog-feeder.sh and the
// OnFailure companion scripts/k0scontroller-remediate.sh (Option-D
// dedicated watchdog unit), mirroring k0s-kubelet-watchdog.sh's
// worker-side semantics.
//
// Why it exists: the k0s binary never sd_notifies (verified at source
// v1.36.4+k0s.0 — supervised is a nil stub on Linux, kardianos has no
// sd_notify) and a controller has no kubelet to feed for it. So a
// feeder loop sends WATCHDOG=1 to the unit's notify socket every
// FeedInterval while the LOCAL apiserver answers ANY HTTP code —
// readyz content is not gated (a missing-storage 200 is not the
// target; a process-level wedge that stops accepting TLS is).
//
// Semantics (1:1):
//   - Startup grace: before the FIRST successful probe, up to
//     FeedGraceFails consecutive failures still feed — the apiserver
//     may take 30-120s to listen (FM3 lesson: an armed watchdog would
//     otherwise kill the unit during every slow init). After the
//     first success, FeedMaxFail consecutive failures trip the
//     failure path.
//   - The failure path in shell is `exit 1` → unit failed →
//     OnFailure=...-restart.service → remediate script. In-agent the
//     equivalent is: run the remediation gates inline, then re-arm
//     (the unit's Restart=always would do the same).
//   - Instance tracking: a changed k0scontroller MainPID means the
//     watched instance ended — the shell exits 0 cleanly (PartOf
//     restarts the unit with the controller); in-agent this re-arms
//     the feeder with fresh grace.
//   - Notify failure → failure path immediately (loud death instead
//     of masking a watchdog timeout).
//
// Remediate gates (k0scontroller-remediate.sh, in order — every PASS
// exits without action; restart only when ALL agree):
//   G1 apiserver alive on re-probe x2?   → false alarm, stop
//   G2 unit not "active"?                → already restarting, stop
//   G3 fresh-start <90s?                 → still initialising, stop
//   G4 peer apiserver dead too?          → WARN only, never blocks
//   G5 last restart <1800s?              → rate-limited, stop
//   G6 systemctl restart + epoch stamp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// runFeeder is the feeder's forever loop — it only returns when ctx
// is cancelled. One tracked k0scontroller instance at a time.
func (h *Hygiene) runFeeder(ctx context.Context) {
	cfg := h.cfg
	unit := cfg.RestartUnit

	mainPID := h.waitMainPID(ctx, unit)
	if mainPID == "" {
		return // ctx cancelled while waiting
	}
	h.appendLog(fmt.Sprintf("feeder: start %s.MainPID=%s interval=%ds url=%s",
		unit, mainPID, int(cfg.FeedInterval.Seconds()), cfg.FeedProbeURL))

	fails := 0
	everOK := false
	for {
		// MainPID drift: readable-and-different → the instance we
		// tracked ended. Re-arm grace like a fresh feeder unit
		// (PartOf restart parity). An EMPTY read is a transient
		// systemctl failure — never counts as an instance change.
		if now := h.unitProp(ctx, unit, "MainPID"); now != "" && now != mainPID {
			h.appendLog(fmt.Sprintf(
				"feeder: %s.MainPID changed (%s -> %s) — instance ended, re-arming grace",
				unit, mainPID, now))
			mainPID = now
			fails = 0
			everOK = false
		}

		alive := h.cfg.probeFn(ctx, cfg.FeedProbeURL)
		doFeed := false
		if alive {
			everOK = true
			fails = 0
			doFeed = true
		} else {
			fails++
			limit := cfg.FeedMaxFail
			if !everOK {
				limit = cfg.FeedGraceFails
			}
			h.appendLog(fmt.Sprintf("feeder: probe fail %d/%d", fails, limit))
			if fails >= limit {
				h.appendLog(fmt.Sprintf(
					"feeder: %d consecutive fails — running remediation gates (shell exit 1 → OnFailure parity)",
					fails))
				h.runRemediate(ctx)
				// Re-arm like the unit's Restart=always: fresh grace
				// for whatever comes back (or the next fails round).
				fails = 0
				everOK = false
				// The shell's exit-1 round ENDED here — no feed this
				// iteration. Feeding right after remediate would let
				// a notify failure invoke runRemediate a second time
				// in the same iteration (double-remediate edge).
				h.feeding.Set(0)
			} else {
				// Startup grace: never probe-OK yet → keep feeding
				// (the apiserver may still be initialising — FM3).
				// Past first success → stop feeding so a wedge trips
				// the watchdog.
				doFeed = !everOK
			}
		}

		if doFeed {
			if err := h.cfg.notifyFn("WATCHDOG=1"); err != nil {
				h.appendLogWarn(fmt.Sprintf(
					"feeder: sd_notify FAIL (%v) — running remediation gates (loud death instead of masking the watchdog)",
					err))
				h.runRemediate(ctx)
				fails = 0
				everOK = false
			} else {
				h.feeding.Set(1)
				h.actions.WithLabelValues(checkFeeder, "feed").Inc()
			}
		} else {
			h.feeding.Set(0)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.FeedInterval):
		}
	}
}

// waitMainPID polls systemctl show -p MainPID until a non-zero pid is
// readable — the feeder start-time `exit 0 + Restart=always retry`
// mapped into an in-process wait.
func (h *Hygiene) waitMainPID(ctx context.Context, unit string) string {
	for {
		if mp := h.unitProp(ctx, unit, "MainPID"); mp != "" && mp != "0" {
			return mp
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(h.cfg.FeedInterval):
		}
	}
}

// unitProp reads a systemd property — empty string on any failure
// (shell `| tr -d '[:space:]'` + `|| true` parity).
func (h *Hygiene) unitProp(ctx context.Context, unit, prop string) string {
	out, err := h.cfg.propFn(ctx, unit, prop)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// runRemediate is the G1..G6 ordered-gate port of
// k0scontroller-remediate.sh. A feeder failure does NOT prove the
// apiserver is dead (the feeder may have self-wedged/missed a
// notify) — every gate is a chance to stop before the restart.
func (h *Hygiene) runRemediate(ctx context.Context) {
	cfg := h.cfg
	unit := cfg.RestartUnit
	h.actions.WithLabelValues(checkFeeder, "remediate").Inc()
	h.appendLog("remediate: OnFailure trigger — running ordered gates before restart of " + unit)

	// G1: re-probe twice 3s apart — one answer = apiserver alive =
	// false alarm (self-correcting).
	for i := 1; i <= 2; i++ {
		if h.cfg.probeFn(ctx, cfg.FeedProbeURL) {
			h.appendLog(fmt.Sprintf(
				"G1 PASS: apiserver answered on probe %d — false alarm, no restart", i))
			return
		}
		if i < 2 {
			h.cfg.sleepFn(3 * time.Second)
		}
	}
	h.appendLog("G1: apiserver failed 2 probes 3s apart — process-level wedge signature, continuing")

	// G2: unit not active = something else is already restarting it
	// (operator, PartOf chain, OOM) — never pile on.
	state, err := h.cfg.isActive(ctx, unit)
	if err != nil || state != "active" {
		h.appendLog(fmt.Sprintf("G2 PASS: %s is-active='%s' (!= active) — already restarting, stop", unit, state))
		return
	}
	h.appendLog("G2: " + unit + " still 'active' — process alive but apiserver not serving, wedge signature")

	// G3: fresh-start grace. ActiveEnterTimestampMonotonic resets on
	// every start; age = uptime_us - mono_us.
	mono := h.unitProp(ctx, unit, "ActiveEnterTimestampMonotonic")
	monoUS, err1 := strconv.ParseInt(mono, 10, 64)
	upS, err2 := h.uptimeSeconds()
	if err1 != nil || err2 != nil {
		h.appendLog(fmt.Sprintf(
			"G3 PASS: unreadable timestamp (mono='%s' uptime=%v) — never restart blind, stop",
			mono, err2))
		return
	}
	ageS := int64((upS*1e6 - float64(monoUS)) / 1e6)
	if ageS < int64(cfg.RemediateFreshGrace.Seconds()) {
		h.appendLog(fmt.Sprintf(
			"G3 PASS: %s started %ds ago (< %ds grace) — apiserver may still be initialising, stop",
			unit, ageS, int(cfg.RemediateFreshGrace.Seconds())))
		return
	}
	h.appendLog(fmt.Sprintf("G3: %s running %ds — not a fresh start", unit, ageS))

	// G4: optional peer fence — WARN only, never blocks (a dead
	// local apiserver is not made worse by restarting it).
	if peer := h.peerAPIServer(); peer != "" {
		if h.cfg.probeFn(ctx, peer) {
			h.appendLog(fmt.Sprintf("G4: peer %s alive — wedge is local-only", peer))
		} else {
			h.appendLogWarn(fmt.Sprintf(
				"G4 WARNING: peer %s ALSO not answering — both controllers may be triggering; restarting anyway (local is dead)",
				peer))
		}
	} else {
		h.appendLog("G4: no PEER_APISERVER configured — peer fence skipped")
	}

	// G5: rate-limit — at most one restart per RemediateMinRestart,
	// budget file last-restart under FeederStateDir.
	lastPath := filepath.Join(cfg.FeederStateDir, fileFeederLastRst)
	delta := h.cfg.nowFn().Unix() - h.readEpoch(lastPath)
	if delta < int64(cfg.RemediateMinRestart.Seconds()) {
		h.appendLog(fmt.Sprintf(
			"G5 PASS: last restart %ds ago (< %ds) — rate-limit, stop",
			delta, int(cfg.RemediateMinRestart.Seconds())))
		return
	}
	h.appendLog(fmt.Sprintf("G5: previous restart %ds ago — allowed", delta))

	// G6: restart. The unit's PartOf fans the restart out to the
	// watchdog unit → feeder gets fresh startup grace.
	//
	// The budget is spent BEFORE the restart call (shell stamped the
	// epoch on success, but the remediate script ran as a oneshot —
	// a watchdog kill mid-restart could not restart it again). In-agent
	// a killed/hung restartFn with an unwritten budget would allow a
	// second restart inside the 1800s window. FeederStateDir may not
	// exist yet (mkdir -p parity) — create it so the mark lands.
	if err := os.MkdirAll(cfg.FeederStateDir, 0o755); err != nil {
		h.appendLogWarn(fmt.Sprintf("G6: mkdir %s failed: %v — restart skipped (budget file must exist)",
			cfg.FeederStateDir, err))
		return
	}
	h.appendLog("G6: all gates passed — systemctl restart " + unit)
	h.writeEpochFile(lastPath)
	if err := h.cfg.restartFn(ctx, unit); err != nil {
		h.appendLogWarn(fmt.Sprintf("G6: restart %s FAIL: %v (budget spent)", unit, err))
		return
	}
	h.appendLog(fmt.Sprintf(
		"G6: restart %s OK (rate-limit mark epoch=%d)", unit, h.cfg.nowFn().Unix()))
	h.actions.WithLabelValues(checkFeeder, "restart_controller").Inc()
}

// peerAPIServer reads PEER_APISERVER="https://ip:6443" out of the
// remediate peer file — the sed 's/^PEER_APISERVER=//p' + strip
// quotes/space parity.
func (h *Hygiene) peerAPIServer() string {
	data, err := os.ReadFile(h.cfg.RemediatePeerFile)
	if err != nil {
		return ""
	}
	// `... | tail -n 1` parity: the LAST assignment wins.
	matches := peerAPIServerRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return ""
	}
	return strings.Trim(string(matches[len(matches)-1][1]), `"' `+"\t")
}
