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
	"strings"
	"time"
)

// runFeeder is the feeder's forever loop — it only returns when ctx
// is cancelled. One tracked k0scontroller instance at a time.
func (h *Hygiene) runFeeder(ctx context.Context) {
	cfg := h.cfg
	unit := cfg.RestartUnit
	// The gauge must not pin at 1 once the loop exits (ctx cancel
	// or a recovered panic in the wrapper) — it would advertise
	// "still feeding" while WATCHDOG=1 has stopped.
	defer h.feeding.Set(0)

	mainPID := h.waitMainPID(ctx, unit)
	if mainPID == "" {
		return // ctx cancelled while waiting
	}
	h.state.AppendLog(fmt.Sprintf("feeder: start %s.MainPID=%s interval=%ds url=%s",
		unit, mainPID, int(cfg.FeedInterval.Seconds()), cfg.FeedProbeURL))

	fails := 0
	everOK := false
	for {
		// MainPID drift: readable-and-different → the instance we
		// tracked ended. Re-arm grace like a fresh feeder unit
		// (PartOf restart parity). An EMPTY read is a transient
		// systemctl failure — never counts as an instance change.
		if now := h.unitProp(ctx, unit, "MainPID"); now != "" && now != mainPID {
			h.state.AppendLog(fmt.Sprintf(
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
			h.state.AppendLog(fmt.Sprintf("feeder: probe fail %d/%d", fails, limit))
			if fails >= limit {
				h.state.AppendLog(fmt.Sprintf(
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
				h.state.AppendLogWarn(fmt.Sprintf(
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
	h.state.AppendLog("remediate: OnFailure trigger — running ordered gates before restart of " + unit)

	// G1: re-probe twice 3s apart — one answer = apiserver alive =
	// false alarm (self-correcting).
	for i := 1; i <= 2; i++ {
		if h.cfg.probeFn(ctx, cfg.FeedProbeURL) {
			h.state.AppendLog(fmt.Sprintf(
				"G1 PASS: apiserver answered on probe %d — false alarm, no restart", i))
			return
		}
		if i < 2 {
			h.cfg.sleepFn(3 * time.Second)
		}
	}
	h.state.AppendLog("G1: apiserver failed 2 probes 3s apart — process-level wedge signature, continuing")

	// G2: unit not active = something else is already restarting it
	// (operator, PartOf chain, OOM) — never pile on.
	state, err := h.cfg.isActive(ctx, unit)
	if err != nil || state != "active" {
		h.state.AppendLog(fmt.Sprintf("G2 PASS: %s is-active='%s' (!= active) — already restarting, stop", unit, state))
		return
	}
	h.state.AppendLog("G2: " + unit + " still 'active' — process alive but apiserver not serving, wedge signature")

	// G3: fresh-start grace. Age must come from ONE clock domain:
	// ActiveEnterTimestampMonotonic is CLOCK_MONOTONIC while
	// /proc/uptime counts suspend time, so uptime-mono inflates the
	// unit's age by every suspend since boot — a host that slept
	// passes the grace gate instantly and restarts mid-init. The
	// wall-clock ActiveEnterTimestamp vs nowFn() is
	// clock-consistent.
	ts := h.unitProp(ctx, unit, "ActiveEnterTimestamp")
	entered, terr := parseSystemdTimestamp(ts)
	if terr != nil {
		h.state.AppendLog(fmt.Sprintf(
			"G3 PASS: unreadable ActiveEnterTimestamp='%s' (%v) — never restart blind, stop",
			ts, terr))
		return
	}
	ageS := int64(h.cfg.nowFn().Sub(entered).Seconds())
	if ageS < int64(cfg.RemediateFreshGrace.Seconds()) {
		h.state.AppendLog(fmt.Sprintf(
			"G3 PASS: %s started %ds ago (< %ds grace) — apiserver may still be initialising, stop",
			unit, ageS, int(cfg.RemediateFreshGrace.Seconds())))
		return
	}
	h.state.AppendLog(fmt.Sprintf("G3: %s running %ds — not a fresh start", unit, ageS))

	// G4: optional peer fence — WARN only, never blocks (a dead
	// local apiserver is not made worse by restarting it).
	if peer := h.peerAPIServer(); peer != "" {
		if h.cfg.probeFn(ctx, peer) {
			h.state.AppendLog(fmt.Sprintf("G4: peer %s alive — wedge is local-only", peer))
		} else {
			h.state.AppendLogWarn(fmt.Sprintf(
				"G4 WARNING: peer %s ALSO not answering — both controllers may be triggering; restarting anyway (local is dead)",
				peer))
		}
	} else {
		h.state.AppendLog("G4: no PEER_APISERVER configured — peer fence skipped")
	}

	// G5: rate-limit — at most one restart per RemediateMinRestart,
	// budget file last-restart under FeederStateDir. The
	// read-epoch/compare/write-epoch runs under rateMu: the file
	// stays the cross-process contract, but in-process
	// check-then-act without the mutex lets two overlapping
	// remediate passes both see "allowed" inside one window
	// (TOCTOU double-restart — workerhygiene rateTrySpend parity).
	// Store.RateTrySpend can't serve this budget: it operates on
	// the Store's Dir (WatchdogStateDir), and last-restart lives
	// under FeederStateDir instead.
	h.rateMu.Lock()
	lastPath := filepath.Join(cfg.FeederStateDir, fileFeederLastRst)
	delta := h.cfg.nowFn().Unix() - h.state.Epoch(lastPath)
	if delta < int64(cfg.RemediateMinRestart.Seconds()) {
		h.rateMu.Unlock()
		h.state.AppendLog(fmt.Sprintf(
			"G5 PASS: last restart %ds ago (< %ds) — rate-limit, stop",
			delta, int(cfg.RemediateMinRestart.Seconds())))
		return
	}
	h.state.AppendLog(fmt.Sprintf("G5: previous restart %ds ago — allowed", delta))

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
		h.rateMu.Unlock()
		h.state.AppendLogWarn(fmt.Sprintf("G6: mkdir %s failed: %v — restart skipped (budget file must exist)",
			cfg.FeederStateDir, err))
		return
	}
	h.state.AppendLog("G6: all gates passed — systemctl restart " + unit)
	h.state.WriteEpochFile(lastPath, h.cfg.nowFn().Unix())
	h.rateMu.Unlock()
	if err := h.cfg.restartFn(ctx, unit); err != nil {
		h.state.AppendLogWarn(fmt.Sprintf("G6: restart %s FAIL: %v (budget spent)", unit, err))
		return
	}
	h.state.AppendLog(fmt.Sprintf(
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
	// `... | tail -n 1` parity: the LAST assignment wins. The
	// regex captures to EOL, so a CRLF peer file leaves a trailing
	// '\r' on the value — trim it too, or every CRLF file's peer
	// URL is garbage and always probes dead.
	matches := peerAPIServerRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return ""
	}
	return strings.Trim(string(matches[len(matches)-1][1]), `"' `+"\t\r")
}

// systemdTimestampLayout is systemctl's "--value" wall-clock
// timestamp format — "Mon 2006-01-02 15:04:05 UTC" (day-abbrev
// prefix + local time + zone abbrev).
const systemdTimestampLayout = "Mon 2006-01-02 15:04:05 MST"

// systemdTimestampLayoutBare is systemdTimestampLayout minus the
// trailing zone field — the fallback parses below re-read the wall
// fields once the zone abbrev has been resolved (or given up on)
// out of band.
const systemdTimestampLayoutBare = "Mon 2006-01-02 15:04:05"

// parseSystemdTimestamp parses a wall-clock systemd property value
// (ActiveEnterTimestamp & friends). "n/a"/empty/garbage fail parse —
// callers treat that as "never act blind".
//
// The emitted zone abbrev resolves most-exact first:
//
//  1. In time.Local — the normal same-host case, DST included. Go
//     flags that path by keeping the result's Location() pinned to
//     time.Local.
//  2. An abbrev Local does NOT define (the agent's TZ disagrees with
//     the zone systemd stamped — e.g. a TZ=UTC agent on a CET host)
//     makes Go FABRICATE a zero-offset location: the instant shifts
//     by the real offset and the G3 age inflates by it, under-firing
//     the fresh-start grace. On fabrication the abbrev is retried as
//     an IANA zone name — the tz database carries the POSIX abbrevs
//     (CET, EST, MST, MET, EET, WET, GMT...) as real zones, so "CET"
//     recovers the +1 the fabrication dropped. The re-parse is only
//     trusted when that zone reproduces the stamped abbrev at that
//     instant (a summer wall time stamped "CET" stays unresolvable).
//  3. Otherwise (no tzdata, a DST-only abbrev like CEST, garbage):
//     the wall fields parse in UTC. Residual error: ± the emitting
//     zone's real offset — bounded by the host's own TZ delta, never
//     by an arbitrary agent-vs-host TZ gap, and the result honestly
//     reports UTC instead of a fake "+00:00 <abbrev>" zone.
func parseSystemdTimestamp(v string) (time.Time, error) {
	s := strings.TrimSpace(v)
	t, err := time.ParseInLocation(systemdTimestampLayout, s, time.Local)
	if err != nil {
		return time.Time{}, err
	}
	if t.Location() == time.Local {
		return t, nil // abbrev defined in Local — exact
	}
	// Fabricated/foreign zone: split the abbrev off (the layout's
	// last whitespace-separated field) and re-parse the wall fields
	// under the best resolvable zone.
	i := strings.LastIndexByte(s, ' ')
	if i < 0 {
		return t, nil // unreachable after a successful layout parse
	}
	wall, abbrev := s[:i], s[i+1:]
	if loc, lerr := time.LoadLocation(abbrev); lerr == nil {
		if tw, werr := time.ParseInLocation(
			systemdTimestampLayoutBare, wall, loc); werr == nil {
			if name, _ := tw.Zone(); name == abbrev {
				return tw, nil
			}
		}
	}
	if tu, uerr := time.Parse(systemdTimestampLayoutBare, wall); uerr == nil {
		return tu, nil
	}
	return t, nil
}
