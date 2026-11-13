package feeder

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
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// Feeder is the sd_notify watchdog feeder — not a Check (it runs on
// its own faster ticker Spawned from the parent's Run, outside the
// dispatch list) but owned by the orchestrator so tests reach it
// through Feeder().
type Feeder struct {
	d *cdeps.Deps
}

// New returns the feeder bound to the shared deps surface.
func New(d *cdeps.Deps) *Feeder { return &Feeder{d: d} }

// peerAPIServerRe matches PEER_APISERVER="https://ip:6443" in the
// remediate peer file.
var peerAPIServerRe = regexp.MustCompile(`(?m)^PEER_APISERVER=(.*)$`)

// Run is the feeder's forever loop — it only returns when ctx
// is cancelled. One tracked k0scontroller instance at a time.
func (f *Feeder) Run(ctx context.Context) {
	// Snapshot ONLY the feeder sub-config + restart unit — never the
	// whole cfg: Cycle's refreshWatchdogConf rewrites the
	// watchdog-conf-derived groups (Hub/Sig13/KineTTL/KinePool/
	// OOMLoop) on the same struct, and a whole-Config copy would
	// race that refresh (workerhygiene's feederWatchdogConf parity:
	// the feeder goroutine must not touch mutable cfg fields).
	// Feeder.* and RestartUnit are not conf-derived — immutable
	// after New.
	fcfg := f.d.Cfg.Feeder
	unit := f.d.Cfg.RestartUnit
	// The gauge must not pin at 1 once the loop exits (ctx cancel
	// or a recovered panic in the wrapper) — it would advertise
	// "still feeding" while WATCHDOG=1 has stopped.
	defer f.d.Feeding.Set(0)

	mainPID := f.waitMainPID(ctx, unit)
	if mainPID == 0 {
		return // ctx cancelled while waiting
	}
	f.d.State.AppendLog(fmt.Sprintf("feeder: start %s.MainPID=%d interval=%ds url=%s",
		unit, mainPID, int(fcfg.Interval.Seconds()), fcfg.ProbeURL))

	fails := 0
	everOK := false
	// Reusable cycle timer: Reset re-arms from end-of-work before each
	// wait (time.After parity) instead of allocating a new timer per
	// cycle; a Reset also supersedes any tick that fired mid-cycle.
	timer := time.NewTimer(fcfg.Interval)
	defer timer.Stop()
	for {
		// MainPID drift: readable-and-different → the instance we
		// tracked ended (MainPID 0 = the unit lost its main
		// process). Re-arm grace like a fresh feeder unit (PartOf
		// restart parity). A read ERROR is a transient probe
		// failure — never counts as an instance change.
		if now, err := f.d.MainPID(ctx, unit); err == nil && now != mainPID {
			f.d.State.AppendLog(fmt.Sprintf(
				"feeder: %s.MainPID changed (%d -> %d) — instance ended, re-arming grace",
				unit, mainPID, now))
			mainPID = now
			fails = 0
			everOK = false
		}

		alive := f.d.Cfg.ProbeFn(ctx, fcfg.ProbeURL)
		doFeed := false
		if alive {
			everOK = true
			fails = 0
			doFeed = true
		} else {
			fails++
			// spof-streak: the post-arm MaxFail streak doubles on a
			// single-controller topology (startup GraceFails stays
			// — it never gates a restart, only the first feed).
			limit := f.d.StreakCycles(fcfg.MaxFail)
			if !everOK {
				limit = fcfg.GraceFails
			}
			f.d.State.AppendLog(fmt.Sprintf("feeder: probe fail %d/%d", fails, limit))
			if fails >= limit {
				f.d.State.AppendLog(fmt.Sprintf(
					"feeder: %d consecutive fails — running remediation gates (shell exit 1 → OnFailure parity)",
					fails))
				f.RunRemediate(ctx)
				// Re-arm like the unit's Restart=always: fresh grace
				// for whatever comes back (or the next fails round).
				fails = 0
				everOK = false
				// The shell's exit-1 round ENDED here — no feed this
				// iteration. Feeding right after remediate would let
				// a notify failure invoke RunRemediate a second time
				// in the same iteration (double-remediate edge).
				f.d.Feeding.Set(0)
			} else {
				// Startup grace: never probe-OK yet → keep feeding
				// (the apiserver may still be initialising — FM3).
				// Past first success → stop feeding so a wedge trips
				// the watchdog.
				doFeed = !everOK
			}
		}

		if doFeed {
			if err := f.d.Cfg.NotifyFn("WATCHDOG=1"); err != nil {
				f.d.State.AppendLogWarn(fmt.Sprintf(
					"feeder: sd_notify FAIL (%v) — running remediation gates (loud death instead of masking the watchdog)",
					err))
				f.RunRemediate(ctx)
				fails = 0
				everOK = false
			} else {
				f.d.Feeding.Set(1)
				f.d.Actions.WithLabelValues(cdeps.CheckFeeder, "feed").Inc()
			}
		} else {
			f.d.Feeding.Set(0)
		}

		timer.Reset(fcfg.Interval)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// waitMainPID polls the shared systemd client's MainPID property
// read until a non-zero pid is readable — the feeder start-time
// `exit 0 + Restart=always retry` mapped into an in-process wait.
func (f *Feeder) waitMainPID(ctx context.Context, unit string) uint32 {
	timer := time.NewTimer(f.d.Cfg.Feeder.Interval)
	defer timer.Stop()
	for {
		if mp, err := f.d.MainPID(ctx, unit); err == nil && mp != 0 {
			return mp
		}
		timer.Reset(f.d.Cfg.Feeder.Interval)
		select {
		case <-ctx.Done():
			return 0
		case <-timer.C:
		}
	}
}

// unitProp reads a systemd property — empty string on any failure
// (shell `| tr -d '[:space:]'` + `|| true` parity).
func (f *Feeder) unitProp(ctx context.Context, unit, prop string) string {
	out, err := f.d.UnitProp(ctx, unit, prop)
	if err != nil {
		return ""
	}
	return out
}

// RunRemediate is the G1..G6 ordered-gate port of
// k0scontroller-remediate.sh. A feeder failure does NOT prove the
// apiserver is dead (the feeder may have self-wedged/missed a
// notify) — every gate is a chance to stop before the restart.
func (f *Feeder) RunRemediate(ctx context.Context) {
	// Same narrow-snapshot rule as Run: a whole-Config copy
	// would race Cycle's refreshWatchdogConf writes; Feeder.* and
	// RestartUnit are immutable after New.
	fcfg := f.d.Cfg.Feeder
	unit := f.d.Cfg.RestartUnit
	f.d.Actions.WithLabelValues(cdeps.CheckFeeder, "remediate").Inc()
	f.d.State.AppendLog("remediate: OnFailure trigger — running ordered gates before restart of " + unit)

	// G1: re-probe twice 3s apart — one answer = apiserver alive =
	// false alarm (self-correcting).
	for i := 1; i <= 2; i++ {
		if f.d.Cfg.ProbeFn(ctx, fcfg.ProbeURL) {
			f.d.State.AppendLog(fmt.Sprintf(
				"G1 PASS: apiserver answered on probe %d — false alarm, no restart", i))
			return
		}
		if i < 2 {
			f.d.Cfg.SleepFn(3 * time.Second)
		}
	}
	f.d.State.AppendLog("G1: apiserver failed 2 probes 3s apart — process-level wedge signature, continuing")

	// G2: unit not active = something else is already restarting it
	// (operator, PartOf chain, OOM) — never pile on.
	state := f.d.UnitActiveState(ctx, unit)
	if state != "active" {
		f.d.State.AppendLog(fmt.Sprintf("G2 PASS: %s is-active='%s' (!= active) — already restarting, stop", unit, state))
		return
	}
	f.d.State.AppendLog("G2: " + unit + " still 'active' — process alive but apiserver not serving, wedge signature")

	// G3: fresh-start grace. Age must come from ONE clock domain:
	// ActiveEnterTimestampMonotonic is CLOCK_MONOTONIC while
	// /proc/uptime counts suspend time, so uptime-mono inflates the
	// unit's age by every suspend since boot — a host that slept
	// passes the grace gate instantly and restarts mid-init. The
	// wall-clock ActiveEnterTimestamp vs Clock.Now() is
	// clock-consistent.
	ts := f.unitProp(ctx, unit, "ActiveEnterTimestamp")
	entered, terr := ParseSystemdTimestamp(ts)
	if terr != nil {
		f.d.State.AppendLog(fmt.Sprintf(
			"G3 PASS: unreadable ActiveEnterTimestamp='%s' (%v) — never restart blind, stop",
			ts, terr))
		return
	}
	ageS := int64(f.d.Cfg.Clock.Now().Sub(entered).Seconds())
	if ageS < int64(fcfg.RemediateFreshGrace.Seconds()) {
		f.d.State.AppendLog(fmt.Sprintf(
			"G3 PASS: %s started %ds ago (< %ds grace) — apiserver may still be initialising, stop",
			unit, ageS, int(fcfg.RemediateFreshGrace.Seconds())))
		return
	}
	f.d.State.AppendLog(fmt.Sprintf("G3: %s running %ds — not a fresh start", unit, ageS))

	// G4: optional peer fence — WARN only, never blocks (a dead
	// local apiserver is not made worse by restarting it).
	if peer := f.PeerAPIServer(); peer != "" {
		if f.d.Cfg.ProbeFn(ctx, peer) {
			f.d.State.AppendLog(fmt.Sprintf("G4: peer %s alive — wedge is local-only", peer))
		} else {
			f.d.State.AppendLogWarn(fmt.Sprintf(
				"G4 WARNING: peer %s ALSO not answering — both controllers may be triggering; restarting anyway (local is dead)",
				peer))
		}
	} else {
		f.d.State.AppendLog("G4: no PEER_APISERVER configured — peer fence skipped")
	}

	// G5: rate-limit — at most one restart per RemediateMinRestart,
	// on the SHARED k0scontroller budget (FileRateRestart under
	// WatchdogStateDir): a sig13/cp-freeze/pki-drift restart
	// seconds earlier must cool this remediate down too — one
	// floor for every k0scontroller restart this subsystem can
	// fire. The epoch read below only feeds the log line; the
	// atomic check+spend is RateTrySpend at the G6 spend point
	// (the old feeder-private last-restart file under
	// FeederStateDir could not see the other checks' spends).
	lastShared := f.d.State.Epoch(
		filepath.Join(f.d.State.Dir, cdeps.FileRateRestart))
	delta := f.d.Cfg.Clock.Now().Unix() - lastShared
	if delta < int64(fcfg.RemediateMinRestart.Seconds()) {
		f.d.State.AppendLog(fmt.Sprintf(
			"G5 PASS: last restart %ds ago (< %ds) — rate-limit, stop",
			delta, int(fcfg.RemediateMinRestart.Seconds())))
		return
	}
	f.d.State.AppendLog(fmt.Sprintf("G5: previous restart %ds ago — allowed", delta))

	// L1↔L3 maintenance hold: a cluster-side drain/upgrade is already
	// cycling this node — the feeder must not stack a remediate
	// restart on top. Checked after G5 so the stale-restart evidence
	// still lands in the log, before any budget is spent.
	if f.d.HoldEmergencyHeal(ctx) {
		f.d.State.AppendLog("G6 PASS: cluster maintenance in progress — holding restart")
		return
	}

	// G6: restart. The unit's PartOf fans the restart out to the
	// watchdog unit → feeder gets fresh startup grace.
	//
	// The budget is spent BEFORE the restart call (shell stamped the
	// epoch on success, but the remediate script ran as a oneshot —
	// a watchdog kill mid-restart could not restart it again). In-agent
	// a killed/hung restart exec with an unwritten budget would allow a
	// second restart inside the 1800s window. RateTrySpend re-checks
	// and stamps atomically under the Store mutex — a sig13/cp-freeze/
	// pki spend landing between G5 and here fails the try and the
	// restart is skipped instead of double-bouncing the controller.
	f.d.State.AppendLog("G6: all gates passed — systemctl restart " + unit)
	if !f.d.State.RateTrySpend(cdeps.FileRateRestart, fcfg.RemediateMinRestart) {
		f.d.State.AppendLog("G6 PASS: shared restart budget spent concurrently — stop")
		return
	}
	if err := f.d.Restart(ctx, unit); err != nil {
		f.d.State.AppendLogWarn(fmt.Sprintf("G6: restart %s FAIL: %v (budget spent)", unit, err))
		return
	}
	f.d.State.AppendLog(fmt.Sprintf(
		"G6: restart %s OK (rate-limit mark epoch=%d)", unit, f.d.Cfg.Clock.Now().Unix()))
	f.d.Actions.WithLabelValues(cdeps.CheckFeeder, "restart_controller").Inc()
}

// peerAPIServer reads PEER_APISERVER="https://ip:6443" out of the
// remediate peer file — the sed 's/^PEER_APISERVER=//p' + strip
// quotes/space parity.
func (f *Feeder) PeerAPIServer() string {
	data, err := os.ReadFile(f.d.Cfg.Feeder.RemediatePeerFile)
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

// SystemdTimestampLayout is systemctl's "--value" wall-clock
// timestamp format — "Mon 2006-01-02 15:04:05 UTC" (day-abbrev
// prefix + local time + zone abbrev).
const SystemdTimestampLayout = "Mon 2006-01-02 15:04:05 MST"

// systemdTimestampLayoutBare is SystemdTimestampLayout minus the
// trailing zone field — the fallback parses below re-read the wall
// fields once the zone abbrev has been resolved (or given up on)
// out of band.
const systemdTimestampLayoutBare = "Mon 2006-01-02 15:04:05"

// ParseSystemdTimestamp parses a wall-clock systemd property value
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
func ParseSystemdTimestamp(v string) (time.Time, error) {
	s := strings.TrimSpace(v)
	t, err := time.ParseInLocation(SystemdTimestampLayout, s, time.Local)
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
