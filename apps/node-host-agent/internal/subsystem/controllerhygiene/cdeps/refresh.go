// refresh.go — the per-cycle watchdogconf knob re-apply (BUG-H9):
// hostconfig rewrites /etc/node-watchdog.conf mid-run, so the
// conf-derived knobs refresh before the checks consume them.
package cdeps

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// RefreshWatchdogConf re-applies the watchdogconf-derived knobs each
// cycle when WatchdogSrc is wired (BUG-H9 — nethealth's per-cycle
// WatchdogSrc.Get parity). The conf is one of several config sources:
// an env-set or programmatic knob must survive a conf rewrite, so a
// field only moves when it still carries the value the PREVIOUS conf
// parse produced (WdApplied). Empty conf keys derive to the package
// default — the same ${VAR:-def} fallback main's envOr chain applied
// at construction.
func (d *Deps) RefreshWatchdogConf() {
	if d.Cfg.WatchdogSrc == nil {
		return
	}
	wd := d.Cfg.WatchdogSrc.Get()
	if wd == nil || wd == d.WdApplied {
		return
	}
	old := d.WdApplied
	if old == nil {
		old, _ = watchdogconf.Parse(nil)
	}
	// Each knob only moves when it still carries the previous
	// conf-derived value — a knob set from elsewhere (env wiring)
	// keeps its override.
	apply := func(prev, next string, set func(string), cur func() string) {
		if cur() == prev {
			set(next)
		}
	}
	// Strings.
	apply(old.APISelf, wd.APISelf, func(v string) { d.Cfg.Hub.SelfAPI = v },
		func() string { return d.Cfg.Hub.SelfAPI })
	apply(old.APIPeer, wd.APIPeer, func(v string) { d.Cfg.Hub.PeerAPI = v },
		func() string { return d.Cfg.Hub.PeerAPI })
	apply(old.KineDBProbe, wd.KineDBProbe, func(v string) { d.Cfg.Hub.KineDBProbe = v },
		func() string { return d.Cfg.Hub.KineDBProbe })
	apply(old.Sig13Autofix, wd.Sig13Autofix, func(v string) {
		if v != "" {
			d.Cfg.Sig13.Mode = v
		}
	}, func() string { return d.Cfg.Sig13.Mode })
	apply(old.KineTTLAutofix, wd.KineTTLAutofix, func(v string) {
		if v != "" {
			d.Cfg.KineTTL.Mode = v
		}
	}, func() string { return d.Cfg.KineTTL.Mode })
	apply(old.KinePoolAutofix, wd.KinePoolAutofix, func(v string) {
		if v != "" {
			d.Cfg.KinePool.Mode = v
		}
	}, func() string { return d.Cfg.KinePool.Mode })
	apply(old.OOMLoopAutofix, wd.OOMLoopAutofix, func(v string) {
		if v != "" {
			d.Cfg.OOMLoop.Mode = v
		}
	}, func() string { return d.Cfg.OOMLoop.Mode })
	// Ints — conf 0 derives to the package default.
	intOf := func(v, def int) int {
		if v > 0 {
			return v
		}
		return def
	}
	applyI := func(prevV, nextV int, set func(int), cur func() int) {
		if cur() == prevV {
			set(nextV)
		}
	}
	applyI(intOf(old.Sig13StaleMinErrs, defaultStaleMinErrs),
		intOf(wd.Sig13StaleMinErrs, defaultStaleMinErrs),
		func(v int) { d.Cfg.Sig13.StaleMinErrs = v },
		func() int { return d.Cfg.Sig13.StaleMinErrs })
	applyI(intOf(old.Sig13SoloCycles, defaultSoloCycles),
		intOf(wd.Sig13SoloCycles, defaultSoloCycles),
		func(v int) { d.Cfg.Sig13.SoloCycles = v },
		func() int { return d.Cfg.Sig13.SoloCycles })
	applyI(intOf(old.Sig13GapCycles, defaultGapCycles),
		intOf(wd.Sig13GapCycles, defaultGapCycles),
		func(v int) { d.Cfg.Sig13.GapCycles = v },
		func() int { return d.Cfg.Sig13.GapCycles })
	applyI(intOf(old.Sig13FrozenCycles, defaultFrozenCycles),
		intOf(wd.Sig13FrozenCycles, defaultFrozenCycles),
		func(v int) { d.Cfg.Sig13.FrozenCycles = v },
		func() int { return d.Cfg.Sig13.FrozenCycles })
	applyI(intOf(old.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		intOf(wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles),
		func(v int) { d.Cfg.KineTTL.RewedgeCycles = v },
		func() int { return d.Cfg.KineTTL.RewedgeCycles })
	applyI(intOf(old.KinePoolMaxConns, defaultPoolMaxConns),
		intOf(wd.KinePoolMaxConns, defaultPoolMaxConns),
		func(v int) { d.Cfg.KinePool.MaxConns = v },
		func() int { return d.Cfg.KinePool.MaxConns })
	applyI(intOf(old.KinePoolCycles, defaultPoolCycles),
		intOf(wd.KinePoolCycles, defaultPoolCycles),
		func(v int) { d.Cfg.KinePool.Cycles = v },
		func() int { return d.Cfg.KinePool.Cycles })
	applyI(intOf(old.OOMLoopMinKills, DefaultOOMMinKills),
		intOf(wd.OOMLoopMinKills, DefaultOOMMinKills),
		func(v int) { d.Cfg.OOMLoop.MinKills = v },
		func() int { return d.Cfg.OOMLoop.MinKills })
	// int64.
	apply64 := func(prevV, nextV int64, set func(int64), cur func() int64) {
		if cur() == prevV {
			set(nextV)
		}
	}
	i64 := func(v int64, def int64) int64 {
		if v > 0 {
			return v
		}
		return def
	}
	apply64(i64(old.Sig13GapMin, defaultGapMin),
		i64(wd.Sig13GapMin, defaultGapMin),
		func(v int64) { d.Cfg.Sig13.GapMin = v },
		func() int64 { return d.Cfg.Sig13.GapMin })
	// Durations — conf seconds 0 derives to the package default.
	dur := func(v int, def time.Duration) time.Duration {
		if v > 0 {
			return time.Duration(v) * time.Second
		}
		return def
	}
	applyD := func(prevV, nextV time.Duration, set func(time.Duration), cur func() time.Duration) {
		if cur() == prevV {
			set(nextV)
		}
	}
	applyD(dur(old.Sig13MinRestartS, defaultMinRestart),
		dur(wd.Sig13MinRestartS, defaultMinRestart),
		func(v time.Duration) { d.Cfg.Sig13.MinRestart = v },
		func() time.Duration { return d.Cfg.Sig13.MinRestart })
	applyD(dur(old.KineTTLMinRestartS, defaultTTLMinRestart),
		dur(wd.KineTTLMinRestartS, defaultTTLMinRestart),
		func(v time.Duration) { d.Cfg.KineTTL.MinRestart = v },
		func() time.Duration { return d.Cfg.KineTTL.MinRestart })
	applyD(dur(old.KineTTLCtlRestartS, defaultTTLCtlRestart),
		dur(wd.KineTTLCtlRestartS, defaultTTLCtlRestart),
		func(v time.Duration) { d.Cfg.KineTTL.CtlRestart = v },
		func() time.Duration { return d.Cfg.KineTTL.CtlRestart })
	applyD(dur(old.KinePoolMinRestartS, defaultPoolMinRestart),
		dur(wd.KinePoolMinRestartS, defaultPoolMinRestart),
		func(v time.Duration) { d.Cfg.KinePool.MinRestart = v },
		func() time.Duration { return d.Cfg.KinePool.MinRestart })
	applyD(dur(old.OOMLoopWindowS, defaultOOMWindow),
		dur(wd.OOMLoopWindowS, defaultOOMWindow),
		func(v time.Duration) { d.Cfg.OOMLoop.Window = v },
		func() time.Duration { return d.Cfg.OOMLoop.Window })
	d.WdApplied = wd
}
