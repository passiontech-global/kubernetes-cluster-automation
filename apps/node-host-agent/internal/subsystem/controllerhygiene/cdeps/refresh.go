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
func applyField[T comparable](dst *T, prev, next T) {
	if *dst == prev {
		*dst = next
	}
}

func applyNonEmpty(dst *string, prev, next string) {
	if next != "" && *dst == prev {
		*dst = next
	}
}

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
	applyField(&d.Cfg.Hub.SelfAPI, old.APISelf, wd.APISelf)
	applyField(&d.Cfg.Hub.PeerAPI, old.APIPeer, wd.APIPeer)
	applyField(&d.Cfg.Hub.KineDBProbe, old.KineDBProbe, wd.KineDBProbe)
	applyNonEmpty(&d.Cfg.Sig13.Mode, old.Sig13Autofix, wd.Sig13Autofix)
	applyNonEmpty(&d.Cfg.KineTTL.Mode, old.KineTTLAutofix, wd.KineTTLAutofix)
	applyNonEmpty(&d.Cfg.KinePool.Mode, old.KinePoolAutofix, wd.KinePoolAutofix)
	applyNonEmpty(&d.Cfg.OOMLoop.Mode, old.OOMLoopAutofix, wd.OOMLoopAutofix)

	// Ints / int64 — conf 0 derives to the package default.
	intOf := func(v, def int) int {
		if v > 0 {
			return v
		}
		return def
	}
	i64 := func(v, def int64) int64 {
		if v > 0 {
			return v
		}
		return def
	}
	dur := func(v int, def time.Duration) time.Duration {
		if v > 0 {
			return time.Duration(v) * time.Second
		}
		return def
	}
	applyField(&d.Cfg.Sig13.StaleMinErrs, intOf(old.Sig13StaleMinErrs, defaultStaleMinErrs), intOf(wd.Sig13StaleMinErrs, defaultStaleMinErrs))
	applyField(&d.Cfg.Sig13.SoloCycles, intOf(old.Sig13SoloCycles, defaultSoloCycles), intOf(wd.Sig13SoloCycles, defaultSoloCycles))
	applyField(&d.Cfg.Sig13.GapCycles, intOf(old.Sig13GapCycles, defaultGapCycles), intOf(wd.Sig13GapCycles, defaultGapCycles))
	applyField(&d.Cfg.Sig13.FrozenCycles, intOf(old.Sig13FrozenCycles, defaultFrozenCycles), intOf(wd.Sig13FrozenCycles, defaultFrozenCycles))
	applyField(&d.Cfg.KineTTL.RewedgeCycles, intOf(old.KineTTLRewedgeCycle, defaultTTLRewedgeCycles), intOf(wd.KineTTLRewedgeCycle, defaultTTLRewedgeCycles))
	applyField(&d.Cfg.KinePool.MaxConns, intOf(old.KinePoolMaxConns, defaultPoolMaxConns), intOf(wd.KinePoolMaxConns, defaultPoolMaxConns))
	applyField(&d.Cfg.KinePool.Cycles, intOf(old.KinePoolCycles, defaultPoolCycles), intOf(wd.KinePoolCycles, defaultPoolCycles))
	applyField(&d.Cfg.OOMLoop.MinKills, intOf(old.OOMLoopMinKills, DefaultOOMMinKills), intOf(wd.OOMLoopMinKills, DefaultOOMMinKills))
	applyField(&d.Cfg.Sig13.GapMin, i64(old.Sig13GapMin, defaultGapMin), i64(wd.Sig13GapMin, defaultGapMin))

	applyField(&d.Cfg.Sig13.MinRestart, dur(old.Sig13MinRestartS, defaultMinRestart), dur(wd.Sig13MinRestartS, defaultMinRestart))
	applyField(&d.Cfg.KineTTL.MinRestart, dur(old.KineTTLMinRestartS, defaultTTLMinRestart), dur(wd.KineTTLMinRestartS, defaultTTLMinRestart))
	applyField(&d.Cfg.KineTTL.CtlRestart, dur(old.KineTTLCtlRestartS, defaultTTLCtlRestart), dur(wd.KineTTLCtlRestartS, defaultTTLCtlRestart))
	applyField(&d.Cfg.KinePool.MinRestart, dur(old.KinePoolMinRestartS, defaultPoolMinRestart), dur(wd.KinePoolMinRestartS, defaultPoolMinRestart))
	applyField(&d.Cfg.OOMLoop.Window, dur(old.OOMLoopWindowS, defaultOOMWindow), dur(wd.OOMLoopWindowS, defaultOOMWindow))
	d.WdApplied = wd
}
