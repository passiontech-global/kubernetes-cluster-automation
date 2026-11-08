// refresh_test.go — the BUG-H9 per-cycle watchdogconf re-apply: a
// knob moves only when it still carries the PREVIOUS conf parse's
// value, so env/programmatic overrides survive a conf rewrite, and
// empty conf keys derive to the package defaults.
package cdeps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

func newReloader(t *testing.T, conf string) *watchdogconf.Reloader {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node-watchdog.conf")
	if conf != "" {
		if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return watchdogconf.NewReloader(path, nil)
}

// oldConf + cfg build the "previous parse" state: WdApplied holds
// the raw old conf and Cfg carries the derived old values.
func oldWorld() (*watchdogconf.Config, Config) {
	old := &watchdogconf.Config{
		APISelf: "10.0.0.1:6443", APIPeer: "10.0.0.2:6443",
		KineDBProbe:  "10.0.0.3:5432",
		Sig13Autofix: "dry-run", Sig13StaleMinErrs: 15, Sig13SoloCycles: 8,
		Sig13GapCycles: 2, Sig13FrozenCycles: 2, Sig13GapMin: 10000,
		Sig13MinRestartS: 7200,
		KineTTLAutofix:   "dry-run", KineTTLMinRestartS: 1800,
		KineTTLCtlRestartS: 7200, KineTTLRewedgeCycle: 2,
		KinePoolAutofix: "dry-run", KinePoolMaxConns: 72,
		KinePoolCycles: 3, KinePoolMinRestartS: 1200,
		OOMLoopAutofix: "dry-run", OOMLoopMinKills: 3, OOMLoopWindowS: 3600,
	}
	cfg := Config{
		Hub: HubConfig{SelfAPI: "10.0.0.1:6443", PeerAPI: "10.0.0.2:6443",
			KineDBProbe: "10.0.0.3:5432"},
		Sig13: Sig13Config{Mode: "dry-run", StaleMinErrs: 15, SoloCycles: 8,
			GapCycles: 2, FrozenCycles: 2, GapMin: 10000, MinRestart: 2 * time.Hour},
		KineTTL: KineTTLConfig{Mode: "dry-run", MinRestart: 30 * time.Minute,
			CtlRestart: 2 * time.Hour, RewedgeCycles: 2},
		KinePool: KinePoolConfig{Mode: "dry-run", MaxConns: 72, Cycles: 3,
			MinRestart: 20 * time.Minute},
		OOMLoop: OOMLoopConfig{Mode: "dry-run", MinKills: 3, Window: time.Hour},
	}
	return old, cfg
}

// The new conf rewrites every knob to a fresh value.
const newConf = `API_SELF=10.9.0.1:6443
API_PEER=10.9.0.2:6443
KINE_DB_PROBE=10.9.0.3:5432
SIG13_AUTOFIX=enforce
APISERVER_STALE_MIN_ERRS=20
APISERVER_SOLO_CYCLES=6
APISERVER_GAP_CYCLES=4
APISERVER_FROZEN_CYCLES=5
APISERVER_GAP_MIN=20000
SIG13_MIN_RESTART_S=3600
KINE_TTL_AUTOFIX=enforce
KINE_TTL_MIN_RESTART_S=1200
KINE_TTL_CTL_RESTART_S=3600
KINE_TTL_REWEDGE_CYCLES=7
KINE_POOL_AUTOFIX=enforce
KINE_POOL_MAX_CONNS=90
KINE_POOL_CYCLES=4
KINE_POOL_MIN_RESTART_S=900
K0S_OOMLOOP_AUTOFIX=enforce
K0S_OOMLOOP_MIN_KILLS=5
K0S_OOMLOOP_WINDOW_S=1800
`

func TestRefreshWatchdogConfMovesAllKnobs(t *testing.T) {
	old, cfg := oldWorld()
	cfg.WatchdogSrc = newReloader(t, newConf)
	d := &Deps{Cfg: cfg, WdApplied: old}

	d.RefreshWatchdogConf()

	if d.Cfg.Hub.SelfAPI != "10.9.0.1:6443" ||
		d.Cfg.Hub.PeerAPI != "10.9.0.2:6443" ||
		d.Cfg.Hub.KineDBProbe != "10.9.0.3:5432" {
		t.Fatalf("hub knobs not moved: %+v", d.Cfg.Hub)
	}
	if d.Cfg.Sig13.Mode != "enforce" || d.Cfg.Sig13.StaleMinErrs != 20 ||
		d.Cfg.Sig13.SoloCycles != 6 || d.Cfg.Sig13.GapCycles != 4 ||
		d.Cfg.Sig13.FrozenCycles != 5 || d.Cfg.Sig13.GapMin != 20000 ||
		d.Cfg.Sig13.MinRestart != time.Hour {
		t.Fatalf("sig13 knobs not moved: %+v", d.Cfg.Sig13)
	}
	if d.Cfg.KineTTL.Mode != "enforce" || d.Cfg.KineTTL.MinRestart != 20*time.Minute ||
		d.Cfg.KineTTL.CtlRestart != time.Hour || d.Cfg.KineTTL.RewedgeCycles != 7 {
		t.Fatalf("kine-ttl knobs not moved: %+v", d.Cfg.KineTTL)
	}
	if d.Cfg.KinePool.Mode != "enforce" || d.Cfg.KinePool.MaxConns != 90 ||
		d.Cfg.KinePool.Cycles != 4 || d.Cfg.KinePool.MinRestart != 15*time.Minute {
		t.Fatalf("kine-pool knobs not moved: %+v", d.Cfg.KinePool)
	}
	if d.Cfg.OOMLoop.Mode != "enforce" || d.Cfg.OOMLoop.MinKills != 5 ||
		d.Cfg.OOMLoop.Window != 30*time.Minute {
		t.Fatalf("oomloop knobs not moved: %+v", d.Cfg.OOMLoop)
	}
	// WdApplied now holds the parse the reloader handed out — a
	// second refresh re-reads an identical conf and every knob only
	// re-applies its own value (idempotent).
	d.RefreshWatchdogConf()
	if d.Cfg.Hub.SelfAPI != "10.9.0.1:6443" ||
		d.Cfg.Sig13.StaleMinErrs != 20 ||
		d.Cfg.OOMLoop.Window != 30*time.Minute {
		t.Fatalf("second refresh drifted: %+v %+v", d.Cfg.Hub, d.Cfg.Sig13)
	}
}

func TestRefreshWatchdogConfPreservesOverrides(t *testing.T) {
	old, cfg := oldWorld()
	// The new conf leaves KINE_TTL_AUTOFIX out (empty next value)
	// and an operator pinned two knobs from elsewhere.
	cfg.WatchdogSrc = newReloader(t, newConf)
	cfg.KineTTL.Mode = "enforce" // env override — not the old conf value
	cfg.Sig13.StaleMinErrs = 99  // another override
	d := &Deps{Cfg: cfg, WdApplied: old}

	d.RefreshWatchdogConf()

	if d.Cfg.KineTTL.Mode != "enforce" {
		t.Fatalf("override lost: KineTTL.Mode=%s", d.Cfg.KineTTL.Mode)
	}
	if d.Cfg.Sig13.StaleMinErrs != 99 {
		t.Fatalf("override lost: StaleMinErrs=%d", d.Cfg.Sig13.StaleMinErrs)
	}
	// Other knobs still moved.
	if d.Cfg.Hub.SelfAPI != "10.9.0.1:6443" {
		t.Fatalf("unrelated knob frozen by the override guard: %+v", d.Cfg.Hub)
	}
}

func TestRefreshWatchdogConfNoopPaths(t *testing.T) {
	t.Run("nil reloader", func(t *testing.T) {
		_, cfg := oldWorld()
		cfg.WatchdogSrc = nil
		d := &Deps{Cfg: cfg}
		d.RefreshWatchdogConf() // must not panic or touch anything
		if d.Cfg.Hub.SelfAPI != "10.0.0.1:6443" || d.WdApplied != nil {
			t.Fatal("nil WatchdogSrc changed state")
		}
	})
	t.Run("same parse pointer", func(t *testing.T) {
		_, cfg := oldWorld()
		rel := newReloader(t, newConf)
		cfg.WatchdogSrc = rel
		// Seed the reloader, then make the conf path a DIRECTORY so
		// the re-read fails (EISDIR) and Get keeps serving the cached
		// last-good parse — the one case the pointer fast path fires.
		d := &Deps{Cfg: cfg, WdApplied: rel.Get()}
		path := rel.Path
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(path) })
		if rel.Get() != d.WdApplied {
			t.Fatal("test setup: reloader did not serve the cached parse")
		}
		d.RefreshWatchdogConf()
		if d.Cfg.Hub.SelfAPI != "10.0.0.1:6443" {
			t.Fatal("identical parse still moved knobs")
		}
	})
}

// A fresh Deps (WdApplied nil) derives the PREVIOUS side from the
// package defaults — Parse(nil) — so defaults-carrying fields move
// onto the new conf values.
func TestRefreshWatchdogConfFreshDeps(t *testing.T) {
	cfg := Config{WatchdogSrc: newReloader(t,
		"APISERVER_STALE_MIN_ERRS=20\nAPI_SELF=10.9.9.9:6443\n")}
	d := &Deps{Cfg: cfg}
	// The 15 here is what ApplyDefaults would have produced.
	d.Cfg.Sig13.StaleMinErrs = 15

	d.RefreshWatchdogConf()

	if d.Cfg.Sig13.StaleMinErrs != 20 {
		t.Fatalf("default-derived knob did not move: %d", d.Cfg.Sig13.StaleMinErrs)
	}
	// SelfAPI carried the old-derived empty value → cur()==prev →
	// the fresh conf value moves in.
	if d.Cfg.Hub.SelfAPI != "10.9.9.9:6443" {
		t.Fatalf("empty-derived knob did not move: SelfAPI=%q", d.Cfg.Hub.SelfAPI)
	}
}
