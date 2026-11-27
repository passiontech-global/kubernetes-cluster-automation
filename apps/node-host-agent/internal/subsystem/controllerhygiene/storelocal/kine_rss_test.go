// kine_rss_test.go — HA-gated kine RSS leak guard tests.
package storelocal_test

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

const kineLeak2850MiB uint64 = 2918 << 20 // ~2.85 GiB (> 1536 MiB default)

func TestKineRSSSingleControllerObserveOnlyNoKill(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{
			name: "empty_peer_api",
			mut: func(e *env) {
				e.H.Cfg.Hub.PeerAPI = ""
				e.H.Cfg.TotalControllers = 0
			},
		},
		{
			name: "total_controllers_1",
			mut: func(e *env) {
				e.H.Cfg.TotalControllers = 1
				e.Alive["https://10.0.0.2:6443/readyz"] = true
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
			tc.mut(e)
			e.MkProc(t, 2001, "kine",
				[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
			e.SetProcRSS(t, 2001, kineLeak2850MiB)

			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 || e.RstN() != 0 {
				t.Fatalf("%s: single-controller killed/restarted kine: kills=%v rst=%d",
					tc.name, e.Kills, e.RstN())
			}
			if !strings.Contains(e.LogLines(), "WARN: kine pid=2001") ||
				!strings.Contains(e.LogLines(), "single-controller") {
				t.Fatalf("%s: expected single-controller WARN log:\n%s", tc.name, e.LogLines())
			}
		})
	}
}

func TestKineRSSHAHealthyPeerEmbeddedSIGTERM(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.EPReady = map[string]int{"10.0.0.2:6443": 2}
	e.MkProc(t, 2001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	e.SetProcRSS(t, 2001, kineLeak2850MiB)

	// Cycles 1 & 2: below 3-cycle streak -> no kill.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before 3-cycle streak: %v", e.Kills)
	}
	// Cycle 3: 3 consecutive cycles + healthy peer -> SIGTERM.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 2001 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("kills=%v want [{2001 SIGTERM}]", e.Kills)
	}
	log := e.LogLines()
	if !strings.Contains(log, "ACTION: terminated kine pid=2001 (SIGTERM)") ||
		!strings.Contains(log, "rss_mib=2918") {
		t.Fatalf("ACTION log missing expected details:\n%s", log)
	}
}

func TestKineRSSHAHealthyPeerStandaloneRestartsKineService(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.EPReady = map[string]int{"10.0.0.2:6443": 2}
	e.MkProc(t, 2002, "kine",
		[]string{"/usr/local/bin/kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	// Place process in standalone kine.service cgroup (Phase-3 split host).
	testutil.WriteFile(t, filepath.Join(e.Proc, "2002", "cgroup"),
		"0::/system.slice/kine.service\n")
	e.SetProcRSS(t, 2002, kineLeak2850MiB)

	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("standalone kine.service should restart unit, not signal pid: %v", e.Kills)
	}
	if e.RstN() != 1 || e.RstAt(0) != "kine.service" {
		t.Fatalf("restarts=%v want [kine.service]", e.Rst)
	}
	if !strings.Contains(e.LogLines(), "ACTION: restarting kine.service") {
		t.Fatalf("standalone restart ACTION not logged:\n%s", e.LogLines())
	}
}

func TestKineRSSHADeadPeerBlocksKill(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{
			name: "peer_readyz_false",
			mut: func(e *env) {
				e.Alive["https://10.0.0.2:6443/readyz"] = false
			},
		},
		{
			name: "quorum_endpoints_below_2",
			mut: func(e *env) {
				e.Alive["https://10.0.0.2:6443/readyz"] = true
				e.EPReady = map[string]int{"10.0.0.2:6443": 1}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
			tc.mut(e)
			e.MkProc(t, 2001, "kine",
				[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
			e.SetProcRSS(t, 2001, kineLeak2850MiB)

			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 || e.RstN() != 0 {
				t.Fatalf("%s: dead peer did not block kine heal: kills=%v rst=%d",
					tc.name, e.Kills, e.RstN())
			}
			if !strings.Contains(e.LogLines(), "WARN: kine pid=2001") ||
				!strings.Contains(e.LogLines(), "unhealthy") {
				t.Fatalf("%s: expected unhealthy-peer WARN log:\n%s", tc.name, e.LogLines())
			}
		})
	}
}

func TestKineRSSCooldownRespected(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CPHealthFn = func(context.Context, string) bool { return true }
	e.Alive["https://10.0.0.2:6443/readyz"] = true
	e.EPReady = map[string]int{"10.0.0.2:6443": 2}
	e.MkProc(t, 2001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	e.SetProcRSS(t, 2001, kineLeak2850MiB)

	// First 3 cycles -> first SIGTERM, spends last-kine-rss-heal (1h).
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("first kill missing: %v", e.Kills)
	}
	// 30m later -> inside 1h cooldown, 3 more leak cycles must NOT double kill.
	e.Now = e.Now.Add(30 * time.Minute)
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 {
		t.Fatalf("cooldown failed to suppress second kill: %v", e.Kills)
	}
	// 1h+ after first kill -> next cycle kills again.
	e.Now = e.Now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if len(e.Kills) != 2 || e.Kills[1].Sig != syscall.SIGTERM {
		t.Fatalf("expected second SIGTERM after cooldown, got %v", e.Kills)
	}
}

func TestKineRSSDisabledAndTransientSpike(t *testing.T) {
	t.Run("disabled_zero", func(t *testing.T) {
		e := fixture(t)
		e.Alive["https://10.0.0.2:6443/readyz"] = true
		e.H.Cfg.KineRSS.MaxRSSMiB = 0
		e.MkProc(t, 2001, "kine",
			[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
		e.SetProcRSS(t, 2001, kineLeak2850MiB)
		for range 4 {
			e.H.Cycle(context.Background())
		}
		if len(e.Kills) != 0 {
			t.Fatalf("disabled kine RSS guard killed kine: %v", e.Kills)
		}
	})

	t.Run("transient_spike_resets_streak", func(t *testing.T) {
		e := fixture(t)
		e.Alive["https://10.0.0.2:6443/readyz"] = true
		e.MkProc(t, 2001, "kine",
			[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)

		e.SetProcRSS(t, 2001, kineLeak2850MiB)
		e.H.Cycle(context.Background())
		e.H.Cycle(context.Background())
		// Drop below threshold -> streak resets.
		e.SetProcRSS(t, 2001, 512<<20)
		e.H.Cycle(context.Background())
		// 2 more high cycles -> still below 3 consecutive.
		e.SetProcRSS(t, 2001, kineLeak2850MiB)
		e.H.Cycle(context.Background())
		e.H.Cycle(context.Background())
		if len(e.Kills) != 0 {
			t.Fatalf("transient spike killed kine: %v", e.Kills)
		}
	})
}
