// kmsv2_guard_test.go — table-driven and scenario tests for K10 KMSv2
// encryption plugin unhealthy/hung socket guard.
package apiserver_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func setupKMSHTTP(t *testing.T, e *env, peerReady int, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/default/endpoints/kubernetes" {
			var b strings.Builder
			b.WriteString(`{"subsets":[{"addresses":[`)
			for i := range peerReady {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"ip":"10.9.9.%d"}`, i+1)
			}
			b.WriteString(`]}]}`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	ep := strings.TrimPrefix(srv.URL, "https://")
	e.H.Cfg.Hub.SelfAPI = ep
	e.H.Cfg.Hub.PeerAPI = ep
	e.H.Cfg.HTTPClient = srv.Client()
	e.H.Client = srv.Client()
}

func startMockKMSUnix(t *testing.T, sockPath string, hang bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if hang {
				held = append(held, c)
			} else {
				_ = c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		for _, c := range held {
			_ = c.Close()
		}
	})
}

func runKMSCheck(e *env) {
	cdepstest.Check[*apiserver.KMSv2Check](e.H, cdeps.CheckKMSv2).Run(context.Background())
}

func TestKMSv2GuardTableAndScenarios(t *testing.T) {
	t.Run("absent_kms_auto_skips_cleanly", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			nilClient bool
		}{
			{name: "404_healthz_no_socket", nilClient: false},
			{name: "nil_client_no_socket", nilClient: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := fixture(t)
				e.H.Cfg.K0sRunDir = t.TempDir()
				if tc.nilClient {
					e.H.Cfg.HTTPClient = nil
					e.H.Client = nil
				} else {
					setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					})
				}

				runKMSCheck(e)
				if e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatal("unexpected KMSv2 latch when KMS is absent")
				}
				if len(e.Rst) != 0 {
					t.Fatalf("unexpected restart when KMS is absent: %v", e.Rst)
				}
				if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKMSv2, "ok")); v != 1 {
					t.Fatalf("ok cycles = %v, want 1", v)
				}
			})
		}
	})

	t.Run("healthy_socket_and_200_healthz_ok", func(t *testing.T) {
		e := fixture(t)
		runDir := t.TempDir()
		e.H.Cfg.K0sRunDir = runDir
		startMockKMSUnix(t, filepath.Join(runDir, "kms.sock"), false)
		setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz/kms-provider-0" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})

		runKMSCheck(e)
		if e.H.State.Exists(cdeps.StateKMSv2Unhealthy) || len(e.Rst) != 0 {
			t.Fatalf("healthy KMSv2 latched or restarted: latch=%v rst=%v",
				e.H.State.Exists(cdeps.StateKMSv2Unhealthy), e.Rst)
		}
		if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKMSv2, "ok")); v != 1 {
			t.Fatalf("ok cycles = %v, want 1", v)
		}
	})

	t.Run("unhealthy_500_latches_restarts_and_recovery_clears", func(t *testing.T) {
		e := fixture(t)
		runDir := t.TempDir()
		e.H.Cfg.K0sRunDir = runDir
		startMockKMSUnix(t, filepath.Join(runDir, "kms.sock"), false)

		var healthy atomic.Bool
		setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz/kms-provider-0" {
				if healthy.Load() {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ok"))
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("kms unhealthy"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})

		// Cycle 1: 1st failure -> suspect only (1-blip debounce).
		runKMSCheck(e)
		if e.H.State.Exists(cdeps.StateKMSv2Unhealthy) || len(e.Rst) != 0 {
			t.Fatal("latched or restarted on single cycle")
		}

		// Cycle 2: 2nd failure -> enters latch and restarts (HA PeerAPI ready >= 2).
		runKMSCheck(e)
		if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
			t.Fatal("expected StateKMSv2Unhealthy latch on 2nd unhealthy cycle")
		}
		if len(e.Rst) != 1 || e.Rst[0] != cdeps.DefaultRestartUnit {
			t.Fatalf("restarts = %v, want [%s]", e.Rst, cdeps.DefaultRestartUnit)
		}

		// Recovery clears latch.
		healthy.Store(true)
		runKMSCheck(e)
		if e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
			t.Fatal("expected StateKMSv2Unhealthy cleared after recovery")
		}
	})

	t.Run("hung_unix_socket_non_blocking_latches_without_hanging", func(t *testing.T) {
		e := fixture(t)
		runDir := t.TempDir()
		e.H.Cfg.K0sRunDir = runDir
		startMockKMSUnix(t, filepath.Join(runDir, "kms.sock"), true)
		setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		start := time.Now()
		runKMSCheck(e)
		runKMSCheck(e)
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("2 cycles against hung unix socket took %s", elapsed)
		}
		if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
			t.Fatal("expected StateKMSv2Unhealthy for hung KMSv2 socket")
		}
	})

	t.Run("oversize_healthz_response_bounded", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.K0sRunDir = t.TempDir()
		big := strings.Repeat("K", 3<<20)
		setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz/kms-provider-0" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(big))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})

		runKMSCheck(e)
		if e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
			t.Fatal("unexpected latch on 200 oversize healthz")
		}
		if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKMSv2, "ok")); v != 1 {
			t.Fatalf("ok cycles = %v, want 1", v)
		}
	})

	t.Run("discovers_encryption_config_from_proc_and_k0s_yaml", func(t *testing.T) {
		for _, source := range []string{"proc", "k0s_yaml"} {
			t.Run(source, func(t *testing.T) {
				e := fixture(t)
				hostRoot := t.TempDir()
				e.H.Cfg.HostRoot = hostRoot
				e.H.Cfg.K0sRunDir = filepath.Join(hostRoot, "run", "k0s")

				sock0 := filepath.Join(hostRoot, "run", "kms0.sock")
				startMockKMSUnix(t, sock0, false)
				// Intentionally omit /run/kms1.sock to verify missing configured socket is flagged unhealthy.

				encCfgPath := "/etc/k0s/enc.yaml"
				encYAML := `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          apiVersion: v2
          name: p0
          endpoint: unix:///run/kms0.sock
      - kms:
          apiVersion: v2
          name: p1
          endpoint: unix:///run/kms1.sock
`
				testutil.WriteFile(t, filepath.Join(hostRoot, "etc", "k0s", "enc.yaml"), encYAML)

				if source == "proc" {
					// Also place a D-state non-apiserver process whose cmdline must be skipped.
					testutil.WriteFile(t, filepath.Join(e.Proc, "200", "stat"), "200 (sleep) D 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config="+encCfgPath+"\x00")
				} else {
					k0sYAML := `apiVersion: k0s.k8sproject.io/v1beta1
kind: ClusterConfig
spec:
  api:
    extraArgs:
      encryption-provider-config: /etc/k0s/enc.yaml
`
					testutil.WriteFile(t, filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml"), k0sYAML)
				}

				var seen0, seen1 atomic.Bool
				setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/healthz/kms-provider-0":
						seen0.Store(true)
						w.WriteHeader(http.StatusOK)
					case "/healthz/kms-provider-1":
						seen1.Store(true)
						w.WriteHeader(http.StatusOK)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				})

				runKMSCheck(e)
				runKMSCheck(e)
				if !seen0.Load() || !seen1.Load() {
					t.Fatalf("expected probes for kms-provider-0 and kms-provider-1: seen0=%v seen1=%v",
						seen0.Load(), seen1.Load())
				}
				if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatal("expected latch for missing configured kms1.sock")
				}
			})
		}
	})

	t.Run("restart_gate_modes_holds_cooldown_and_spof_streak", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			mode        string
			peerReady   int
			maintHold   bool
			preCooldown bool
			spof        bool
			cycles      int
			wantRst     int
			wantDryRun  float64
			wantOutcome string
		}{
			{
				name:       "mode_off_latches_without_restart",
				mode:       cdeps.ModeOff,
				peerReady:  2,
				cycles:     2,
				wantRst:    0,
				wantDryRun: 0,
			},
			{
				name:       "mode_dry_run_logs_without_restart",
				mode:       cdeps.ModeDryRun,
				peerReady:  2,
				cycles:     2,
				wantRst:    0,
				wantDryRun: 1,
			},
			{
				name:        "quorum_hold_blocks_restart",
				mode:        cdeps.ModeEnforce,
				peerReady:   1,
				cycles:      2,
				wantRst:     0,
				wantOutcome: "quorum_hold",
			},
			{
				name:        "maintenance_hold_blocks_restart",
				mode:        cdeps.ModeEnforce,
				peerReady:   2,
				maintHold:   true,
				cycles:      2,
				wantRst:     0,
				wantOutcome: "maint_hold",
			},
			{
				name:        "cooldown_blocks_restart",
				mode:        cdeps.ModeEnforce,
				peerReady:   2,
				preCooldown: true,
				cycles:      2,
				wantRst:     0,
				wantOutcome: "cooldown",
			},
			{
				name:       "spof_doubles_streak_from_2_to_4",
				mode:       cdeps.ModeEnforce,
				spof:       true,
				cycles:     3,
				wantRst:    0, // 4 cycles needed on SPOF
				wantDryRun: 0,
			},
			{
				name:       "spof_fires_on_cycle_4",
				mode:       cdeps.ModeEnforce,
				spof:       true,
				cycles:     4,
				wantRst:    1,
				wantDryRun: 0,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := fixture(t)
				runDir := t.TempDir()
				e.H.Cfg.K0sRunDir = runDir
				startMockKMSUnix(t, filepath.Join(runDir, "kms.sock"), false)
				setupKMSHTTP(t, e, tc.peerReady, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/healthz/kms-provider-0" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				})

				e.H.Cfg.Sig13.Mode = tc.mode
				e.H.Cfg.Sig13.MinRestart = time.Hour
				if tc.spof {
					e.H.Cfg.Hub.PeerAPI = ""
					e.H.Cfg.TotalControllers = 1
				}
				if tc.maintHold {
					e.H.Cfg.Coord = &nodecoord.Coord{
						Now: func() time.Time { return e.Now },
						GetAnnos: func(context.Context) (map[string]string, error) {
							return map[string]string{
								nodecond.AnnoClusterMaintenanceUntil: e.Now.Add(time.Hour).UTC().Format(time.RFC3339),
							}, nil
						},
					}
				}
				if tc.preCooldown {
					e.H.State.RateSpend(cdeps.FileRateRestart)
				}

				for range tc.cycles {
					runKMSCheck(e)
				}
				if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatal("expected StateKMSv2Unhealthy latch")
				}
				if len(e.Rst) != tc.wantRst {
					t.Fatalf("restarts = %d (%v), want %d", len(e.Rst), e.Rst, tc.wantRst)
				}
				if got := promtest.ToFloat64(e.H.Actions.WithLabelValues(cdeps.CheckKMSv2, "dryrun_restart")); got != tc.wantDryRun {
					t.Fatalf("dryrun_restart = %v, want %v", got, tc.wantDryRun)
				}
				if tc.wantOutcome != "" {
					if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckKMSv2, tc.wantOutcome)); got == 0 {
						t.Fatalf("expected outcome %q metric > 0", tc.wantOutcome)
					}
				}
			})
		}
	})
}

func TestKMSv2GuardAdversarialTier5(t *testing.T) {
	t.Run("oversized_configs_fail_bounded", func(t *testing.T) {
		for _, target := range []string{"k0s_yaml", "encryption_provider_config"} {
			t.Run(target, func(t *testing.T) {
				e := fixture(t)
				base := t.TempDir()
				hostRoot := filepath.Join(base, "hostroot")
				e.H.Cfg.HostRoot = hostRoot
				e.H.Cfg.K0sRunDir = filepath.Join(hostRoot, "run", "k0s")
				setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				})

				var bigPath string
				if target == "k0s_yaml" {
					bigPath = filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml")
				} else {
					bigPath = filepath.Join(hostRoot, "etc", "k0s", "enc.yaml")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config=/etc/k0s/enc.yaml\x00")
				}
				if err := os.MkdirAll(filepath.Dir(bigPath), 0o755); err != nil {
					t.Fatal(err)
				}
				f, err := os.Create(bigPath)
				if err != nil {
					t.Fatal(err)
				}
				// 16 MiB sparse file (> 1 MiB cap) must fail fast without reading past cap.
				if err := f.Truncate(16 << 20); err != nil {
					_ = f.Close()
					t.Fatal(err)
				}
				_ = f.Close()

				start := time.Now()
				runKMSCheck(e)
				runKMSCheck(e)
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("oversized %s took %s", target, elapsed)
				}
				if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatalf("expected StateKMSv2Unhealthy for oversized %s", target)
				}
				if logs := e.LogLines(); !strings.Contains(logs, "exceeds") {
					t.Fatalf("expected size-cap error in logs, got:\n%s", logs)
				}
			})
		}

		t.Run("exact_cap_plus_one_fails", func(t *testing.T) {
			e := fixture(t)
			hostRoot := filepath.Join(t.TempDir(), "hostroot")
			e.H.Cfg.HostRoot = hostRoot
			e.H.Cfg.K0sRunDir = filepath.Join(hostRoot, "run", "k0s")
			setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			})
			k0sPath := filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml")
			if err := os.MkdirAll(filepath.Dir(k0sPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(k0sPath, make([]byte, (1<<20)+1), 0o644); err != nil {
				t.Fatal(err)
			}
			runKMSCheck(e)
			runKMSCheck(e)
			if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
				t.Fatal("expected StateKMSv2Unhealthy at maxKMSConfigBytes+1")
			}
			if logs := e.LogLines(); !strings.Contains(logs, "exceeds") {
				t.Fatalf("expected size-cap error in logs, got:\n%s", logs)
			}
		})
	})

	t.Run("path_traversal_and_symlink_escape_rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			setup      func(t *testing.T, e *env, base, hostRoot string)
			wantLogSub string
		}{
			{
				name: "proc_relative_dotdot",
				setup: func(t *testing.T, e *env, base, _ string) {
					testutil.WriteFile(t, filepath.Join(base, "outside-enc.yaml"), "not: [valid: yaml")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config=../outside-enc.yaml\x00")
				},
				wantLogSub: "invalid encryption config path",
			},
			{
				name: "proc_absolute_dotdot",
				setup: func(t *testing.T, e *env, base, _ string) {
					testutil.WriteFile(t, filepath.Join(base, "outside-enc.yaml"), "not: [valid: yaml")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config=/etc/k0s/../../outside-enc.yaml\x00")
				},
				wantLogSub: "invalid encryption config path",
			},
			{
				name: "k0s_yaml_extra_args_dotdot",
				setup: func(t *testing.T, _ *env, base, hostRoot string) {
					testutil.WriteFile(t, filepath.Join(base, "outside-enc.yaml"), "not: [valid: yaml")
					k0sYAML := `apiVersion: k0s.k8sproject.io/v1beta1
kind: ClusterConfig
spec:
  api:
    extraArgs:
      encryption-provider-config: ../outside-enc.yaml
`
					testutil.WriteFile(t, filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml"), k0sYAML)
				},
				wantLogSub: "invalid encryption config path",
			},
			{
				name: "kms_endpoint_unix_dotdot",
				setup: func(t *testing.T, _ *env, base, hostRoot string) {
					startMockKMSUnix(t, filepath.Join(base, "outside.sock"), false)
					encYAML := `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          apiVersion: v2
          name: evil
          endpoint: unix://../outside.sock
      - kms:
          apiVersion: v2
          name: evil2
          endpoint: unix:///run/../../outside.sock
`
					testutil.WriteFile(t, filepath.Join(hostRoot, "etc", "k0s", "enc.yaml"), encYAML)
					k0sYAML := `apiVersion: k0s.k8sproject.io/v1beta1
kind: ClusterConfig
spec:
  api:
    extraArgs:
      encryption-provider-config: /etc/k0s/enc.yaml
`
					testutil.WriteFile(t, filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml"), k0sYAML)
				},
				wantLogSub: "invalid kms endpoint",
			},
			{
				name: "symlink_escape_outside_hostroot",
				setup: func(t *testing.T, e *env, base, hostRoot string) {
					outside := filepath.Join(base, "outside-enc.yaml")
					testutil.WriteFile(t, outside, "not: [valid: yaml")
					encDir := filepath.Join(hostRoot, "etc", "k0s")
					if err := os.MkdirAll(encDir, 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, filepath.Join(encDir, "enc.yaml")); err != nil {
						t.Fatal(err)
					}
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config=/etc/k0s/enc.yaml\x00")
				},
				wantLogSub: "escapes HostRoot",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := fixture(t)
				base := t.TempDir()
				hostRoot := filepath.Join(base, "hostroot")
				if err := os.MkdirAll(hostRoot, 0o755); err != nil {
					t.Fatal(err)
				}
				e.H.Cfg.HostRoot = hostRoot
				e.H.Cfg.K0sRunDir = filepath.Join(hostRoot, "run", "k0s")
				var probed []string
				e.H.Cfg.KMSProbeFn = func(_ context.Context, sock string) error {
					probed = append(probed, sock)
					return nil
				}
				setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				})

				tc.setup(t, e, base, hostRoot)
				runKMSCheck(e)
				runKMSCheck(e)

				for _, p := range probed {
					if strings.Contains(p, "outside") {
						t.Fatalf("KMSProbeFn probed escaped socket %q", p)
					}
				}
				if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatalf("expected StateKMSv2Unhealthy for %s", tc.name)
				}
				logs := e.LogLines()
				if strings.Contains(logs, "parse encryption config") {
					t.Fatalf("escaped outside file was read and parsed:\n%s", logs)
				}
				if !strings.Contains(logs, tc.wantLogSub) {
					t.Fatalf("expected %q in logs, got:\n%s", tc.wantLogSub, logs)
				}
			})
		}
	})

	t.Run("non_regular_files_rejected_without_blocking", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			useProc bool
			kind    string
		}{
			{name: "k0s_yaml_directory", useProc: false, kind: "dir"},
			{name: "k0s_yaml_fifo", useProc: false, kind: "fifo"},
			{name: "enc_cfg_directory", useProc: true, kind: "dir"},
			{name: "enc_cfg_fifo", useProc: true, kind: "fifo"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := fixture(t)
				hostRoot := t.TempDir()
				e.H.Cfg.HostRoot = hostRoot
				e.H.Cfg.K0sRunDir = filepath.Join(hostRoot, "run", "k0s")
				setupKMSHTTP(t, e, 2, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				})

				target := filepath.Join(hostRoot, "etc", "k0s", "k0s.yaml")
				if tc.useProc {
					target = filepath.Join(hostRoot, "etc", "k0s", "enc.yaml")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "stat"), "201 (kube-apiserver) S 1 0 0")
					testutil.WriteFile(t, filepath.Join(e.Proc, "201", "cmdline"),
						"kube-apiserver\x00--encryption-provider-config=/etc/k0s/enc.yaml\x00")
				}
				if tc.kind == "dir" {
					if err := os.MkdirAll(target, 0o755); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := syscall.Mkfifo(target, 0o600); err != nil {
						t.Fatal(err)
					}
				}

				done := make(chan struct{})
				go func() {
					defer close(done)
					runKMSCheck(e)
					runKMSCheck(e)
				}()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatalf("KMSv2Check blocked on non-regular %s", tc.name)
				}
				if !e.H.State.Exists(cdeps.StateKMSv2Unhealthy) {
					t.Fatalf("expected StateKMSv2Unhealthy for %s", tc.name)
				}
				if logs := e.LogLines(); !strings.Contains(logs, "non-regular file") {
					t.Fatalf("expected non-regular file error in logs, got:\n%s", logs)
				}
			})
		}
	})
}
