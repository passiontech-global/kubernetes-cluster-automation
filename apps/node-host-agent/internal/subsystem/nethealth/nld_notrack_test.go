// nld_notrack_test.go — unit tests for #12A NodeLocalDNS raw NOTRACK drift guard.

package nethealth

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

const healthyIPTablesRaw = `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 169.254.20.10/32 -p udp -m udp --dport 53 -j NOTRACK
-A PREROUTING -d 169.254.20.10/32 -p tcp -m tcp --dport 53 -j NOTRACK
-A OUTPUT -d 169.254.20.10/32 -p udp -m udp --dport 53 -j NOTRACK
-A OUTPUT -d 169.254.20.10/32 -p tcp -m tcp --dport 53 -j NOTRACK
-A OUTPUT -s 169.254.20.10/32 -p udp -m udp --sport 53 -j NOTRACK
-A OUTPUT -s 169.254.20.10/32 -p tcp -m tcp --sport 53 -j NOTRACK
COMMIT
`

const healthyNFTRaw = `table ip raw {
	chain PREROUTING {
		type filter hook prerouting priority raw; policy accept;
		ip daddr 169.254.20.10 udp dport 53 counter packets 10 bytes 600 notrack
		ip daddr 169.254.20.10 tcp dport 53 counter packets 4 bytes 240 notrack
	}
	chain OUTPUT {
		type filter hook output priority raw; policy accept;
		ip daddr 169.254.20.10 udp dport 53 counter packets 10 bytes 600 notrack
		ip saddr 169.254.20.10 udp sport 53 counter packets 5 bytes 300 notrack
	}
}
`

func nldEnv(t *testing.T, ip string) *env {
	t.Helper()
	e := fixture(t, nil)
	e.n.cfg.linkAddrsFn = func(_ int, name string) ([]netlink.Addr, error) {
		if name != nldIface {
			return nil, netlink.LinkNotFoundError{}
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, nil
		}
		return []netlink.Addr{{
			IPNet: &net.IPNet{IP: parsed, Mask: net.CIDRMask(32, 32)},
		}}, nil
	}
	return e
}

func TestNLDNoTrackCheckOrderAppendedToGroup2Tail(t *testing.T) {
	e := fixture(t, nil)
	if len(e.n.groups) != 2 {
		t.Fatalf("groups len = %d, want 2", len(e.n.groups))
	}
	var got []string
	for _, ent := range e.n.groups[1].Entries {
		got = append(got, ent.Name)
	}
	want := []string{
		checkEgress,
		checkNebula,
		checkF2B,
		checkClock,
		checkCT,
		checkNebTCP,
		checkNLDNoTrack,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("group 2 check order = %v, want %v", got, want)
	}
}

func TestNLDNoTrackGatedWhenInterfaceMissingOrWrongIP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		linkAddrs func(int, string) ([]netlink.Addr, error)
	}{
		{
			name: "missing_interface",
			linkAddrs: func(int, string) ([]netlink.Addr, error) {
				return nil, netlink.LinkNotFoundError{}
			},
		},
		{
			name: "enodev_error",
			linkAddrs: func(int, string) ([]netlink.Addr, error) {
				return nil, unix.ENODEV
			},
		},
		{
			name: "wrong_ip",
			linkAddrs: func(int, string) ([]netlink.Addr, error) {
				return []netlink.Addr{{
					IPNet: &net.IPNet{IP: net.ParseIP("10.8.0.10"), Mask: net.CIDRMask(24, 32)},
				}}, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t, nil)
			e.n.cfg.linkAddrsFn = tc.linkAddrs
			e.n.nldNoTrackFails = 1
			e.n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, "missing=OUTPUT")

			e.n.Cycle(context.Background())

			if e.n.nldNoTrackFails != 0 {
				t.Fatalf("nldNoTrackFails = %d, want 0", e.n.nldNoTrackFails)
			}
			if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("pre-existing latch not cleared on gated cycle")
			}
			if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "gated")); got != 1 {
				t.Fatalf("cycles{gated} = %v, want 1", got)
			}
			if e.host.Ran("iptables-save") || e.host.Ran("nft") {
				t.Fatalf("raw probe ran on gated host: %v", e.host.Cmds())
			}
		})
	}
}

func TestNLDNoTrackCiliumLRPBypassVsCiliumWithoutLRP(t *testing.T) {
	t.Run("cilium_lrp_active_gates_and_clears", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		if err := os.MkdirAll(filepath.Join(e.n.cfg.sysClassNet, "cilium_host"), 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, e.n.cfg.ciliumSocket, "")
		e.n.cfg.unixGet = func(_ context.Context, _, path string) ([]byte, error) {
			if path != "/v1/service" {
				return nil, errors.New("unexpected path")
			}
			return []byte(`[
				{"spec":{"name":"kube-dns","namespace":"kube-system","flags":{"type":"LocalRedirect"},"frontend-address":{"ip":"10.96.0.10","port":53}}}
			]`), nil
		}
		e.n.nldNoTrackFails = 1
		e.n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, "missing=OUTPUT")

		e.n.Cycle(context.Background())

		if e.n.nldNoTrackFails != 0 {
			t.Fatalf("nldNoTrackFails = %d, want 0", e.n.nldNoTrackFails)
		}
		if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
			t.Fatal("pre-existing latch not cleared when Cilium LRP is active")
		}
		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "gated")); got != 1 {
			t.Fatalf("cycles{gated} = %v, want 1", got)
		}
		if e.host.Ran("iptables-save") {
			t.Fatalf("iptables-save should not run when Cilium LRP is active")
		}
	})

	t.Run("cilium_without_lrp_checks_raw_table", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		if err := os.MkdirAll(filepath.Join(e.n.cfg.sysClassNet, "cilium_host"), 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, e.n.cfg.ciliumSocket, "")
		e.n.cfg.unixGet = func(_ context.Context, _, path string) ([]byte, error) {
			if path != "/v1/service" {
				return nil, errors.New("unexpected path")
			}
			return []byte(`[
				{"spec":{"name":"kube-dns","namespace":"kube-system","flags":{"type":"ClusterIP"},"frontend-address":{"ip":"10.96.0.10","port":53}}},
				{"spec":{"name":"metrics-lrp","namespace":"monitoring","flags":{"type":"LocalRedirect"},"frontend-address":{"ip":"10.96.1.2","port":9100}}}
			]`), nil
		}
		e.host.On("iptables-save -t raw", healthyIPTablesRaw)

		e.n.Cycle(context.Background())

		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "ok")); got != 1 {
			t.Fatalf("cycles{ok} = %v, want 1", got)
		}
		if !e.host.Ran("iptables-save -t raw") {
			t.Fatalf("expected iptables-save to run on Cilium node without DNS LRP")
		}
	})

	t.Run("cilium_host_without_socket_checks_raw_table", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		if err := os.MkdirAll(filepath.Join(e.n.cfg.sysClassNet, "cilium_host"), 0o755); err != nil {
			t.Fatal(err)
		}
		// ciliumSocket does not exist -> proceed to raw table probe.
		e.host.On("iptables-save -t raw", healthyIPTablesRaw)

		e.n.Cycle(context.Background())

		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "ok")); got != 1 {
			t.Fatalf("cycles{ok} = %v, want 1", got)
		}
		if !e.host.Ran("iptables-save -t raw") {
			t.Fatalf("expected iptables-save to run when cilium socket is absent")
		}
	})
}

func TestNLDNoTrackHealthyIPTables(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
	}{
		{
			name: "j_notrack",
			out:  healthyIPTablesRaw,
		},
		{
			name: "j_ct_notrack_and_sport_and_dports_and_comment",
			out: `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 169.254.20.10 -p udp -m comment --comment "nld pre" -m multiport --dports 53,5353 -j CT --notrack
-A OUTPUT -s 169.254.20.10/32 -p tcp --sport 53 -j CT --notrack
COMMIT
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := nldEnv(t, "169.254.20.10")
			e.host.On("iptables-save -t raw", tc.out)

			e.n.Cycle(context.Background())

			if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("unexpected latch on healthy iptables raw table")
			}
			if e.n.nldNoTrackFails != 0 {
				t.Fatalf("nldNoTrackFails = %d, want 0", e.n.nldNoTrackFails)
			}
			if e.host.Ran("nft") {
				t.Fatalf("nft fallback should not run when iptables-save succeeds")
			}
			if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "ok")); got != 1 {
				t.Fatalf("cycles{ok} = %v, want 1", got)
			}
		})
	}
}

func TestNLDNoTrackHealthyNFTFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		iptErr     error
		iptOut     string
		nftOut     string
		preFailure bool
	}{
		{
			name:       "iptables_fails_nft_uppercase_chains",
			iptErr:     errCmdFail,
			nftOut:     healthyNFTRaw,
			preFailure: true,
		},
		{
			name:   "iptables_empty_nft_lowercase_meta_l4proto",
			iptOut: "",
			nftOut: `table ip raw {
	chain prerouting {
		type filter hook prerouting priority raw; policy accept;
		ip daddr 169.254.20.10/32 meta l4proto { tcp, udp } th dport 53 notrack
	}
	chain output {
		type filter hook output priority raw; policy accept;
		ip daddr 169.254.20.10 meta l4proto { tcp, udp } th dport 53 notrack
	}
}
`,
		},
		{
			name:   "nft_custom_chain_names_with_hooks_and_xt_target",
			iptErr: errCmdFail,
			nftOut: `table ip raw {
	chain custom_pre {
		type filter hook prerouting priority -300; policy accept;
		ip daddr 169.254.20.10 udp dport 53 counter packets 0 bytes 0 xt target "NOTRACK"
	}
	chain custom_out {
		type filter hook output priority -300; policy accept;
		ip daddr 169.254.20.10 tcp dport 53 counter packets 0 bytes 0 xt target "CT" --notrack
	}
}
`,
			preFailure: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := nldEnv(t, "169.254.20.10")
			if tc.preFailure {
				e.host.FailOn("iptables-save -t raw", tc.iptErr)
			} else {
				e.host.On("iptables-save -t raw", tc.iptOut)
			}
			e.host.On("nft list table ip raw", tc.nftOut)

			e.n.Cycle(context.Background())

			if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("unexpected latch on healthy nft fallback")
			}
			if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "ok")); got != 1 {
				t.Fatalf("cycles{ok} = %v, want 1", got)
			}
		})
	}
}

func TestNLDNoTrackTransientMissResetsOnHealthyCycle(t *testing.T) {
	e := nldEnv(t, "169.254.20.10")
	missingOutput := `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 169.254.20.10/32 -p udp --dport 53 -j NOTRACK
COMMIT
`
	e.host.On("iptables-save -t raw", missingOutput)
	e.n.Cycle(context.Background())

	if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
		t.Fatal("latched after 1 cycle (below ConsecNeeded=2)")
	}
	if e.n.nldNoTrackFails != 1 {
		t.Fatalf("nldNoTrackFails = %d, want 1", e.n.nldNoTrackFails)
	}
	logs := logLines(t, e)
	if !strings.Contains(logs, "suspect: nodelocaldns-notrack missing=OUTPUT (check 1/2)") {
		t.Fatalf("missing pending suspect log:\n%s", logs)
	}

	// Healthy cycle resets streak.
	e.host.On("iptables-save -t raw", healthyIPTablesRaw)
	e.n.Cycle(context.Background())
	if e.n.nldNoTrackFails != 0 {
		t.Fatalf("nldNoTrackFails = %d after healthy cycle, want 0", e.n.nldNoTrackFails)
	}

	// Another single miss must still be pending (1/2), not latched.
	e.host.On("iptables-save -t raw", missingOutput)
	e.n.Cycle(context.Background())
	if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
		t.Fatal("latched immediately after reset — streak did not reset")
	}
	if e.n.nldNoTrackFails != 1 {
		t.Fatalf("nldNoTrackFails = %d, want 1", e.n.nldNoTrackFails)
	}
}

func TestNLDNoTrackDriftVariantsHysteresisDetectOnlyAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name        string
		setup       func(e *env)
		wantMissing string
	}{
		{
			name: "missing_output",
			setup: func(e *env) {
				e.host.On("iptables-save -t raw", `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 169.254.20.10 -p udp --dport 53 -j NOTRACK
COMMIT
`)
			},
			wantMissing: "missing=OUTPUT",
		},
		{
			name: "missing_prerouting",
			setup: func(e *env) {
				e.host.On("iptables-save -t raw", `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -d 169.254.20.10 -p udp --dport 53 -j NOTRACK
COMMIT
`)
			},
			wantMissing: "missing=PREROUTING",
		},
		{
			name: "missing_both_iptables_empty_raw",
			setup: func(e *env) {
				e.host.On("iptables-save -t raw", `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`)
			},
			wantMissing: "missing=PREROUTING,OUTPUT",
		},
		{
			name: "nft_missing_table_no_such_file_or_directory",
			setup: func(e *env) {
				fe := testutil.NewFakeExec(
					testutil.ExecRule{Substr: "iptables-save -t raw", Err: errCmdFail},
					testutil.ExecRule{Substr: "nft list table ip raw", Out: "Error: No such file or directory\n", Err: errCmdFail},
				)
				e.host = fe
				e.n.cfg.runHostCmd = fe.Run
				e.n.cfg.runMountCmd = fe.Run
			},
			wantMissing: "missing=PREROUTING,OUTPUT",
		},
		{
			name: "nft_missing_table_does_not_exist",
			setup: func(e *env) {
				fe := testutil.NewFakeExec(
					testutil.ExecRule{Substr: "iptables-save -t raw", Err: errCmdFail},
					testutil.ExecRule{Substr: "nft list table ip raw", Out: "Error: Could not process rule: Table 'raw' does not exist\n", Err: errCmdFail},
				)
				e.host = fe
				e.n.cfg.runHostCmd = fe.Run
				e.n.cfg.runMountCmd = fe.Run
			},
			wantMissing: "missing=PREROUTING,OUTPUT",
		},
		{
			name: "iptables_clean_empty_and_nft_unavailable",
			setup: func(e *env) {
				e.host.On("iptables-save -t raw", "")
				e.host.FailOn("nft list table ip raw", errors.New("executable file not found"))
			},
			wantMissing: "missing=PREROUTING,OUTPUT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := nldEnv(t, "169.254.20.10")
			tc.setup(e)

			// Cycle 1: pending only.
			e.n.Cycle(context.Background())
			if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("latched on cycle 1")
			}

			// Cycle 2: latch enters.
			e.n.Cycle(context.Background())
			if !stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("latch not raised after 2 consecutive misses")
			}
			logs := logLines(t, e)
			wantEnter := "STATE-ENTER: " + latchdefs.LatchNodeLocalDNSNoTrackDrift + " " + tc.wantMissing
			if !strings.Contains(logs, wantEnter) {
				t.Fatalf("missing %q in logs:\n%s", wantEnter, logs)
			}

			// Cycle 3: no duplicate STATE-ENTER, zero mutations (detect-only).
			e.n.Cycle(context.Background())
			logs = logLines(t, e)
			if cnt := strings.Count(logs, "STATE-ENTER: "+latchdefs.LatchNodeLocalDNSNoTrackDrift); cnt != 1 {
				t.Fatalf("STATE-ENTER count = %d, want 1:\n%s", cnt, logs)
			}
			for _, cmd := range e.host.Cmds() {
				joined := strings.Join(cmd, " ")
				if strings.HasPrefix(joined, "iptables ") || strings.HasPrefix(joined, "nft add") ||
					strings.HasPrefix(joined, "nft insert") {
					t.Fatalf("detect-only guard executed mutation command %q", joined)
				}
			}
			if e.sd.Ran("restart") {
				t.Fatalf("detect-only guard restarted a unit: %v", e.sd.Cmds())
			}

			// Cycle 4: recovery clears latch and resets streak.
			e.host.On("iptables-save -t raw", healthyIPTablesRaw)
			e.n.Cycle(context.Background())
			if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
				t.Fatal("latch remained after recovery")
			}
			if e.n.nldNoTrackFails != 0 {
				t.Fatalf("nldNoTrackFails = %d after recovery, want 0", e.n.nldNoTrackFails)
			}
			logs = logLines(t, e)
			wantExit := "STATE-EXIT: " + latchdefs.LatchNodeLocalDNSNoTrackDrift
			if !strings.Contains(logs, wantExit) {
				t.Fatalf("missing %q in logs:\n%s", wantExit, logs)
			}
		})
	}
}

func TestNLDNoTrackProbeErrorsAbortAndPreserveState(t *testing.T) {
	t.Run("netlink_eperm_aborts", func(t *testing.T) {
		e := fixture(t, nil)
		e.n.cfg.linkAddrsFn = func(int, string) ([]netlink.Addr, error) {
			return nil, unix.EPERM
		}
		e.n.nldNoTrackFails = 1
		e.n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, "missing=OUTPUT")

		e.n.Cycle(context.Background())

		if e.n.nldNoTrackFails != 1 {
			t.Fatalf("streak changed on abort: %d", e.n.nldNoTrackFails)
		}
		if !stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
			t.Fatal("pre-existing latch cleared on abort")
		}
		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "abort")); got != 1 {
			t.Fatalf("cycles{abort} = %v, want 1", got)
		}
	})

	t.Run("both_iptables_and_nft_fail_aborts", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		e.host.FailOn("iptables-save -t raw", errors.New("xtables lock timeout"))
		e.host.FailOn("nft list table ip raw", errors.New("operation not permitted"))
		e.n.nldNoTrackFails = 1
		e.n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, "missing=OUTPUT")

		e.n.Cycle(context.Background())

		if e.n.nldNoTrackFails != 1 {
			t.Fatalf("streak changed on abort: %d", e.n.nldNoTrackFails)
		}
		if !stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
			t.Fatal("pre-existing latch cleared on abort")
		}
		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "abort")); got != 1 {
			t.Fatalf("cycles{abort} = %v, want 1", got)
		}
	})

	t.Run("cilium_unix_get_error_aborts", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		if err := os.MkdirAll(filepath.Join(e.n.cfg.sysClassNet, "cilium_host"), 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, e.n.cfg.ciliumSocket, "")
		e.n.cfg.unixGet = func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("connection refused")
		}
		e.n.nldNoTrackFails = 1
		e.n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, "missing=OUTPUT")

		e.n.Cycle(context.Background())

		if e.n.nldNoTrackFails != 1 {
			t.Fatalf("streak changed on abort: %d", e.n.nldNoTrackFails)
		}
		if !stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
			t.Fatal("pre-existing latch cleared on abort")
		}
		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "abort")); got != 1 {
			t.Fatalf("cycles{abort} = %v, want 1", got)
		}
	})

	t.Run("cilium_invalid_json_aborts", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		if err := os.MkdirAll(filepath.Join(e.n.cfg.sysClassNet, "cilium_host"), 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, e.n.cfg.ciliumSocket, "")
		e.n.cfg.unixGet = func(context.Context, string, string) ([]byte, error) {
			return []byte("{truncated"), nil
		}

		e.n.Cycle(context.Background())

		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "abort")); got != 1 {
			t.Fatalf("cycles{abort} = %v, want 1", got)
		}
	})

	t.Run("sysclassnet_unreadable_aborts", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores chmod 0000")
		}
		e := nldEnv(t, "169.254.20.10")
		if err := os.Chmod(e.n.cfg.sysClassNet, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.n.cfg.sysClassNet, 0o755) })

		e.n.Cycle(context.Background())

		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "abort")); got != 1 {
			t.Fatalf("cycles{abort} = %v, want 1", got)
		}
	})
}

func TestNLDNoTrackTokenBoundaryAndKillSwitch(t *testing.T) {
	t.Run("iptables_rejects_false_matches", func(t *testing.T) {
		badIPTables := `*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
# -A PREROUTING -d 169.254.20.10 -p udp --dport 53 -j NOTRACK
-A PREROUTING -d 169.254.20.100 -p udp --dport 53 -j NOTRACK
-A PREROUTING -d 169.254.20.10 -p udp --dport 5300 -j NOTRACK
-A PREROUTING ! -d 169.254.20.10 -p udp --dport 53 -j NOTRACK
-A PREROUTING -d 169.254.20.10 -p udp ! --dport 53 -j NOTRACK
-A PREROUTING -m comment --comment "-d 169.254.20.10 --dport 53 -j NOTRACK" -j ACCEPT
-A OUTPUT -d 169.254.20.10 -p udp --dport 53 -j CT
COMMIT
*filter
-A PREROUTING -d 169.254.20.10 -p udp --dport 53 -j NOTRACK
COMMIT
`
		preOK, outOK := parseIPTablesRawNoTrack(badIPTables, "169.254.20.10")
		if preOK || outOK {
			t.Fatalf("false match in iptables parser: preOK=%v outOK=%v", preOK, outOK)
		}
	})

	t.Run("nft_rejects_false_matches", func(t *testing.T) {
		badNFT := `table ip raw {
	chain PREROUTING {
		type filter hook prerouting priority raw; policy accept;
		# ip daddr 169.254.20.10 udp dport 53 notrack
		ip daddr 169.254.20.100 udp dport 53 notrack
		ip daddr 169.254.20.10 udp dport 5300 notrack
		ip daddr != 169.254.20.10 udp dport 53 notrack
		ip daddr 169.254.20.10 udp dport != 53 notrack
		ip daddr 169.254.20.10 udp dport 53 comment "notrack"
	}
	chain OUTPUT {
		type filter hook output priority raw; policy accept;
		ip daddr 169.254.20.10 udp dport 53 xt target "CT"
	}
}
`
		preOK, outOK := parseNFTRawNoTrack(badNFT, "169.254.20.10")
		if preOK || outOK {
			t.Fatalf("false match in nft parser: preOK=%v outOK=%v", preOK, outOK)
		}
	})

	t.Run("wd_sig_kill_switch_disables_check", func(t *testing.T) {
		e := nldEnv(t, "169.254.20.10")
		e.n.cfg.Watchdog.Disabled = map[string]bool{checkNLDNoTrack: true}
		e.host.On("iptables-save -t raw", "*raw\nCOMMIT\n")

		e.n.Cycle(context.Background())
		e.n.Cycle(context.Background())

		if e.host.Ran("iptables-save") {
			t.Fatal("nodelocaldns-notrack ran despite WD_SIG disable")
		}
		if stateExists(e, latchdefs.LatchNodeLocalDNSNoTrackDrift) {
			t.Fatal("latch raised while check disabled")
		}
		if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(checkNLDNoTrack, "disabled")); got != 2 {
			t.Fatalf("cycles{disabled} = %v, want 2", got)
		}
	})
}
