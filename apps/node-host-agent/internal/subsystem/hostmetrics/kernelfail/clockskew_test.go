// clockskew_test.go — unit tests for timedatectl timesync-status parsing and
// the adjtimex -> timesyncd fallback flow in clockSkewProbe/checkClockSkew.
package kernelfail

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestParseTimesyncStatusOffset(t *testing.T) {
	cases := []struct {
		name       string
		out        string
		wantOff    float64
		wantSynced bool
		wantOK     bool
	}{
		{
			name: "healthy positive ms offset",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"Poll interval: 4min 16s (min: 32s; max 4min 16s)\n" +
				"         Leap: normal\n" +
				"       Offset: +1.238ms\n" +
				" Packet count: 42\n",
			wantOff:    0.001238,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "healthy negative ms offset",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: -40.430ms\n" +
				" Packet count: 12\n",
			wantOff:    -0.04043,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "large negative seconds offset",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: -7.803s\n" +
				" Packet count: 5\n",
			wantOff:    -7.803,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "microseconds us and unicode micro sign",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: +500us\n" +
				" Packet count: 3\n",
			wantOff:    0.0005,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "unicode microsecond unit",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: -250µs\n" +
				" Packet count: 3\n",
			wantOff:    -0.00025,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "minutes unit",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: +2.5min\n" +
				" Packet count: 2\n",
			wantOff:    150.0,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "compound systemd timespan min + s",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: -1min 7.803s\n" +
				" Packet count: 4\n",
			wantOff:    -67.803,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "zero offset without unit",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: 0\n" +
				" Packet count: 1\n",
			wantOff:    0,
			wantSynced: true,
			wantOK:     true,
		},
		{
			name: "packet count zero signals silent stall",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"Poll interval: 32s (min: 32s; max 4min 16s)\n" +
				" Packet count: 0\n",
			wantOff:    0,
			wantSynced: false,
			wantOK:     true,
		},
		{
			name: "server n/a and packet count zero signals silent stall",
			out: "       Server: n/a\n" +
				"Poll interval: 0 (min: 32s; max 4min 16s)\n" +
				" Packet count: 0\n",
			wantOff:    0,
			wantSynced: false,
			wantOK:     true,
		},
		{
			name: "server (null) signals unsynced",
			out: "       Server: (null)\n" +
				"       Offset: -3.2s\n" +
				" Packet count: 1\n",
			wantOff:    -3.2,
			wantSynced: false,
			wantOK:     true,
		},
		{
			name: "missing server line marks unsynced while preserving offset",
			out: "Poll interval: 32s\n" +
				"       Offset: -7.803s\n" +
				" Packet count: 5\n",
			wantOff:    -7.803,
			wantSynced: false,
			wantOK:     true,
		},
		{
			name:   "empty output is unparseable",
			out:    "",
			wantOK: false,
		},
		{
			name:   "garbage output is unparseable",
			out:    "Failed to query server: Unit not found\n",
			wantOK: false,
		},
		{
			name: "synced server without offset line is truncated/invalid",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				" Packet count: 10\n",
			wantOK: false,
		},
		{
			name: "corrupt offset on synced server is invalid",
			out: "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
				"       Offset: bogus\n" +
				" Packet count: 10\n",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			off, synced, ok := parseTimesyncStatusOffset(tc.out)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (off=%v synced=%v)", ok, tc.wantOK, off, synced)
			}
			if !ok {
				return
			}
			if synced != tc.wantSynced {
				t.Fatalf("synced = %v, want %v (off=%v)", synced, tc.wantSynced, off)
			}
			if math.Abs(off-tc.wantOff) > 1e-9 {
				t.Fatalf("off = %.9f, want %.9f", off, tc.wantOff)
			}
		})
	}
}

func TestClockSkewProbeTimesyncdFallback(t *testing.T) {
	t.Run("silent stall: adjtimex clean but timedatectl reports -7.803s -> restarts and latches", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		now := time.Unix(1_700_000_000, 0)
		f.deps.Clock.Set(func() time.Time { return now })
		// Kernel adjtimex looks healthy: STA_UNSYNC=0 and tiny -2ms offset.
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = -2_000_000 // -2ms in ns
			tx.Status = unix.STA_NANO
			return 0, nil
		}
		var restarted int
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			switch strings.Join(argv, " ") {
			case "timedatectl timesync-status":
				return "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
					"       Offset: -7.803s\n" +
					" Packet count: 9\n", nil
			case "systemctl is-active --quiet systemd-timesyncd":
				return "", nil
			case "systemctl restart systemd-timesyncd":
				restarted++
				return "", nil
			default:
				t.Fatalf("unexpected RunHostCmd: %v", argv)
				return "", nil
			}
		}

		for i := 0; i < clockSkewLatchNeeded; i++ {
			f.r.checkClockSkew(context.Background())
		}
		if restarted != 1 {
			t.Fatalf("timesyncd restarts = %d, want 1 (rate-limited across ticks)", restarted)
		}
		if _, err := os.Stat(filepath.Join(f.deps.StateDir, "state-clock-skew")); err != nil {
			t.Fatal("state-clock-skew latch missing after 5 ticks of -7.803s timesyncd offset")
		}
	})

	t.Run("silent stall: adjtimex clean but Packet count 0 / Server n/a -> restarts timesyncd", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = 500_000 // +0.5ms in ns
			tx.Status = unix.STA_NANO
			return 0, nil
		}
		restarted := false
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			switch strings.Join(argv, " ") {
			case "timedatectl timesync-status":
				return "       Server: n/a\nPoll interval: 0\n Packet count: 0\n", nil
			case "systemctl is-active --quiet systemd-timesyncd":
				return "", nil
			case "systemctl restart systemd-timesyncd":
				restarted = true
				return "", nil
			default:
				t.Fatalf("unexpected RunHostCmd: %v", argv)
				return "", nil
			}
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || synced {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want ok=true synced=false", off, synced, ok)
		}
		f.r.checkClockSkew(context.Background())
		if !restarted {
			t.Fatal("timesyncd not restarted when timedatectl reported Server: n/a / Packet count: 0")
		}
	})

	t.Run("healthy timesyncd smaller than adjtimex keeps larger magnitude and stays clean", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = -40_000_000 // -40ms in ns
			tx.Status = unix.STA_NANO
			return 0, nil
		}
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			if strings.Join(argv, " ") == "timedatectl timesync-status" {
				return "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
					"       Offset: +1.238ms\n" +
					" Packet count: 42\n", nil
			}
			t.Fatalf("unexpected RunHostCmd: %v", argv)
			return "", nil
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || !synced || math.Abs(off-(-0.04)) > 1e-9 {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want (-0.04, true, true)", off, synced, ok)
		}
	})

	t.Run("timedatectl error falls back safely to adjtimex", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = 10_000_000 // +10ms in ns
			tx.Status = unix.STA_NANO
			return 0, nil
		}
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			if strings.Join(argv, " ") == "timedatectl timesync-status" {
				return "", errors.New("dbus unavailable")
			}
			t.Fatalf("unexpected RunHostCmd: %v", argv)
			return "", nil
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || !synced || math.Abs(off-0.01) > 1e-9 {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want (0.01, true, true)", off, synced, ok)
		}
	})

	t.Run("chronyc host skips timedatectl on healthy adjtimex fast path", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "chronyc"), "#!/bin/sh\n")
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = 5_000_000 // +5ms in ns
			tx.Status = unix.STA_NANO
			return 0, nil
		}
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			t.Fatalf("healthy chronyc host must not fork: %v", argv)
			return "", nil
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || !synced || math.Abs(off-0.005) > 1e-9 {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want (0.005, true, true)", off, synced, ok)
		}
	})

	t.Run("adjtimex ENOSYS falls back to timedatectl timesync-status", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			if strings.Join(argv, " ") == "timedatectl timesync-status" {
				return "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
					"       Offset: -40.430ms\n" +
					" Packet count: 8\n", nil
			}
			t.Fatalf("unexpected RunHostCmd: %v", argv)
			return "", nil
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || !synced || math.Abs(off-(-0.04043)) > 1e-9 {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want (-0.04043, true, true)", off, synced, ok)
		}
	})

	t.Run("chronyc tracking failure falls back to timedatectl when present", func(t *testing.T) {
		f := kfixture(t)
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "chronyc"), "#!/bin/sh\n")
		testutil.WriteFile(t, filepath.Join(f.deps.HostRoot, "usr", "bin", "timedatectl"), "#!/bin/sh\n")
		f.r.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
			tx.Offset = 1_000_000 // +1s in us (> 0.5s)
			tx.Status = 0
			return 0, nil
		}
		var cmds []string
		f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
			cmd := strings.Join(argv, " ")
			cmds = append(cmds, cmd)
			switch cmd {
			case "chronyc tracking":
				return "", errors.New("chronyd not running")
			case "timedatectl timesync-status":
				return "       Server: 162.159.200.1 (time.cloudflare.com)\n" +
					"       Offset: -7.803s\n" +
					" Packet count: 5\n", nil
			default:
				t.Fatalf("unexpected RunHostCmd: %v", argv)
				return "", nil
			}
		}

		off, synced, ok := f.r.clockSkewProbe(context.Background())
		if !ok || !synced || math.Abs(off-(-7.803)) > 1e-9 {
			t.Fatalf("probe = (off=%v, synced=%v, ok=%v), want (-7.803, true, true)", off, synced, ok)
		}
		if len(cmds) != 2 || cmds[0] != "chronyc tracking" || cmds[1] != "timedatectl timesync-status" {
			t.Fatalf("cmds = %v, want [chronyc tracking, timedatectl timesync-status]", cmds)
		}
	})
}
