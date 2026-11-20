// systemd_internal_test.go — parity pin for the ActiveAge uptime
// source: the Config-alias rework moved ProcUptimeFile from a Config
// field to the WithProcUptimeFile Option; the `/proc/uptime` default
// must survive a dropped Option or ActiveAge reads nothing.
package systemd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestDefaultProcUptimeFile(t *testing.T) {
	c := New(Config{})
	if c.procUptimeFile != defaultProcUptimeFile {
		t.Fatalf("procUptimeFile default = %q, want %q",
			c.procUptimeFile, defaultProcUptimeFile)
	}
	if defaultProcUptimeFile != "/proc/uptime" {
		t.Fatalf("defaultProcUptimeFile changed: %q", defaultProcUptimeFile)
	}
}

func TestClientMethodsAndCLIFallbacks(t *testing.T) {
	f := testutil.NewFakeExec()
	f.On("show -p ActiveEnterTimestampMonotonic", "ActiveEnterTimestampMonotonic=1234567\n")
	f.On("MainPID", "4242\n")
	f.On("list-units", "k0sworker.service loaded active running k0s worker\n")
	f.On("is-system-running", "running\n")
	f.On("stop ", "")
	f.On("reset-failed", "")

	c := New(Config{HostRoot: t.TempDir(), RunCmd: f.Run})
	defer c.Close()

	if c.dbusUnavailable(errors.New("other")) {
		t.Fatal("unrelated error reported dbusUnavailable")
	}
	if !c.dbusUnavailable(errDBusUnavailable) {
		t.Fatal("errDBusUnavailable not reported")
	}

	ctx := context.Background()
	if _, err := c.ActiveEnterUSec(ctx, "k0sworker"); err == nil {
		t.Fatal("expected ActiveEnterUSec without dbus backend to return error")
	}
	if pid, err := c.MainPID(ctx, "k0sworker"); err != nil || pid != 4242 {
		t.Fatalf("MainPID = (%d,%v)", pid, err)
	}
	if units, err := c.ListUnits(ctx); err != nil || len(units) != 1 || units[0].Name != "k0sworker.service" {
		t.Fatalf("ListUnits = (%+v,%v)", units, err)
	}
	if units, err := c.ListUnitsByPatterns(ctx, "*.service"); err != nil || len(units) != 1 {
		t.Fatalf("ListUnitsByPatterns = (%+v,%v)", units, err)
	}
	if st, err := c.SystemState(ctx); err != nil || st != "running" {
		t.Fatalf("SystemState = (%q,%v)", st, err)
	}
	if err := c.Stop(ctx, "k0sworker"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.ResetFailed(ctx, "k0sworker"); err != nil {
		t.Fatalf("ResetFailed: %v", err)
	}
}

func TestRunVerbHonorsCallerDeadline(t *testing.T) {
	const cfgTimeout = 2 * time.Second

	t.Run("dbus_preserves_longer_deadline", func(t *testing.T) {
		c := New(Config{
			HostRoot: t.TempDir(),
			Timeout:  cfgTimeout,
			RunCmd: func(context.Context, []string) (string, error) {
				return "", errors.New("cli should not run")
			},
		})
		defer c.Close()
		c.dbus = newDBusBackend(t.TempDir())

		wantDL := time.Now().Add(90 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), wantDL)
		defer cancel()

		var gotDL time.Time
		if err := c.runVerb(ctx, func(dctx context.Context) error {
			var ok bool
			gotDL, ok = dctx.Deadline()
			if !ok {
				t.Fatal("dbusCtx missing deadline")
			}
			return nil
		}, "restart", "k0sworker"); err != nil {
			t.Fatalf("runVerb: %v", err)
		}
		if gotDL.Sub(wantDL).Abs() > time.Millisecond {
			t.Fatalf("dbusCtx deadline = %v, want %v (diff %v)", gotDL, wantDL, gotDL.Sub(wantDL))
		}
	})

	t.Run("dbus_bounds_unbudgeted_ctx", func(t *testing.T) {
		c := New(Config{
			HostRoot: t.TempDir(),
			Timeout:  cfgTimeout,
			RunCmd: func(context.Context, []string) (string, error) {
				return "", errors.New("cli should not run")
			},
		})
		defer c.Close()
		c.dbus = newDBusBackend(t.TempDir())

		before := time.Now()
		var gotDL time.Time
		if err := c.runVerb(context.Background(), func(dctx context.Context) error {
			var ok bool
			gotDL, ok = dctx.Deadline()
			if !ok {
				t.Fatal("dbusCtx missing fallback deadline")
			}
			return nil
		}, "restart", "k0sworker"); err != nil {
			t.Fatalf("runVerb: %v", err)
		}
		rem := gotDL.Sub(before)
		if rem < cfgTimeout-200*time.Millisecond || rem > cfgTimeout+200*time.Millisecond {
			t.Fatalf("dbusCtx fallback timeout = %v, want ~%v", rem, cfgTimeout)
		}
	})

	t.Run("cli_fallback_preserves_longer_deadline", func(t *testing.T) {
		var gotDL time.Time
		c := New(Config{
			HostRoot: t.TempDir(),
			Timeout:  cfgTimeout,
			RunCmd: func(ctx context.Context, _ []string) (string, error) {
				var ok bool
				gotDL, ok = ctx.Deadline()
				if !ok {
					t.Fatal("RunCmd ctx missing deadline")
				}
				return "", nil
			},
		})
		defer c.Close()
		c.dbus = newDBusBackend(t.TempDir())

		wantDL := time.Now().Add(90 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), wantDL)
		defer cancel()

		err := c.runVerb(ctx, func(context.Context) error {
			return errDBusUnavailable
		}, "restart", "k0sworker")
		if err != nil {
			t.Fatalf("runVerb: %v", err)
		}
		if gotDL.Sub(wantDL).Abs() > 50*time.Millisecond {
			t.Fatalf("CLI fallback deadline = %v, want ~%v (diff %v)", gotDL, wantDL, gotDL.Sub(wantDL))
		}
	})

	t.Run("cli_fallback_respects_shorter_deadline", func(t *testing.T) {
		var gotDL time.Time
		c := New(Config{
			HostRoot: t.TempDir(),
			Timeout:  cfgTimeout,
			RunCmd: func(ctx context.Context, _ []string) (string, error) {
				var ok bool
				gotDL, ok = ctx.Deadline()
				if !ok {
					t.Fatal("RunCmd ctx missing deadline")
				}
				return "", nil
			},
		})
		defer c.Close()

		wantDL := time.Now().Add(500 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), wantDL)
		defer cancel()

		if err := c.Restart(ctx, "k0sworker"); err != nil {
			t.Fatalf("Restart: %v", err)
		}
		if gotDL.After(wantDL.Add(5 * time.Millisecond)) {
			t.Fatalf("shorter deadline exceeded: got %v > want %v", gotDL, wantDL)
		}
	})
}
