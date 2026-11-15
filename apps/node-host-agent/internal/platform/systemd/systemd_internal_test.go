// systemd_internal_test.go — parity pin for the ActiveAge uptime
// source: the Config-alias rework moved ProcUptimeFile from a Config
// field to the WithProcUptimeFile Option; the `/proc/uptime` default
// must survive a dropped Option or ActiveAge reads nothing.
package systemd

import (
	"context"
	"errors"
	"testing"

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
