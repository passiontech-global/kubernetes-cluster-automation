// systemd_internal_test.go — parity pin for the ActiveAge uptime
// source: the Config-alias rework moved ProcUptimeFile from a Config
// field to the WithProcUptimeFile Option; the `/proc/uptime` default
// must survive a dropped Option or ActiveAge reads nothing.
package systemd

import "testing"

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
