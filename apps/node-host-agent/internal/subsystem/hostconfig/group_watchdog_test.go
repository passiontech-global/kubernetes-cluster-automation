// group_watchdog_test.go — legacy node-watchdog stack prune:
// units/drop-ins/scripts swept, keep-list preserved, and
// idempotent second cycle.
package hostconfig

import (
	"strings"
	"testing"
)

// ---------- legacy watchdog prune ----------

func TestPruneLegacyWatchdogStack(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	// Seed every legacy artifact the prune must sweep.
	for _, u := range legacyWatchdogUnits {
		hostWrite(t, r, "/etc/systemd/system/"+u, "[Unit]\n")
	}
	for _, p := range legacyWatchdogDropins {
		hostWrite(t, r, p, "[Service]\nWatchdogSec=30s\n")
	}
	for _, s := range legacyWatchdogScripts {
		hostWrite(t, r, s, "#!/bin/sh\n")
	}
	hostWrite(t, r, "/usr/local/lib/node-watchdog/lib.sh", "# lib\n")
	hostWrite(t, r, "/usr/local/lib/node-watchdog/modules/50-fail2ban.sh", "#!/bin/sh\n")
	hostWrite(t, r, "/var/lib/node-exporter/textfile/node-watchdog.prom", "x 1\n")

	c := loadCyc(t, r, vars, "node-b")
	c.groupWatchdog()

	// units stopped+disabled
	for _, want := range []string{
		"systemctl disable --now node-watchdog.timer",
		"systemctl disable --now k0s-apiserver-wedge-probe.timer",
		"systemctl disable --now kine-db-probe.timer",
		"systemctl disable --now api-backend-guard.service",
		"systemctl disable --now nebula-route-guard.service",
	} {
		if len(sr.callsMatching(want)) == 0 {
			t.Fatalf("missing call %q", want)
		}
	}
	// every unit file / drop-in / script / lib dir gone
	for _, u := range legacyWatchdogUnits {
		if hostExists(r, "/etc/systemd/system/"+u) {
			t.Fatalf("unit file still present: %s", u)
		}
	}
	for _, p := range append(append([]string{}, legacyWatchdogDropins...), legacyWatchdogScripts...) {
		if hostExists(r, p) {
			t.Fatalf("file still present: %s", p)
		}
	}
	if hostExists(r, "/usr/local/lib/node-watchdog") {
		t.Fatal("/usr/local/lib/node-watchdog still present")
	}
	if hostExists(r, "/var/lib/node-exporter/textfile/node-watchdog.prom") {
		t.Fatal("stale .prom not removed on k8s worker")
	}
	// keep-list: conf rendered, state dir + log + marker live on
	conf := hostRead(t, r, "/etc/node-watchdog.conf")
	if !strings.Contains(conf, "OVERLAY_PROBE_TARGETS") {
		t.Fatalf("node-watchdog.conf must keep rendering:\n%s", conf)
	}
	if !hostExists(r, "/var/lib/node-watchdog/installed") {
		t.Fatal("state dir installed marker missing")
	}
	if len(sr.callsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not run after unit removal")
	}
	// idempotent second cycle — no resurrected files, no errors
	sr.calls = nil
	c.groupWatchdog()
	for _, u := range legacyWatchdogUnits {
		if hostExists(r, "/etc/systemd/system/"+u) {
			t.Fatalf("unit file resurrected: %s", u)
		}
	}
}
