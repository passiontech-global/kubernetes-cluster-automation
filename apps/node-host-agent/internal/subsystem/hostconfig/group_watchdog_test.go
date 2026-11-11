// group_watchdog_test.go — legacy node-watchdog stack prune:
// units/drop-ins/scripts swept, keep-list preserved, and
// idempotent second cycle.
package hostconfig

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// ---------- legacy watchdog prune ----------

func TestPruneLegacyWatchdogStack(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	// Seed every legacy artifact the prune must sweep.
	for _, u := range watchdogconf.LegacyUnits {
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

	// units stopped+disabled — ONE batched `systemctl disable
	// --now` covering every seeded unit file (the per-unit fork
	// fan-out is gone; the file sweep still removes them all).
	disableCalls := sr.CallsMatching("systemctl disable --now")
	if len(disableCalls) != 1 {
		t.Fatalf("systemctl disable calls=%d want 1: %v",
			len(disableCalls), disableCalls)
	}
	for _, u := range watchdogconf.LegacyUnits {
		if !strings.Contains(disableCalls[0], u) {
			t.Fatalf("batched disable missing unit %q: %q", u, disableCalls[0])
		}
	}
	// every unit file / drop-in / script / lib dir gone
	for _, u := range watchdogconf.LegacyUnits {
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
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not run after unit removal")
	}
	// idempotent second cycle — no resurrected files, no errors
	sr.ClearLog()
	c.groupWatchdog()
	for _, u := range watchdogconf.LegacyUnits {
		if hostExists(r, "/etc/systemd/system/"+u) {
			t.Fatalf("unit file resurrected: %s", u)
		}
	}
}

// ---------- controller tuning drop-ins (ctrlDropIn) ----------

// TestCtrlDropInConvergesBothWays — a per-host map var renders the
// drop-in for THIS node and daemon-reloads exactly once; an identical
// re-render stays silent; an absent var converges a stale drop-in
// away (reload only when a file actually came off disk); a map
// without this node is a no-op.
func TestCtrlDropInConvergesBothWays(t *testing.T) {
	vars := writeVarsDir(t, `k0scontroller_memory_max_by_host:
  node-a: 16Gi
  node-b: 14Gi
k0scontroller_cpu_weight_by_host:
  node-a: 10000
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	render := func(v string) []byte { return []byte("[Service]\nMemoryMax=" + v + "\n") }
	drop := "/etc/systemd/system/k0scontroller.service.d/50-memory-guard.conf"

	// map hit → drop-in rendered for node-b + one daemon-reload
	c.ctrlDropIn("k0scontroller_memory_max_by_host", "50-memory-guard.conf", render)
	if got := hostRead(t, r, drop); !strings.Contains(got, "MemoryMax=14Gi") {
		t.Fatalf("drop-in = %q, want node-b's 14Gi value", got)
	}
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n != 1 {
		t.Fatalf("daemon-reload calls = %d want 1 after the first converge", n)
	}

	// unchanged re-render → silent
	sr.ClearLog()
	c.ctrlDropIn("k0scontroller_memory_max_by_host", "50-memory-guard.conf", render)
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n != 0 {
		t.Fatalf("daemon-reload fired %d times on an unchanged drop-in", n)
	}

	// stale file + absent var → removed + daemon-reload
	stale := "/etc/systemd/system/k0scontroller.service.d/51-go-memlimit.conf"
	hostWrite(t, r, stale, "[Service]\nEnvironment=GOMEMLIMIT=8Gi\n")
	c.ctrlDropIn("k0scontroller_go_memlimit_by_host", "51-go-memlimit.conf", render)
	if hostExists(r, stale) {
		t.Fatal("stale drop-in not removed on an absent var")
	}
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n != 1 {
		t.Fatalf("daemon-reload calls = %d want 1 after the removal", n)
	}

	// map without this node → nothing on disk, nothing to reload
	sr.ClearLog()
	c.ctrlDropIn("k0scontroller_cpu_weight_by_host", "52-cpuweight.conf", render)
	if hostExists(r, "/etc/systemd/system/k0scontroller.service.d/52-cpuweight.conf") {
		t.Fatal("drop-in created from a map missing this node")
	}
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n != 0 {
		t.Fatalf("daemon-reload fired %d times on a no-op removal", n)
	}
	if c.errs != 0 {
		t.Fatalf("errs = %d — converge-only paths must not count errors", c.errs)
	}
}

// ---------- strListVar: list-ish var reads ----------

func TestStrListVar(t *testing.T) {
	vars := writeVarsDir(t, `str_list_ok:
  - 10.0.0.1
  - 10.0.0.2
str_list_scalar: "10.0.0.1, 10.0.0.2"
str_list_chars:
  - a
  - b
str_list_empty: []
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	// A real YAML list passes through untouched.
	if got := strListVar(c, "str_list_ok"); !slices.Equal(got,
		[]string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("strListVar(list)=%v", got)
	}
	// A jinja scalar rendered to a STRING must not go through
	// Vars.List — ToIter would iterate it rune-by-rune; the
	// char-split fallback reparses the scalar on whitespace/commas.
	if got := strListVar(c, "str_list_scalar"); !slices.Equal(got,
		[]string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("strListVar(scalar)=%v", got)
	}
	// A genuine list of 1-char entries trips the same char-split
	// guard and reparses via Stringify ("[a, b]" → a, b).
	if got := strListVar(c, "str_list_chars"); !slices.Equal(got,
		[]string{"a", "b"}) {
		t.Fatalf("strListVar(chars)=%v", got)
	}
	if got := strListVar(c, "str_list_empty"); len(got) != 0 {
		t.Fatalf("strListVar(empty)=%v want empty", got)
	}
	if got := strListVar(c, "no_such_var"); got != nil {
		t.Fatalf("strListVar(unset)=%v want nil", got)
	}
}

// poisonVars appends a poisoned scalar to defaults.yaml and returns
// the appended raw value.
func poisonVars(t *testing.T, varsDir, line string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(varsDir, "defaults.yaml"),
		os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestWatchdogConfInjectionFailsClosed: a quote or newline in a
// vars-derived value would inject arbitrary conf/shell directives
// into /etc/node-watchdog.conf (the watchdog scripts source it
// wholesale). The render must fail CLOSED — counted error, warn, and
// NO conf write (the previous on-disk file keeps serving).
func TestWatchdogConfInjectionFailsClosed(t *testing.T) {
	for name, poisoned := range map[string]string{
		"quote":    `interdc_slowpath_rtt_ms: '100"; rm -rf /'`,
		"newline":  "interdc_slowpath_rtt_ms: |-\n  100\n  200",
		"expand":   `interdc_slowpath_rtt_ms: '$(id)'`,
		"backtick": "interdc_slowpath_rtt_ms: '`id`'",
		// A trailing backslash escapes the render's own closing
		// quote: the string swallows the following conf lines and the
		// next line's value parses OUTSIDE quotes where ; | & execute.
		"backslash": `interdc_slowpath_rtt_ms: 'neb1\'`,
	} {
		t.Run(name, func(t *testing.T) {
			vars := writeVarsDir(t, "")
			poisonVars(t, vars, poisoned)
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				WatchdogScriptsDir: t.TempDir()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			c.groupWatchdog()
			if hostExists(r, "/etc/node-watchdog.conf") {
				t.Fatalf("conf written despite refused %s value", name)
			}
			if c.errs == 0 {
				t.Fatal("refused value not counted as a cycle error")
			}
		})
	}
}
