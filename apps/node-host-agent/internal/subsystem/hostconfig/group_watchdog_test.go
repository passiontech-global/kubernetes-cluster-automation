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

// twoHubNodes — the stock registry with node-b promoted to a second
// hub so the lighthouse peer/fallback-resolver derivations have a
// sibling to point at.
const twoHubNodes = `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
  hub: true
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`

func patchVarsFile(t *testing.T, varsDir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(varsDir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestWatchdogConfHubLighthouseLines — loading as a hub renders the
// SIG13 block: self IP, the OTHER hub as API_PEER, and the kine/oom
// autofix keys the controller remediation modules source.
func TestWatchdogConfHubLighthouseLines(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", twoHubNodes)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupWatchdog()
	conf := hostRead(t, r, "/etc/node-watchdog.conf")
	for _, want := range []string{
		"SIG13_AUTOFIX=\"off\"",
		"API_SELF=\"10.0.1.10:6443\"",
		"API_PEER=\"10.0.2.20:6443\"",
		"KINE_DB_PROBE=", "KINE_POOL_AUTOFIX=\"off\"",
		"KINE_TTL_AUTOFIX=\"off\"", "K0S_OOMLOOP_AUTOFIX=\"off\"",
		"APISERVER_FAST_PROBE_CYCLES=\"3\"",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("hub watchdog conf missing %q:\n%s", want, conf)
		}
	}
	if c.errs != 0 {
		t.Fatalf("hub conf render counted errors: %d", c.errs)
	}
}

// TestWatchdogConfRefusedValueKeepsPrevious — one unsafe value fails
// the WHOLE conf render closed: the previous on-disk file stays and
// the refusal counts a cycle error.
func TestWatchdogConfRefusedValueKeepsPrevious(t *testing.T) {
	vars := writeVarsDir(t, `interdc_nebula_net: 'inj"ect'`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/node-watchdog.conf", "# PREVIOUS GOOD CONF\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupWatchdog()
	if got := hostRead(t, r, "/etc/node-watchdog.conf"); got != "# PREVIOUS GOOD CONF\n" {
		t.Fatalf("refused render rewrote the conf:\n%s", got)
	}
	if c.errs == 0 {
		t.Fatal("unsafe conf value did not count a cycle error")
	}
}

// TestWatchdogConfWorkerStripsCpEndpoint — on a worker with the api
// LB enabled the cp_endpoint entry is stripped from DNS_FALLBACK_MAP
// (it must resolve to the local LB VIP path), while the plain-name
// fallback entries stay.
func TestWatchdogConfWorkerStripsCpEndpoint(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupWatchdog()
	conf := hostRead(t, r, "/etc/node-watchdog.conf")
	if strings.Contains(conf, "api.test.internal:6443=") {
		t.Fatalf("cp_endpoint entry not stripped on a worker:\n%s", conf)
	}
	if !strings.Contains(conf, "api2.test.internal:6443=") {
		t.Fatalf("fallback-name entries lost from DNS_FALLBACK_MAP:\n%s", conf)
	}
}

// TestWatchdogAPIBackendVarsDerivation — the watchdog's api-lb knobs
// derive from api_lb_backends the way defaults.yaml's jinja does
// (probe = *_ctrl addrs, servers = name=addr for all, vip = first
// *_lb name); explicit vars win over the derivation.
func TestWatchdogAPIBackendVarsDerivation(t *testing.T) {
	derived := writeVarsDir(t, `api_lb_backends:
  - name: api_dc1_ctrl
    addr: "10.0.1.10:6443"
  - name: api_dc1_lb
    addr: "10.0.1.11:6443"
  - name: api_dc2_ctrl
    addr: "10.0.2.20:6443"
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: derived, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, derived, "node-b")
	c.groupWatchdog()
	conf := hostRead(t, r, "/etc/node-watchdog.conf")
	for _, want := range []string{
		`API_BACKENDS="10.0.1.10:6443 10.0.2.20:6443"`,
		`API_LB_SERVERS="api_dc1_ctrl=10.0.1.10:6443 api_dc1_lb=10.0.1.11:6443 api_dc2_ctrl=10.0.2.20:6443"`,
		`API_LB_VIP="api_dc1_lb"`,
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("derived api-lb knob missing %q:\n%s", want, conf)
		}
	}

	// Explicit vars override the derivation verbatim.
	explicit := writeVarsDir(t, `api_lb_backends:
  - name: api_dc1_ctrl
    addr: "10.0.1.10:6443"
apiserver_probe_backends: [10.9.9.9]
apiserver_lb_servers: "explicit=only"
apiserver_lb_vip: "myvip"
`)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: explicit, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, explicit, "node-b")
	c2.groupWatchdog()
	conf2 := hostRead(t, r2, "/etc/node-watchdog.conf")
	for _, want := range []string{
		`API_BACKENDS="10.9.9.9"`,
		`API_LB_SERVERS="explicit=only"`,
		`API_LB_VIP="myvip"`,
	} {
		if !strings.Contains(conf2, want) {
			t.Fatalf("explicit override missing %q:\n%s", want, conf2)
		}
	}
}

// TestWatchdogControllerTuningDropins — the controller node gets the
// MemoryMax/OOMPolicy + GOMEMLIMIT cgroup boundary and the sshd
// CPUWeight fan-out; every changed drop-in daemon-reloads.
func TestWatchdogControllerTuningDropins(t *testing.T) {
	vars := writeVarsDir(t, `k0scontroller_memory_max_by_host:
  node-a: 16Gi
k0scontroller_go_memlimit_by_host:
  node-a: 2900MiB
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c := loadCyc(t, r, vars, "node-a")
	c.groupWatchdog()

	mem := hostRead(t, r, "/etc/systemd/system/k0scontroller.service.d/50-memory-guard.conf")
	if !strings.Contains(mem, "MemoryMax=16Gi") || !strings.Contains(mem, "OOMPolicy=continue") {
		t.Fatalf("memory guard drop-in wrong:\n%s", mem)
	}
	ml := hostRead(t, r, "/etc/systemd/system/k0scontroller.service.d/51-go-memlimit.conf")
	if !strings.Contains(ml, "Environment=GOMEMLIMIT=2900MiB") ||
		!strings.Contains(ml, "Environment=GOGC=50") {
		t.Fatalf("gomemlimit drop-in wrong:\n%s", ml)
	}
	for _, d := range []string{"ssh.service.d", "ssh@.service.d", "sshd.service.d"} {
		cpu := hostRead(t, r, "/etc/systemd/system/"+d+"/10-cpuweight.conf")
		if !strings.Contains(cpu, "CPUWeight=10000") {
			t.Fatalf("%s missing CPUWeight drop-in:\n%s", d, cpu)
		}
	}
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n < 5 {
		t.Fatalf("daemon-reload calls = %d, want the changed drop-ins reloaded", n)
	}
	// Idempotent second pass: no further reloads when nothing drifts.
	sr.ClearLog()
	c.groupWatchdog()
	if n := len(sr.CallsMatching("systemctl daemon-reload")); n != 0 {
		t.Fatalf("unchanged controller tuning reloaded %d times", n)
	}
}

// TestWatchdogSkipsUnknownNode — neither worker nor a registry node:
// the group is a prune-only no-op and renders nothing.
func TestWatchdogSkipsUnknownNode(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-z", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-z")
	c.groupWatchdog()
	if hostExists(r, "/etc/node-watchdog.conf") {
		t.Fatal("watchdog conf rendered for an unknown node")
	}
	if hostExists(r, "/var/lib/node-watchdog/installed") {
		t.Fatal("installed marker written for an unknown node")
	}
}

// TestWatchdogLogFileCreateFailureWarns — /var/log not creatable:
// the compat log file failure is a warning, never counted, and the
// rest of the converge (conf, dirs, marker) still lands.
func TestWatchdogLogFileCreateFailureWarns(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/var/log", "not a dir\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupWatchdog()
	if c.errs != 0 {
		t.Fatalf("errs = %d — the compat log file is best-effort", c.errs)
	}
	if !hostExists(r, "/etc/node-watchdog.conf") {
		t.Fatal("conf not converged despite the log-file failure")
	}
}

// TestWatchdogAPILBVarsShapeSkips — non-mapping entries and entries
// missing name/addr in api_lb_backends are skipped by the derivation.
func TestWatchdogAPILBVarsShapeSkips(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - just-a-string
  - name: no_addr
  - addr: "10.0.1.10:6443"
  - name: api_dc1_ctrl
    addr: "10.0.1.11:6443"
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	pb, lbSrv, lbVip := c.apilbWatchdogVars()
	if strings.Join(pb, " ") != "10.0.1.11:6443" {
		t.Fatalf("probe backends = %v, want only the *_ctrl addr", pb)
	}
	if lbSrv != "api_dc1_ctrl=10.0.1.11:6443" {
		t.Fatalf("lb servers = %q — the addrless entry must be skipped", lbSrv)
	}
	if lbVip != "" {
		t.Fatalf("lb vip = %q, want empty without a *_lb backend", lbVip)
	}
}

// TestControllerTuningSkipsNonController — the tuning drop-ins only
// converge on k0scontroller hosts.
func TestControllerTuningSkipsNonController(t *testing.T) {
	vars := writeVarsDir(t, `k0scontroller_memory_max_by_host:
  node-b: 16Gi
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.controllerTuning()
	if hostExists(r, "/etc/systemd/system/k0scontroller.service.d/50-memory-guard.conf") {
		t.Fatal("controller drop-in written without the controller unit")
	}
	if hostExists(r, "/etc/systemd/system/ssh.service.d/10-cpuweight.conf") {
		t.Fatal("sshd drop-in written without the controller unit")
	}
}
