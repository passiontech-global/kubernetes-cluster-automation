// group_watchdog_extra_test.go — node-watchdog.conf render coverage
// beyond the prune suite: the hub/lighthouse SIG13 block, the
// fail-closed wval refusal, the api-lb fallback-map strip, the
// apilbWatchdogVars derivation (+ explicit overrides), the
// controllerTuning drop-in fan-out, and the not-my-node early gate.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
