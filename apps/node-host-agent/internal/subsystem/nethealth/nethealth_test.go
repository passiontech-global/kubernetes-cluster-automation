package nethealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// errCmdFail / errNoUnit are the canned failures: host commands
// fail like a non-zero exit, a unit the fixture did not stub reads
// as absent to the systemd client.
var (
	errCmdFail = errors.New("exit 2")
	errNoUnit  = errors.New("no such unit")
)

// env is the fixture: tempdir state/hosts/resolv + canned probes and
// recording FakeExec runners for host commands and the systemd
// client. The recorders serialize their own logs — Cycle
// (checkNebulaDirectTCP → n.ip) and a spawned routeGuard goroutine
// can invoke them concurrently.
type env struct {
	n        *NetHealth
	state    string
	hosts    string
	resv     string
	procudp  string
	procudp6 string
	uptime   string
	ctcount  string
	ctmax    string
	timex    unix.Timex
	adjErr   error
	now      time.Time
	host     *testutil.FakeExec // runHostCmd + runMountCmd seam
	sd       *testutil.FakeExec // systemd client's RunCmd seam
	dnsOK    map[string]string  // "ns|name" → ip; absent = fail
	tcpOK    map[string]bool    // "host:port" → reachable
	pingOK   map[string]bool    // "ip|marked" → alive
	pingRTT  map[string]float64
	httpErr  map[string]error
}

func fixture(t *testing.T, wd *watchdogconf.Config) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		now:     time.Now(),
		host:    testutil.NewFakeExec(),
		sd:      testutil.NewFakeExec().Miss(errNoUnit),
		dnsOK:   map[string]string{},
		tcpOK:   map[string]bool{},
		pingOK:  map[string]bool{},
		pingRTT: map[string]float64{},
		httpErr: map[string]error{},
	}
	e.state = filepath.Join(root, "watchdog")
	e.hosts = filepath.Join(root, "hosts")
	e.resv = filepath.Join(root, "resolv.conf")
	e.procudp = filepath.Join(root, "udp")
	e.procudp6 = filepath.Join(root, "udp6")
	e.uptime = filepath.Join(root, "uptime")
	e.ctcount = filepath.Join(root, "nf_conntrack_count")
	e.ctmax = filepath.Join(root, "nf_conntrack_max")
	for _, d := range []string{e.state} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, e.uptime, "3600.00 7200.00\n")
	testutil.WriteFile(t, e.hosts, "127.0.0.1 localhost\n::1 localhost\n")
	// Healthy defaults: empty conntrack table, synchronized clock.
	testutil.WriteFile(t, e.ctcount, "0\n")
	testutil.WriteFile(t, e.ctmax, "262144\n")
	if wd == nil {
		wd = &watchdogconf.Config{}
	}
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sd.Run})
	n, err := New(Config{
		Interval:           time.Hour,
		WatchdogStateDir:   e.state,
		WatchdogLogFile:    filepath.Join(root, "watchdog.log"),
		HostResolvConf:     e.resv,
		HostsFile:          e.hosts,
		ProcNetUDP:         e.procudp,
		ProcNetUDP6:        e.procudp6,
		UptimeFile:         e.uptime,
		ConntrackCountFile: e.ctcount,
		ConntrackMaxFile:   e.ctmax,
		HostRoot:           "/",
		Watchdog:           wd,
		Systemd:            sd,
		ConsecNeeded:       2,
		MinRestart:         30 * time.Minute,
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	n.cfg.Clock.Set(func() time.Time { return e.now })
	n.cfg.runHostCmd = e.host.Run
	n.cfg.runMountCmd = e.host.Run
	n.cfg.dnsProbe = func(_ context.Context, ns, name string) (string, error) {
		if ip, ok := e.dnsOK[ns+"|"+name]; ok {
			return ip, nil
		}
		return "", errors.New("timeout")
	}
	n.cfg.tcpProbe = func(_ context.Context, host, port string, _ time.Duration) error {
		if e.tcpOK[host+":"+port] {
			return nil
		}
		return errors.New("refused")
	}
	n.cfg.ping = func(_ context.Context, ip string, _, _ int, marked bool) (bool, float64) {
		return e.pingOK[fmt.Sprintf("%s|%v", ip, marked)],
			e.pingRTT[fmt.Sprintf("%s|%v", ip, marked)]
	}
	n.cfg.probeHTTP = func(_ context.Context, url string, _ time.Duration) error {
		return e.httpErr[url]
	}
	n.cfg.adjtimexFn = func(buf *unix.Timex) (int, error) {
		*buf = e.timex
		return 0, e.adjErr
	}
	e.n = n
	return e
}

func logLines(t *testing.T, e *env) string {
	t.Helper()
	data, err := os.ReadFile(e.n.cfg.WatchdogLogFile)
	if err != nil {
		return ""
	}
	return string(data)
}

func stateExists(e *env, name string) bool {
	_, err := os.Stat(filepath.Join(e.state, "state-"+name))
	return err == nil
}

// The suspectLog dedupe budgets are named last-suspect-<key>; keys
// without a state-* latch (egress-probe-<ip> and friends) had no
// reset path — a latch exit is the incident boundary that now drops
// the whole family, while ordinary last-* action budgets stay.
func TestStateExitDropsSuspectBudgets(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, filepath.Join(e.state, "state-conntrack-pressure"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "last-suspect-conntrack-pressure"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "last-suspect-egress-probe-8.8.8.8"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "last-nebula-restart"), "1\n") // action budget — not a suspect key

	e.n.stateExit("conntrack-pressure")

	// The latch and its OWN dedupe budget go — a cleared condition
	// must not suppress the first line of a re-incident.
	for _, f := range []string{
		"state-conntrack-pressure",
		"last-suspect-conntrack-pressure",
	} {
		if _, err := os.Stat(filepath.Join(e.state, f)); !os.IsNotExist(err) {
			t.Fatalf("%s kept after latch exit", f)
		}
	}
	// Other keys' budgets stay: ExitClearSuspect is per-name (the
	// egress probe's dedupe window has nothing to do with this
	// latch), and action budgets are never suspect keys.
	for _, f := range []string{
		"last-suspect-egress-probe-8.8.8.8",
		"last-nebula-restart",
	} {
		if _, err := os.Stat(filepath.Join(e.state, f)); err != nil {
			t.Fatalf("%s removed by stateExit: %v", f, err)
		}
	}
}

// --- overlay-egress (12) ---

// overlayEnv wires a live nebula overlay + one relay.
func overlayEnv(t *testing.T, extra func(*watchdogconf.Config)) *env {
	wd := &watchdogconf.Config{
		OverlayEgressRelays: []string{"8.8.8.8"},
		OverlayEgressTable:  100,
		OverlayEgressTCP:    map[string]string{"8.8.8.8": "53"},
	}
	if extra != nil {
		extra(wd)
	}
	e := fixture(t, wd)
	e.sd.On("is-enabled nebula@interdc", "enabled\n")
	e.sd.On("is-active nebula@interdc", "active\n")
	e.host.On("rule list", "0:\tfrom all lookup local\n")
	return e
}

// --- nebula-health (13) ---

func nebulaEnv(t *testing.T, mutate func(*watchdogconf.Config)) *env {
	wd := &watchdogconf.Config{
		NebulaNet:            "interdc",
		NebulaDev:            "neb1",
		NebulaPort:           45670,
		NebulaStatsURL:       "http://127.0.0.1:9800/metrics",
		OverlayActive:        "nebula",
		OverlayProbeTargets:  []string{"10.8.0.1", "10.8.0.2"},
		OverlayProbeMarkers:  []string{"10.8.1.1", "10.8.1.2"},
		OverlayProbeCount:    3,
		OverlayProbeWait:     4,
		NebulaDegradedConsec: 2,
	}
	if mutate != nil {
		mutate(wd)
	}
	e := fixture(t, wd)
	e.sd.On("is-enabled nebula@interdc", "enabled\n")
	e.sd.On("is-active nebula@interdc", "active\n")
	// UDP socket bound + tun has an addr + stats ok + all pings ok.
	// 45670 = 0xB266.
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st tx_queue rx_queue\n"+
		"  1: 0100007F:B266 00000000:0000 07 00000000:00000000\n")
	e.host.On("addr show dev neb1", "3: neb1    inet 10.8.0.10/24 scope global neb1\n")
	for _, ip := range []string{"10.8.0.1", "10.8.0.2", "10.8.1.1", "10.8.1.2"} {
		e.pingOK[ip+"|false"] = true
		e.pingRTT[ip+"|false"] = 5
	}
	return e
}

func TestSignalDisabledSkipsCheck(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.cfg.Watchdog.Disabled = map[string]bool{"nebula-health": true}
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st\n") // would fail
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart nebula") {
		t.Fatal("nebula check ran despite WD_SIG disable")
	}
}

// --- Name contract ---

func TestNameIdentifiesNetHealth(t *testing.T) {
	if got := fixture(t, nil).n.Name(); got != "nethealth" {
		t.Fatalf("Name()=%q want nethealth", got)
	}
}

// applyDefaults mirrors the shell-module defaults — a zero Config
// (the "no conf file" node) must land on every documented default
// without any explicit value.
func TestApplyDefaultsZeroConfig(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	if c.Interval != defaultInterval ||
		c.WatchdogStateDir != defaultWatchdogStateDir ||
		c.WatchdogLogFile != defaultWatchdogLogFile ||
		c.HostResolvConf != defaultHostResolvConf ||
		c.HostsFile != defaultHostsFile ||
		c.ProcNetUDP != defaultProcNetUDP ||
		c.ProcNetUDP6 != defaultProcNetUDP6 ||
		c.UptimeFile != defaultUptimeFile ||
		c.ConntrackCountFile != defaultConntrackCountFile ||
		c.ConntrackMaxFile != defaultConntrackMaxFile ||
		c.ConntrackStatFile != defaultConntrackStatFile ||
		c.HostRoot != defaultHostRoot ||
		c.ConsecNeeded != defaultConsecNeeded ||
		c.MinRestart != defaultMinRestart {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Watchdog == nil {
		t.Fatal("nil Watchdog not replaced with an empty config")
	}
	if c.NebulaDirectTCPPorts == nil {
		t.Fatal("nil port list not defaulted")
	}
	if got := c.sysClassNet; got != defaultSysClassNet {
		t.Fatalf("sysClassNet=%q want %q", got, defaultSysClassNet)
	}
	// The transport seams fall back to production defaults, not nil.
	if c.runHostCmd == nil || c.runMountCmd == nil || c.dnsProbe == nil ||
		c.tcpProbe == nil || c.ping == nil || c.probeHTTP == nil {
		t.Fatalf("default transport seam missing: runHostCmd=%v runMountCmd=%v "+
			"dnsProbe=%v tcpProbe=%v ping=%v probeHTTP=%v",
			c.runHostCmd != nil, c.runMountCmd != nil, c.dnsProbe != nil,
			c.tcpProbe != nil, c.ping != nil, c.probeHTTP != nil)
	}
	if c.adjtimexFn == nil {
		t.Fatal("adjtimexFn default missing")
	}
	if c.Clock == nil {
		t.Fatal("Clock default missing")
	}
}

// The default host-exec closures go through one hostexec Runner — on
// HostRoot "/" (agent on the host itself) that is a plain exec of
// the named binary, with stderr folded into the output
// (ExecCombined).
func TestDefaultHostExecSeams(t *testing.T) {
	c := Config{HostRoot: "/"}
	c.applyDefaults()
	ctx := context.Background()
	if _, err := c.runHostCmd(ctx, []string{"true"}); err != nil {
		t.Fatalf("default runHostCmd failed: %v", err)
	}
	if _, err := c.runMountCmd(ctx, []string{"true"}); err != nil {
		t.Fatalf("default runMountCmd failed: %v", err)
	}
	// A failing binary surfaces its output+error through the same
	// seam the trimRunErr diagnostics consume.
	_, err := c.runHostCmd(ctx, []string{"false"})
	if err == nil {
		t.Fatal("default runHostCmd swallowed a non-zero exit")
	}
}

// The default tcpProbe is a plain dial: refused port errors, an open
// loopback listener succeeds (and closes).
func TestDefaultTCPProbe(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	ctx := context.Background()
	if err := c.tcpProbe(ctx, "127.0.0.1", "1", time.Second); err == nil {
		t.Fatal("tcpProbe dialled a closed port successfully")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if err := c.tcpProbe(ctx, "127.0.0.1", port, time.Second); err != nil {
		t.Fatalf("tcpProbe failed against a live listener: %v", err)
	}
}

// The default ping seam composes runHostCmd (captured at
// applyDefaults time) — the marked variant adds the decimal 8192
// fwmark (iputils rejects the hex form) and success parses the min
// RTT out of ping output; no output parses as -1.
func TestDefaultPingSeam(t *testing.T) {
	fake := testutil.NewFakeExec()
	c := Config{}
	c.runHostCmd = fake.Run
	c.applyDefaults()
	ctx := context.Background()
	// Unmatched command → the fake answers success with no output.
	ok, rtt := c.ping(ctx, "10.0.0.1", 3, 4, true)
	if !ok || rtt != -1 {
		t.Fatalf("ping=%v rtt=%v want true/-1 on empty output", ok, rtt)
	}
	joined := fake.Joined()
	if !strings.Contains(joined, "-m 8192") {
		t.Fatalf("marked ping missing the 0x2000 mark: %s", joined)
	}
	// Failing transport → unreachable, no RTT.
	fake.ClearLog()
	fake.FailOn("ping", errCmdFail)
	ok, rtt = c.ping(ctx, "10.0.0.1", 3, 4, false)
	if ok || rtt != 0 {
		t.Fatalf("ping=%v rtt=%v want false/0 on transport failure", ok, rtt)
	}
	if strings.Contains(fake.Joined(), "-m 8192") {
		t.Fatal("unmarked ping carried the fwmark flag")
	}
}

// Registering the same metrics twice on one registry fails the
// second New instead of silently double-counting.
func TestNewRejectsDuplicateMetricRegistration(t *testing.T) {
	root := t.TempDir()
	mk := func() Config {
		state := filepath.Join(root, "wd")
		if err := os.MkdirAll(state, 0o755); err != nil {
			t.Fatal(err)
		}
		return Config{
			Interval:         time.Hour,
			WatchdogStateDir: state,
			WatchdogLogFile:  filepath.Join(root, "wd.log"),
			HostRoot:         "/",
		}
	}
	reg := prometheus.NewRegistry()
	if _, err := New(mk(), reg); err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, err := New(mk(), reg); err == nil {
		t.Fatal("second New registered duplicate metrics without error")
	}
}

// The default dnsProbe is a direct one-nameserver A lookup (dig @ns
// parity): a loopback resolver that refuses connections surfaces as
// an error, never a pinned lie. Loopback-only — no external DNS.
func TestDefaultDNSProbe(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	ip, err := c.dnsProbe(context.Background(), "127.0.0.1", "example.internal")
	if err == nil {
		t.Fatalf("dnsProbe succeeded against a dead loopback resolver: ip=%q", ip)
	}
	if ip != "" {
		t.Fatalf("dnsProbe returned ip=%q with an error", ip)
	}
}

// The default probeHTTP is the shared insecure-TLS GET: a refused
// loopback port is an error.
func TestDefaultProbeHTTP(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	if err := c.probeHTTP(context.Background(),
		"http://127.0.0.1:1/metrics", time.Second); err == nil {
		t.Fatal("probeHTTP succeeded against a refused loopback port")
	}
}

// unitEnabledActive folds a missing systemd client to false —
// callers gate remediation on it and a nil client must read as
// "not up", never panic.
func TestUnitEnabledActiveNilSystemd(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.Systemd = nil
	if e.n.unitEnabledActive(context.Background(), "nebula@interdc") {
		t.Fatal("unitEnabledActive true without a systemd client")
	}
}
