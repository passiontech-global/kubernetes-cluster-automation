package nethealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// can invoke them concurrently (W8).
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
	n.cfg.nowFn = func() time.Time { return e.now }
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

	for _, f := range []string{
		"state-conntrack-pressure",
		"last-suspect-conntrack-pressure",
		"last-suspect-egress-probe-8.8.8.8",
	} {
		if _, err := os.Stat(filepath.Join(e.state, f)); !os.IsNotExist(err) {
			t.Fatalf("%s kept after latch exit", f)
		}
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-nebula-restart")); err != nil {
		t.Fatal("action budget removed by the suspect-budget prune")
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
