package nethealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// env is the fixture: tempdir state/hosts/resolv + canned probes and
// a fake host-command runner + fake systemd.
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
	// mu guards cmds/sdcmds — Cycle (checkNebulaDirectTCP → n.ip)
	// and a spawned routeGuard goroutine can invoke runHost
	// concurrently (W8).
	mu       sync.Mutex
	cmds     [][]string
	cmdReply map[string]string
	cmdFail  map[string]bool
	sdReply  map[string]string
	sdcmds   [][]string
	dnsOK    map[string]string // "ns|name" → ip; absent = fail
	tcpOK    map[string]bool   // "host:port" → reachable
	pingOK   map[string]bool   // "ip|marked" → alive
	pingRTT  map[string]float64
	httpErr  map[string]error
}

// matchReply returns the reply for the LONGEST matching key — a
// generic "rule list" key must not shadow "rule list pref 1500", nor
// "fail2ban-client status" shadow "fail2ban-client status sshd".
func matchReply(m map[string]string, j string) (string, bool) {
	best, bestLen := "", -1
	for k, v := range m {
		if strings.Contains(j, k) && len(k) > bestLen {
			best, bestLen = v, len(k)
		}
	}
	return best, bestLen >= 0
}

func (e *env) runHost(ctx context.Context, argv []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cmds = append(e.cmds, argv)
	j := strings.Join(argv, " ")
	for k := range e.cmdFail {
		if strings.Contains(j, k) {
			return "", errors.New("exit 2")
		}
	}
	if v, ok := matchReply(e.cmdReply, j); ok {
		return v, nil
	}
	return "", nil
}

func (e *env) sdRun(ctx context.Context, argv []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sdcmds = append(e.sdcmds, argv)
	j := strings.Join(argv, " ")
	if v, ok := matchReply(e.sdReply, j); ok {
		return v, nil
	}
	return "", errors.New("no such unit")
}

func (e *env) sdRan(sub string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.sdcmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func (e *env) cmdRan(sub string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.cmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T, wd *watchdogconf.Config) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		now:      time.Now(),
		cmdReply: map[string]string{},
		cmdFail:  map[string]bool{},
		sdReply:  map[string]string{},
		dnsOK:    map[string]string{},
		tcpOK:    map[string]bool{},
		pingOK:   map[string]bool{},
		pingRTT:  map[string]float64{},
		httpErr:  map[string]error{},
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
	writeFile(t, e.uptime, "3600.00 7200.00\n")
	writeFile(t, e.hosts, "127.0.0.1 localhost\n::1 localhost\n")
	// Healthy defaults: empty conntrack table, synchronized clock.
	writeFile(t, e.ctcount, "0\n")
	writeFile(t, e.ctmax, "262144\n")
	if wd == nil {
		wd = &watchdogconf.Config{}
	}
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sdRun})
	n, err := New(Config{
		Enabled:            true,
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
	n.cfg.runHostCmd = e.runHost
	n.cfg.runMountCmd = e.runHost
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

// --- dns-fallback (20) ---

func TestDNSFallbackPinAndRecover(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1", "10.0.0.2"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	latch := "dns-fallback"

	// All NS fail → counter, no pin yet (need 2 cycles).
	e.n.Cycle(context.Background())
	if strings.Contains(readFileT(t, e.hosts), "node-watchdog-dns") {
		t.Fatal("pinned before ConsecNeeded")
	}
	// Cycle 2: still failing → pin last-good/candidates that TCP-answer.
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.2 api.test.internal") {
		t.Fatalf("no pin written:\n%s", hosts)
	}
	if !stateExists(e, latch) {
		t.Fatal("dns-fallback latch missing")
	}
	// DNS recovers → block + pin + latch removed.
	e.dnsOK["10.1.1.1|api.test.internal"] = "10.0.0.1"
	e.n.Cycle(context.Background())
	hosts = readFileT(t, e.hosts)
	if strings.Contains(hosts, "node-watchdog-dns") {
		t.Fatalf("block not removed after recovery:\n%s", hosts)
	}
	if stateExists(e, latch) {
		t.Fatal("latch kept after recovery")
	}
	if files := e.n.pinFiles(); len(files) != 0 {
		t.Fatalf("pin files kept after recovery: %v", files)
	}
	// last-known-good cache kept the resolved IP.
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "dnsfb-lg-api.test.internal")); got != "10.0.0.1" {
		t.Fatalf("last-good=%q want 10.0.0.1", got)
	}
}

func TestDNSFallbackKeepsDeadPinWithoutReplacement(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	// Pre-existing pin; DNS fails; candidate unreachable → keep pin.
	writeFile(t, filepath.Join(e.state, "dnsfb-pin-api.test.internal"),
		"10.0.0.1 api.test.internal\n")
	writeFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.test.internal\n# END node-watchdog-dns\n")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !strings.Contains(readFileT(t, e.hosts), "10.0.0.1 api.test.internal") {
		t.Fatal("dead pin removed — a dead IP beats NXDOMAIN")
	}
	if !stateExists(e, "dns-fallback") {
		t.Fatal("latch missing with active pin")
	}
}

// A `# BEGIN` without `# END` (truncated/corrupted hosts file) must
// not silently eat the lines after the marker: they are kept as
// ordinary content and the rewritten file is well-formed again.
func TestRenderHostsBlockUnterminatedBegin(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")

	if !e.n.renderHostsBlock("10.0.0.2 api.y\n") {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.1 stranded.example") {
		t.Fatalf("tail after unterminated BEGIN dropped:\n%s", hosts)
	}
	if !strings.Contains(hosts, hostsBlockEnd) ||
		!strings.Contains(hosts, "10.0.0.2 api.y") {
		t.Fatalf("new block not written well-formed:\n%s", hosts)
	}
	// The rewrite is convergent: the next render sees a clean file.
	if e.n.renderHostsBlock("10.0.0.2 api.y\n") {
		t.Fatalf("rewrite not idempotent:\n%s", readFileT(t, e.hosts))
	}

	// Removing the block keeps the tail too.
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n10.0.0.1 stranded.example\n")
	if !e.n.renderHostsBlock("") {
		t.Fatal("unterminated block removal not rewritten")
	}
	hosts = readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.1 stranded.example") {
		t.Fatalf("tail dropped on block removal:\n%s", hosts)
	}
	if strings.Contains(hosts, hostsBlockBegin) {
		t.Fatalf("stray BEGIN kept:\n%s", hosts)
	}
}

// A tail line pinning a MANAGED fallback name is residue of an
// earlier managed block — keeping it above the new block would let a
// dead pin shadow the fresh one (first match wins). Foreign names
// still get the rescue.
func TestRenderHostsBlockTailDropsStaleManagedPins(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	writeFile(t, e.hosts, "127.0.0.1 localhost\n"+
		hostsBlockBegin+"\n"+
		"10.0.0.9 api.test.internal\n"+ // stale pin on a managed name
		"10.0.0.7 stranded.example\n") // foreign entry — rescued

	if !e.n.renderHostsBlock("10.0.0.2 api.test.internal\n") {
		t.Fatal("unterminated block not rewritten")
	}
	hosts := readFileT(t, e.hosts)
	if !strings.Contains(hosts, "10.0.0.7 stranded.example") {
		t.Fatalf("foreign tail entry dropped:\n%s", hosts)
	}
	if strings.Contains(hosts, "10.0.0.9 api.test.internal") {
		t.Fatalf("stale managed pin kept in tail — shadows fresh pin:\n%s", hosts)
	}
	if !strings.Contains(hosts,
		hostsBlockBegin+"\n10.0.0.2 api.test.internal\n"+hostsBlockEnd) {
		t.Fatalf("fresh block not written well-formed:\n%s", hosts)
	}
}

// A file-level bind mount (the DaemonSet's /host/etc/hosts mount)
// makes rename(2) return EBUSY — hostutil.WriteFileAtomic must fall
// back to a direct fsync'd write instead of never landing the pin.
func TestWriteFileAtomicBusyFallback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hosts")
	writeFile(t, target, "127.0.0.1 localhost\n")

	old := hostutil.RenameFile
	defer func() { hostutil.RenameFile = old }()
	hostutil.RenameFile = func(_, _ string) error { return unix.EBUSY }

	if err := hostutil.WriteFileAtomic(target, "1.2.3.4 pinned.example\n"); err != nil {
		t.Fatalf("WriteFileAtomic EBUSY fallback failed: %v", err)
	}
	if got := readFileT(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("content after fallback=%q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-hosts")); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind after fallback")
	}

	// A non-fallback rename error propagates and never touches the
	// target — the fallback is EBUSY/EXDEV only.
	hostutil.RenameFile = func(_, _ string) error { return unix.EPERM }
	if err := hostutil.WriteFileAtomic(target, "9.9.9.9 evil\n"); !errors.Is(err, unix.EPERM) {
		t.Fatalf("WriteFileAtomic err=%v want EPERM", err)
	}
	if got := readFileT(t, target); got != "1.2.3.4 pinned.example\n" {
		t.Fatalf("target overwritten on non-fallback rename error:\n%s", got)
	}
}

// The suspectLog dedupe budgets are named last-suspect-<key>; keys
// without a state-* latch (egress-probe-<ip> and friends) had no
// reset path — a latch exit is the incident boundary that now drops
// the whole family, while ordinary last-* action budgets stay.
func TestStateExitDropsSuspectBudgets(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, filepath.Join(e.state, "state-conntrack-pressure"), "1\n")
	writeFile(t, filepath.Join(e.state, "last-suspect-conntrack-pressure"), "1\n")
	writeFile(t, filepath.Join(e.state, "last-suspect-egress-probe-8.8.8.8"), "1\n")
	writeFile(t, filepath.Join(e.state, "last-nebula-restart"), "1\n") // action budget — not a suspect key

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

func TestDNSFallbackEmptyMapCleans(t *testing.T) {
	e := fixture(t, nil) // empty conf
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	writeFile(t, e.hosts, "127.0.0.1 localhost\n# BEGIN node-watchdog-dns\n"+
		"10.0.0.1 api.x\n# END node-watchdog-dns\n")
	writeFile(t, filepath.Join(e.state, "dnsfb-pin-api.x"), "10.0.0.1 api.x\n")
	writeFile(t, filepath.Join(e.state, "state-dns-fallback"), "1\n")
	e.n.Cycle(context.Background())
	if strings.Contains(readFileT(t, e.hosts), "node-watchdog-dns") {
		t.Fatal("block kept with empty map")
	}
	if stateExists(e, "dns-fallback") {
		t.Fatal("latch kept with empty map")
	}
	if files := e.n.pinFiles(); len(files) != 0 {
		t.Fatalf("pins kept with empty map: %v", files)
	}
}

// TestDNSFallbackPrunesFailCounters: a name dropped from
// DNS_FALLBACK_MAP loses its in-memory fail counter alongside the
// pin/counter files — otherwise dnsfails grows with every map edit.
func TestDNSFallbackPrunesFailCounters(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
			{Name: "gone.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	// All lookups fail → both names accumulate fail counters.
	e.n.Cycle(context.Background())
	if len(e.n.dnsfails) != 2 {
		t.Fatalf("dnsfails = %v, want 2 entries", e.n.dnsfails)
	}

	// Drop the second name from the map → its counter is pruned.
	e.n.cfg.Watchdog = &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.1"}},
		},
	}
	e.n.Cycle(context.Background())
	if _, ok := e.n.dnsfails["gone.test.internal"]; ok {
		t.Fatal("dnsfails kept a name removed from DNS_FALLBACK_MAP")
	}
	if _, ok := e.n.dnsfails["api.test.internal"]; !ok {
		t.Fatal("dnsfails lost the still-mapped name")
	}
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// --- coredns-stub (21) ---

func TestCoreDNSStubRestart(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 127.0.0.1\nnameserver 10.1.1.1\n")
	e.sdReply["LoadState --value coredns.service"] = "loaded\n"
	e.sdReply["is-active coredns.service"] = "inactive\n"
	e.n.Cycle(context.Background())
	if !e.sdRan("restart coredns.service") {
		t.Fatalf("coredns not restarted, cmds=%v", e.sdcmds)
	}
	// Cooldown: second cycle does not re-restart.
	e.sdcmds = nil
	e.n.Cycle(context.Background())
	if e.sdRan("restart coredns.service") {
		t.Fatal("restart inside 5m cooldown")
	}
}

func TestCoreDNSStubNoLoopbackNoRestart(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.sdReply["LoadState --value coredns.service"] = "loaded\n"
	e.sdReply["is-active coredns.service"] = "inactive\n"
	e.n.Cycle(context.Background())
	if e.sdRan("coredns") {
		t.Fatal("restart without loopback resolv.conf")
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
	e.sdReply["is-enabled nebula@interdc"] = "enabled\n"
	e.sdReply["is-active nebula@interdc"] = "active\n"
	e.cmdReply["rule list"] = "0:\tfrom all lookup local\n"
	return e
}

func TestEgressUnderlayDiesRelaysImmediately(t *testing.T) {
	e := overlayEnv(t, nil)
	// fwmark rule present, no pref-1500 rules.
	e.cmdReply["rule list pref 1500"] = ""
	// Marked ping fails; TCP fallback fails too → underlay dead.
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("relay rule not added, cmds=%v", e.cmds)
	}
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	// Relay target itself unreachable through tunnel → suspect log.
	e.pingOK["8.8.8.8|false"] = false
	if !strings.Contains(logLines(t, e), "overlay relay table 100") {
		t.Fatalf("missing ACTION log:\n%s", logLines(t, e))
	}
}

func TestEgressRecoveryNeedsTwoFreshProbes(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = "1500:\tfrom all to 8.8.8.8 lookup 100\n"
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true // underlay back
	// Cycle 1: probe=direct, ctr 1 < 2 → stays relay.
	e.n.Cycle(context.Background())
	if e.cmdRan("rule del pref 1500 to 8.8.8.8") {
		t.Fatal("rule removed before hysteresis")
	}
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule del pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("direct rule not restored, cmds=%v", e.cmds)
	}
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "direct" {
		t.Fatalf("committed=%q want direct", got)
	}
}

func TestEgressDriftHeal(t *testing.T) {
	e := overlayEnv(t, nil)
	// Committed relay but live rule missing → re-add immediately.
	e.cmdReply["rule list pref 1500"] = ""
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = false
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatal("committed relay state not healed into live rules")
	}
	if !strings.Contains(logLines(t, e), "heal egress") {
		t.Fatalf("missing heal log:\n%s", logLines(t, e))
	}
}

func TestEgressICMPBlockedTCPAliveIsDirect(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = ""
	e.pingOK["8.8.8.8|true"] = false // ICMP filtered
	e.tcpOK["8.8.8.8:53"] = true     // but TCP answers
	e.n.Cycle(context.Background())
	if e.cmdRan("rule add pref 1500 to 8.8.8.8") {
		t.Fatal("relay rule added while TCP alive (ICMP-block false positive)")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-icmpblk-8.8.8.8")); err != nil {
		t.Fatal("icmpblk flag not written")
	}
}

func TestEgressNoOverlayCleanup(t *testing.T) {
	e := overlayEnv(t, nil)
	// Nebula down → overlayUp false → full cleanup.
	e.sdReply = map[string]string{}
	e.cmdReply["rule list pref 1500"] = "1500:\tfrom all to 8.8.8.8 lookup 100\n"
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule del pref 1390 fwmark 0x2000") {
		t.Fatal("fwmark probe rule not removed")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-state-8.8.8.8")); !os.IsNotExist(err) {
		t.Fatal("egress state kept with overlay down")
	}
}

func TestEgressRemovedRelayCleaned(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = "1500:\tfrom all to 9.9.9.9 lookup 100\n"
	writeFile(t, filepath.Join(e.state, "egress-state-9.9.9.9"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule del pref 1500 to 9.9.9.9/32 lookup 100") {
		t.Fatal("stale relay rule not removed")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-state-9.9.9.9")); !os.IsNotExist(err) {
		t.Fatal("stale relay state kept")
	}
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
	e.sdReply["is-enabled nebula@interdc"] = "enabled\n"
	e.sdReply["is-active nebula@interdc"] = "active\n"
	// UDP socket bound + tun has an addr + stats ok + all pings ok.
	// 45670 = 0xB266.
	writeFile(t, e.procudp, "  sl  local_address rem_address   st tx_queue rx_queue\n"+
		"  1: 0100007F:B266 00000000:0000 07 00000000:00000000\n")
	e.cmdReply["addr show dev neb1"] = "3: neb1    inet 10.8.0.10/24 scope global neb1\n"
	for _, ip := range []string{"10.8.0.1", "10.8.0.2", "10.8.1.1", "10.8.1.2"} {
		e.pingOK[ip+"|false"] = true
		e.pingRTT[ip+"|false"] = 5
	}
	return e
}

func TestNebulaHealthy(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("false latch on healthy nebula")
	}
	if e.sdRan("restart nebula") {
		t.Fatal("restart on healthy nebula")
	}
}

func TestNebulaNoSocketRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	writeFile(t, e.procudp, "  sl  local_address rem_address   st\n"+
		"  1: 0100007F:0050 00000000:0000 07\n") // no :B9B6 (45670)
	e.n.Cycle(context.Background())
	if e.sdRan("restart nebula") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.n.Cycle(context.Background())
	if !e.sdRan("restart nebula@interdc") {
		t.Fatalf("nebula not restarted, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-nebula-restart")); err != nil {
		t.Fatal("budget not spent")
	}
}

func TestNebulaDataplaneDeadIsolates(t *testing.T) {
	e := nebulaEnv(t, nil)
	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		e.pingOK[ip+"|false"] = false // all pub targets dead
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch missing on dataplane dead")
	}
	e.n.Cycle(context.Background())
	if !e.sdRan("restart nebula@interdc") {
		t.Fatal("no restart on persistent dataplane dead")
	}
}

func TestNebulaDegradedLatch(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeMarkers = []string{"10.8.1.1", "10.8.1.2", "10.8.1.3"}
	})
	// 2 of 3 markers dead but one alive → degraded, not isolated
	// (isolated needs ALL of a group dead).
	e.pingOK["10.8.1.3|false"] = true
	e.pingOK["10.8.1.1|false"] = false
	e.pingOK["10.8.1.2|false"] = false
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch before DEGRADED_CONSEC")
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing after 2 runs")
	}
	if stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch on partial loss")
	}
	if e.sdRan("restart nebula") {
		t.Fatal("degraded is not a restart reason")
	}
}

func TestNebulaNotActiveCleansStates(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sdReply["is-active nebula@interdc"] = "inactive\n"
	writeFile(t, filepath.Join(e.state, "state-nebula-isolated"), "1\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") {
		t.Fatal("nebula state kept while inactive")
	}
}

func TestNebulaOverlayTincSkipsDataplane(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayActive = "tinc"
	})
	// All probes dead — but overlay=tinc → no dataplane probing, no
	// dataplane states.
	for k := range e.pingOK {
		e.pingOK[k] = false
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("dataplane latch while tinc is active overlay")
	}
	if e.sdRan("restart nebula") {
		t.Fatal("restart while only dataplane evidence (asymmetric probe)")
	}
}

func TestNebulaSlowpathAndSiteedge(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlaySlowpathMarkers = []string{"10.8.1.1"}
		wd.OverlaySiteMarkers = []string{"10.9.0.1"}
	})
	e.pingOK["10.9.0.1|false"] = true
	e.pingRTT["10.8.1.1|false"] = 150 // > slowpath 100ms
	e.pingRTT["10.9.0.1|false"] = 80  // > siteedge 50ms
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-slowpath") {
		t.Fatal("slowpath latch missing")
	}
	if !stateExists(e, "nebula-siteedge") {
		t.Fatal("siteedge latch missing")
	}
}

// --- fail2ban (50) ---

func TestFail2banDownAndBans(t *testing.T) {
	e := fixture(t, nil)
	e.sdReply["LoadState --value fail2ban.service"] = "loaded\n"
	e.sdReply["is-active fail2ban.service"] = "inactive\n"
	e.cmdReply["fail2ban-client status"] =
		"Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"
	e.cmdReply["fail2ban-client status sshd"] = "Currently banned:\t7\n"
	e.cmdReply["fail2ban-client status recidive"] = "Currently banned:\t1\n"
	e.n.Cycle(context.Background())
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban-down latch missing")
	}
	// A stopped jail protects nothing — the guard restarts the unit.
	if !e.sdRan("restart fail2ban.service") {
		t.Fatalf("fail2ban not restarted, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-fail2ban-restart")); err != nil {
		t.Fatal("restart budget file missing")
	}
	got := hostutil.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned"))
	if !strings.Contains(got, "sshd=7") || !strings.Contains(got, "recidive=1") {
		t.Fatalf("banned file=%q", got)
	}
}

func TestFail2banNoUnitSkips(t *testing.T) {
	e := fixture(t, nil)
	e.n.Cycle(context.Background())
	if e.sdRan("restart") || stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban ran without unit")
	}
}

func TestEgressHealedRelayDropsRuleForTCPProbe(t *testing.T) {
	// Committed relay + missing live rule → heal re-adds it, then the
	// TCP fallback must still drop the rule for the probe window
	// (pre-heal snapshot would have said hadRule=false → connect
	// through the overlay → false "direct" → relay/direct flap).
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = ""
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = true // underlay actually alive via TCP
	e.n.Cycle(context.Background())
	if !e.cmdRan("rule del pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("rule not dropped for TCP probe window: %v", e.cmds)
	}
	if !e.cmdRan("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("rule not restored after TCP probe: %v", e.cmds)
	}
}

// When the probe-window rule del fails the TCP fallback is skipped —
// committing relay then only restates live; the log must not claim
// "(direct failed)" underlay evidence the skipped probe never made.
func TestEgressUnprobeableWindowCommitsToLive(t *testing.T) {
	e := overlayEnv(t, nil)
	// Committed direct but a live relay rule (drift); the heal del
	// AND the probe-window del both fail → no probe runs.
	e.cmdReply["rule list pref 1500"] = "1500:\tfrom all to 8.8.8.8 lookup 100\n"
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "direct\n")
	e.cmdFail["rule del"] = true
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = true // would prove direct — never consulted

	e.n.Cycle(context.Background())

	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay (committed to live)", got)
	}
	log := logLines(t, e)
	if !strings.Contains(log, "unprobeable window — committed to live") {
		t.Fatalf("missing unprobeable-window commit log:\n%s", log)
	}
	if strings.Contains(log, "direct failed") {
		t.Fatalf("misleading '(direct failed)' logged for an unrun probe:\n%s", log)
	}
}

func TestDNSFallbackEmptyMapRemovesAllDNSFBFiles(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		writeFile(t, filepath.Join(e.state, f), "x\n")
	}
	e.n.Cycle(context.Background())
	for _, f := range []string{"dnsfb-pin-api.x", "dnsfb-lg-api.x", "dnsfb-ctr-api.x"} {
		if _, err := os.Stat(filepath.Join(e.state, f)); !os.IsNotExist(err) {
			t.Fatalf("%s kept with empty map", f)
		}
	}
}

func TestSignalDisabledSkipsCheck(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.cfg.Watchdog.Disabled = map[string]bool{"nebula-health": true}
	writeFile(t, e.procudp, "  sl  local_address rem_address   st\n") // would fail
	e.n.Cycle(context.Background())
	if e.sdRan("restart nebula") {
		t.Fatal("nebula check ran despite WD_SIG disable")
	}
}

// --- clock-sync (H1) ---

func TestClockSyncLatchAndRateLimitedRestart(t *testing.T) {
	e := fixture(t, nil)
	e.timex.Status = unix.STA_UNSYNC
	e.sdReply["is-enabled systemd-timesyncd.service"] = "enabled\n"
	e.sdReply["is-active systemd-timesyncd.service"] = "active\n"
	e.sdReply["restart systemd-timesyncd.service"] = ""

	// Cycle 1: first failure — no latch, no restart yet.
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch before ConsecNeeded")
	}
	if e.sdRan("restart") {
		t.Fatal("ntp restart before ConsecNeeded")
	}

	// Cycle 2: second consecutive failure → latch + restart.
	e.n.Cycle(context.Background())
	if !stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch missing after ConsecNeeded")
	}
	if !e.sdRan("restart systemd-timesyncd.service") {
		t.Fatalf("timesyncd not restarted, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-ntp-restart")); err != nil {
		t.Fatal("last-ntp-restart budget not spent")
	}

	// Cycle 3 (still failing): the 30m budget blocks a re-restart.
	e.sdcmds = nil
	e.n.Cycle(context.Background())
	if e.sdRan("restart systemd-timesyncd.service") {
		t.Fatal("restart inside last-ntp-restart cooldown")
	}

	// Budget expired → next failing cycle restarts again.
	e.now = e.now.Add(31 * time.Minute)
	e.n.Cycle(context.Background())
	if !e.sdRan("restart systemd-timesyncd.service") {
		t.Fatal("no restart after last-ntp-restart window elapsed")
	}

	// Clock syncs again → latch clears.
	e.timex.Status = 0
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch kept after resync")
	}
}

func TestClockSyncEsterrorTooLarge(t *testing.T) {
	e := fixture(t, nil)
	// No STA_UNSYNC — but esterror above 500ms is unhealthy on its own.
	e.timex.Esterror = 600_000
	e.sdReply["is-enabled chronyd.service"] = "enabled\n"
	e.sdReply["is-active chronyd.service"] = "active\n"
	e.sdReply["restart chronyd.service"] = ""
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch missing on esterror > 500ms")
	}
	// timesyncd absent → falls through to the first enabled/active unit.
	if !e.sdRan("restart chronyd.service") {
		t.Fatalf("chronyd not restarted, cmds=%v", e.sdcmds)
	}
}

// On a chrony node, timesyncd's unit FILE exists (it ships with
// systemd) but the daemon is disabled — restarting it would start a
// second clock-discipline daemon fighting chrony over adjtimex. The
// picker must prefer the enabled/active unit, not UnitExists order.
func TestClockSyncPrefersEnabledDaemonOverInstalled(t *testing.T) {
	e := fixture(t, nil)
	e.timex.Status = unix.STA_UNSYNC
	// timesyncd installed but disabled (is-enabled → error), chrony
	// is the live daemon.
	e.sdReply["is-enabled chrony.service"] = "enabled\n"
	e.sdReply["is-active chrony.service"] = "active\n"
	e.sdReply["LoadState --value systemd-timesyncd.service"] = "loaded\n"
	e.sdReply["restart chrony.service"] = ""
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if e.sdRan("restart systemd-timesyncd.service") {
		t.Fatal("disabled timesyncd restarted on a chrony node — " +
			"would start a second sync daemon")
	}
	if !e.sdRan("restart chrony.service") {
		t.Fatalf("chrony not restarted, cmds=%v", e.sdcmds)
	}
}

func TestClockSyncAdjtimexErrorAborts(t *testing.T) {
	e := fixture(t, nil)
	e.adjErr = errors.New("operation not permitted")
	e.sdReply["is-enabled systemd-timesyncd.service"] = "enabled\n"
	e.sdReply["is-active systemd-timesyncd.service"] = "active\n"
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("adjtimex error must not false-latch clock-unsync")
	}
	if e.sdRan("restart") {
		t.Fatal("ntp restart on adjtimex read failure")
	}
}

// --- conntrack-guard (H2) ---

func TestConntrackPressureHysteresis(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.ctmax, "1000\n")

	// 0.85 — between the bands: no latch without prior state.
	writeFile(t, e.ctcount, "850\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch below enter ratio")
	}
	// 0.95 > 0.90 → latch arms.
	writeFile(t, e.ctcount, "950\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "conntrack-pressure") {
		t.Fatal("latch missing above enter ratio")
	}
	// 0.85 — inside the hysteresis band: latch holds.
	writeFile(t, e.ctcount, "850\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "conntrack-pressure") {
		t.Fatal("latch dropped inside hysteresis band")
	}
	// 0.75 < 0.80 → latch clears.
	writeFile(t, e.ctcount, "750\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch kept below exit ratio")
	}
}

func TestConntrackMissingFilesDropsLatch(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, filepath.Join(e.state, "state-conntrack-pressure"), "1\n")
	// Module unloaded → both /proc entries gone.
	if err := os.Remove(e.ctcount); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.ctmax); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("stale conntrack-pressure latch kept with no table")
	}
}

// --- conntrack udp/53 flush triggers ---

func TestConntrackFlushOnDNSFallbackPin(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background()) // second fail → pin + block update
	if !strings.Contains(readFileT(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("dns-fallback pin missing")
	}
	if !e.cmdRan("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.cmds)
	}
}

func TestConntrackFlushMissingBinaryOnlyLogs(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true
	e.cmdFail["conntrack"] = true // binary absent
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	// The pin still lands — a missing conntrack binary must never
	// fail the cycle.
	if !strings.Contains(readFileT(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("dns-fallback pin missing after conntrack flush failure")
	}
	if !strings.Contains(logLines(t, e), "flush skipped") {
		t.Fatalf("missing flush-skip log:\n%s", logLines(t, e))
	}
}

func TestConntrackFlushOnCoreDNSRestart(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 127.0.0.1\nnameserver 10.1.1.1\n")
	e.sdReply["LoadState --value coredns.service"] = "loaded\n"
	e.sdReply["is-active coredns.service"] = "inactive\n"
	e.sdReply["restart coredns.service"] = ""
	e.n.Cycle(context.Background())
	if !e.sdRan("restart coredns.service") {
		t.Fatal("coredns stub not restarted")
	}
	if !e.cmdRan("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.cmds)
	}
}

func TestConntrackFlushOnNebulaRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sdReply["restart nebula@interdc"] = ""
	writeFile(t, e.procudp, "  sl  local_address rem_address   st\n"+
		"  1: 0100007F:0050 00000000:0000 07\n") // :B266 (45670) gone
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !e.sdRan("restart nebula@interdc") {
		t.Fatal("nebula not restarted")
	}
	if !e.cmdRan("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.cmds)
	}
}

// --- B3: per-peer nebula udp/<port> conntrack flush ---

// countCmds returns how many recorded host commands contain sub.
func countCmds(e *env, sub string) int {
	n := 0
	for _, c := range e.cmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

func TestNebulaIsolatedFlushesPeerConntrack(t *testing.T) {
	e := nebulaEnv(t, nil)
	// Every underlay probe target dead → dataplane isolated. Only the
	// peer underlay IPs (OVERLAY_PROBE_TARGETS) are flushed — marker
	// IPs are overlay addresses conntrack never records.
	for _, ip := range []string{"10.8.0.1", "10.8.0.2", "10.8.1.1", "10.8.1.2"} {
		e.pingOK[ip+"|false"] = false
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch missing on dataplane dead")
	}
	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		if !e.cmdRan("conntrack -D -p udp --dport 45670 -d " + ip) {
			t.Fatalf("no per-peer conntrack flush for %s, cmds=%v", ip, e.cmds)
		}
	}
	if e.cmdRan("-d 10.8.1.1") || e.cmdRan("-d 10.8.1.2") {
		t.Fatalf("marker (overlay) IPs flushed — only underlay peers allowed, cmds=%v", e.cmds)
	}
	// Edge-only: a second cycle still isolated must NOT re-flush.
	e.cmds = nil
	e.n.Cycle(context.Background())
	if got := countCmds(e, "conntrack -D -p udp --dport 45670 -d"); got != 0 {
		t.Fatalf("peer flush re-ran while already isolated (%d flushes), cmds=%v", got, e.cmds)
	}
}

func TestEgressSwitchFlushesPeerConntrack(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = ""
	// Underlay dead → committed state flips direct -> relay; the
	// peer's udp/<nebula-port> conntrack gets flushed.
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	if !e.cmdRan("conntrack -D -p udp --dport 45670 -d 8.8.8.8") {
		t.Fatalf("no per-peer conntrack flush on egress switch, cmds=%v", e.cmds)
	}
}

func TestEgressRecoveryFlushesPeerConntrack(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = "1500:\tfrom all to 8.8.8.8 lookup 100\n"
	writeFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true // underlay back
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background()) // 2nd fresh probe → flip to direct
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "direct" {
		t.Fatalf("committed=%q want direct", got)
	}
	if !e.cmdRan("conntrack -D -p udp --dport 45670 -d 8.8.8.8") {
		t.Fatalf("no per-peer conntrack flush on egress recovery, cmds=%v", e.cmds)
	}
}

func TestPeerConntrackFlushHonoursNebulaPort(t *testing.T) {
	e := overlayEnv(t, func(wd *watchdogconf.Config) {
		wd.NebulaPort = 45671
	})
	e.cmdReply["rule list pref 1500"] = ""
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if !e.cmdRan("conntrack -D -p udp --dport 45671 -d 8.8.8.8") {
		t.Fatalf("flush used wrong port, cmds=%v", e.cmds)
	}
}

func TestPeerConntrackFlushBestEffort(t *testing.T) {
	e := overlayEnv(t, nil)
	e.cmdReply["rule list pref 1500"] = ""
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.cmdFail["conntrack"] = true // binary absent → skip, never fail
	e.n.Cycle(context.Background())
	// The relay commit still lands — a missing conntrack binary must
	// never block the path switch.
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	if !strings.Contains(logLines(t, e), "flush 8.8.8.8 skipped") {
		t.Fatalf("missing flush-skip log:\n%s", logLines(t, e))
	}
}
