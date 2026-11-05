// Package nethealth ports the node-watchdog network/shared modules
// that run on BOTH worker and hub (non-agent) nodes — they depend on
// host files, host commands and the parsed node-watchdog.conf, never
// on the kube API:
//
//   - 20-dns-fallback.sh    — sig10: every nameserver in host
//     resolv.conf dead for CONSEC_NEEDED cycles → pin
//     DNS_FALLBACK_MAP names to reachable IPs in the managed
//     `# BEGIN node-watchdog-dns` block of host /etc/hosts; remove it
//     when DNS recovers.
//   - 21-coredns-stub.sh    — sig11: resolv.conf points at 127.0.0.1
//     but the coredns stub unit is down → restart it (the port adds a
//     5m cooldown — the shell had none).
//   - 12-overlay-egress.sh  — sig4: conditional egress relays. An
//     off-mesh IP routes via the overlay only while the underlay path
//     is dead: probe it under a fwmark that pins the main table, swap
//     `ip rule pref 1500 to <ip>/32 lookup <table>` in/out. Committed
//     state lives in egress-state-<ip> files (drift-healed against
//     the live rules every cycle).
//   - 13-nebula-health.sh   — nebula@NEBULA_NET health: UDP socket
//     bound, neb1 has an IPv4 addr, stats endpoint answers, and —
//     only while nebula is the ACTIVE overlay — dataplane ping
//     probes over OVERLAY_PROBE_TARGETS/MARKERS/SITE_MARKERS drive
//     the nebula-isolated/degraded/slowpath/siteedge latches and the
//     rate-limited nebula restart.
//   - 50-fail2ban.sh        — unit installed but service down →
//     state-fail2ban-down; banned counts per jail are written to
//     fail2ban-banned for hostmetrics (node_fail2ban_banned_ips).
//
// Agent-native additions (no shell-module counterpart):
//
//   - clock-sync (H1)       — kernel clock discipline via adjtimex:
//     STA_UNSYNC or esterror > 500ms for ConsecNeeded cycles →
//     clock-unsync latch + a rate-limited timesyncd/chrony restart.
//   - conntrack-guard (H2)  — nf_conntrack table pressure latch
//     (enter >0.90 used, clear <0.80) plus a best-effort stale
//     udp/53 conntrack flush after every DNS-path transition
//     (dns-fallback pin write, coredns-stub/nebula restart).
//
// Host commands (ip/ping/fail2ban-client) run through one seam —
// nsenter-wrapped into the host net namespace when containerized,
// plain exec on the host — and are fully fakeable in tests. DNS and
// TCP probes are Go-native and injectable.
package nethealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// Defaults mirror the shell modules + DaemonSet host mounts.
const (
	defaultInterval         = 2 * time.Minute
	minUptimeSeconds        = 1200 // WD_REQUIRES: uptime for 20/21
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile  = "/host/var/log/node-watchdog.log"
	defaultHostResolvConf   = "/host/etc/resolv.conf"
	defaultHostsFile        = "/host/etc/hosts"
	defaultProcNetUDP       = "/proc/1/net/udp"
	defaultProcNetUDP6      = "/proc/1/net/udp6"
	defaultUptimeFile       = "/proc/uptime"
	defaultHostRoot         = "/host"
	defaultSysClassNet      = "/sys/class/net"
	defaultConsecNeeded     = 2
	defaultMinRestart       = 30 * time.Minute
	corednsRestartInterval  = 5 * time.Minute
	ntpRestartInterval      = 30 * time.Minute
	purgeBudget             = time.Hour // shell last-purge-* rate window
	// suspectLogCadence is the re-reminder interval suspectLog
	// applies to suspect/hold lines whose condition persists:
	// STATE-ENTER announces the transition and the raw line then
	// repeats at most this often — a held condition must not re-log
	// every cycle for weeks (controllerhygiene's suspectLog parity).
	suspectLogCadence = time.Hour

	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"

	// clockMaxEsterrorUS: an adjtimex estimated error above this
	// (microseconds, 500ms) counts the clock as unsynchronized even
	// while the kernel has not set STA_UNSYNC — a drifting clock
	// breaks TLS/cert checks long before the discipline gives up.
	clockMaxEsterrorUS = 500_000
	// Conntrack pressure hysteresis: the latch arms above 0.90 of
	// the table used and only clears below 0.80 — a hovering
	// counter must not flap the state file every cycle.
	conntrackEnterRatio = 0.90
	conntrackExitRatio  = 0.80
)

// Check names — prometheus `check` label + log context.
const (
	checkDNSFB   = "dns-fallback"
	checkCoreDNS = "coredns-stub"
	checkEgress  = "overlay-egress"
	checkNebula  = "nebula-health"
	checkF2B     = "fail2ban"
	checkClock   = "clock-sync"
	checkCT      = "conntrack-guard"
	checkNebTCP  = "nebula-direct-tcp"
)

// defaultNebulaDirectTCPPorts is the pref-1499 Direct-Underlay TCP
// bypass set — hostconfig's nebula_direct_tcp_ports var rendered
// into /etc/nebula/<net>/nebula-up.sh + the T5b ip-rule converge;
// the guard re-adds a rule the kernel dropped.
var defaultNebulaDirectTCPPorts = []int{22, 6443, 8132, 9443, 39901}

const (
	f2bRestartInterval = 30 * time.Minute
	// fileLastRun is the per-cycle liveness stamp (BUG-H1).
	fileLastRun = "last-run"
)

const hostsBlockBegin = "# BEGIN node-watchdog-dns"
const hostsBlockEnd = "# END node-watchdog-dns"

// fileSuspectLog prefixes the suspectLog dedupe budgets:
// last-suspect-<key> epoch files spent at most once per
// suspectLogCadence — the same rateOK/last-* convention as the
// action budgets, applied to log noise.
const fileSuspectLog = "last-suspect-"

// Config carries the nethealth knobs — all test-injectable. Per-node
// values come from Watchdog (the parsed node-watchdog.conf); nil →
// empty config (every check idles on defaults like the shell did on
// nodes without a conf file).
type Config struct {
	Enabled            bool          // false → Run idles until ctx done
	Interval           time.Duration // check cadence
	WatchdogStateDir   string        // state-*/egress-*/dnsfb-* files
	WatchdogLogFile    string        // appended watchdog log (NPD filelog)
	HostResolvConf     string        // host resolv.conf (DNS probe source)
	HostsFile          string        // host /etc/hosts (managed block)
	ProcNetUDP         string        // host /proc/1/net/udp (socket check)
	ProcNetUDP6        string        // host /proc/1/net/udp6
	UptimeFile         string        // host /proc/uptime (20/21 gate)
	ConntrackCountFile string        // nf_conntrack_count (entries used)
	ConntrackMaxFile   string        // nf_conntrack_max (table size)
	HostRoot           string        // "/" = already on host (no nsenter)
	Watchdog           *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf file every Cycle so
	// hostconfig rewrites (OVERLAY_*, DNS_FALLBACK_MAP, WD_SIG_*
	// kill switches) apply live instead of only at agent start.
	WatchdogSrc  *watchdogconf.Reloader
	Systemd      *systemd.Client // nil → systemd checks degrade keep-only
	ConsecNeeded int
	MinRestart   time.Duration
	// NebulaDirectTCPPorts is the nebula_direct_tcp_ports list the
	// pref-1499 route guard enforces — TCP dport on these ports
	// bypasses the overlay (direct underlay). Nil → the default
	// [22 6443 8132 9443 39901].
	NebulaDirectTCPPorts []int

	// Seams — nil gets production defaults.
	nowFn func() time.Time
	// runHostCmd executes a host binary (ip, ping): nsenter -t 1 -n --
	// <argv> when HostRoot != "/", plain exec on the host itself.
	// Netns only — the binaries are shipped in the container image.
	runHostCmd func(ctx context.Context, argv []string) (string, error)
	// runMountCmd is runHostCmd with -m (host mount ns): needed for
	// binaries+state that only exist on the host, e.g. fail2ban-client
	// talking to /run/fail2ban/fail2ban.sock.
	runMountCmd func(ctx context.Context, argv []string) (string, error)
	// dnsProbe resolves name via ONE nameserver (dig @ns A +short
	// parity) and returns the first IPv4 — direct query, never NSS
	// (the managed /etc/hosts pin would shadow it).
	dnsProbe func(ctx context.Context, nameserver, name string) (string, error)
	// tcpProbe is tcp_ok host port timeout parity.
	tcpProbe func(ctx context.Context, host, port string, timeout time.Duration) error
	// ping probes one IP: marked=true → SO_MARK 0x2000 underlay pin
	// (ping -m 8192); returns reachability + min RTT ms.
	ping func(ctx context.Context, ip string, count, waitSec int, marked bool) (bool, float64)
	// probeHTTP fetches url, nil on any 2xx — used for nebula stats.
	probeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// routeDebounce overrides the route guard's netlink-burst
	// debounce window (default 200ms; tests shrink it).
	routeDebounce time.Duration
	// routeMinRestore overrides the minimum interval between
	// route-guard restores (default 2s; tests shrink it) — the
	// exec-storm cap for sustained DEL-event floods.
	routeMinRestore time.Duration
	// openRouteSocket overrides the route guard's NETLINK_ROUTE
	// socket factory — default binds RTMGRP_IPV4_ROUTE|RTMGRP_IPV4_RULE
	// in the host netns: directly when the pod netns IS the host's
	// (hostNetwork, same inode as /proc/1/ns/net), else setns into
	// pid-1's netns (hostPID — no /host/proc mount needed).
	openRouteSocket func() (int, error)
	// sysClassNet is the sysfs net-device dir the route guard
	// resolves the nebula dev's ifindex from — the netns the bound
	// socket watches under hostNetwork (same convention as
	// hostmetrics' SysClassNet; tests point it at a fixture).
	sysClassNet string
	// adjtimexFn reads the kernel clock discipline — a modes==0
	// (read-only) adjtimex(2) needs no CAP_SYS_TIME. Tests inject.
	adjtimexFn func(buf *unix.Timex) (int, error)
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.HostResolvConf == "" {
		c.HostResolvConf = defaultHostResolvConf
	}
	if c.HostsFile == "" {
		c.HostsFile = defaultHostsFile
	}
	if c.ProcNetUDP == "" {
		c.ProcNetUDP = defaultProcNetUDP
	}
	if c.ProcNetUDP6 == "" {
		c.ProcNetUDP6 = defaultProcNetUDP6
	}
	if c.UptimeFile == "" {
		c.UptimeFile = defaultUptimeFile
	}
	if c.ConntrackCountFile == "" {
		c.ConntrackCountFile = defaultConntrackCountFile
	}
	if c.ConntrackMaxFile == "" {
		c.ConntrackMaxFile = defaultConntrackMaxFile
	}
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.Watchdog == nil {
		c.Watchdog = &watchdogconf.Config{}
	}
	c.Watchdog.Normalize()
	if c.ConsecNeeded <= 0 {
		c.ConsecNeeded = defaultConsecNeeded
	}
	if c.MinRestart <= 0 {
		c.MinRestart = defaultMinRestart
	}
	if c.NebulaDirectTCPPorts == nil {
		c.NebulaDirectTCPPorts = defaultNebulaDirectTCPPorts
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
	}
	if c.runHostCmd == nil {
		root := c.HostRoot
		c.runHostCmd = func(ctx context.Context, argv []string) (string, error) {
			if root != "/" {
				argv = append([]string{"nsenter", "-t", "1", "-n", "--"}, argv...)
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(cctx, argv[0], argv[1:]...).CombinedOutput()
			return string(out), err
		}
	}
	if c.runMountCmd == nil {
		root := c.HostRoot
		c.runMountCmd = func(ctx context.Context, argv []string) (string, error) {
			if root != "/" {
				argv = append([]string{"nsenter", "-t", "1", "-m", "-n", "--"}, argv...)
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(cctx, argv[0], argv[1:]...).CombinedOutput()
			return string(out), err
		}
	}
	if c.dnsProbe == nil {
		c.dnsProbe = func(ctx context.Context, nameserver, name string) (string, error) {
			dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(dctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(dctx, "udp", net.JoinHostPort(nameserver, "53"))
				},
			}
			ips, err := r.LookupIP(dctx, "ip4", name)
			if err != nil || len(ips) == 0 {
				if err == nil {
					err = fmt.Errorf("no A records")
				}
				return "", err
			}
			return ips[0].String(), nil
		}
	}
	if c.tcpProbe == nil {
		c.tcpProbe = func(ctx context.Context, host, port string, timeout time.Duration) error {
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			d := net.Dialer{}
			conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
			if err != nil {
				return err
			}
			return conn.Close()
		}
	}
	if c.ping == nil {
		run := c.runHostCmd
		c.ping = func(ctx context.Context, ip string, count, waitSec int, marked bool) (bool, float64) {
			args := []string{"ping"}
			if marked {
				// -m takes DECIMAL only — 8192 = 0x2000 (iputils
				// rejects the hex form, incident note in the shell).
				args = append(args, "-m", "8192")
			}
			args = append(args, fmt.Sprintf("-c%d", count),
				fmt.Sprintf("-W%d", waitSec), ip)
			out, err := run(ctx, args)
			if err != nil {
				return false, 0
			}
			return true, minRTT(out)
		}
	}
	if c.probeHTTP == nil {
		c.probeHTTP = func(ctx context.Context, url string, timeout time.Duration) error {
			return probeHTTPGet(ctx, url, timeout)
		}
	}
	if c.sysClassNet == "" {
		c.sysClassNet = defaultSysClassNet
	}
	if c.adjtimexFn == nil {
		c.adjtimexFn = unix.Adjtimex
	}
}

// NetHealth runs the network checks on one ticker.
type NetHealth struct {
	cfg Config

	dnsfails     map[string]int // per DNS_FALLBACK_MAP name
	nebulaFails  int            // socket/tun/stats fails
	nebulaDpFail int            // dataplane-dead fails
	nebulaDeg    int            // dataplane-degraded runs
	pmtuFails    int            // consecutive DF-probe failures (W9-NM1)
	clockFails   int            // consecutive unsynced adjtimex reads
	egressCtr    map[string]int // per relay probe!=committed counter

	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action

	// routeGuardRunning keeps the route guard single-flight while
	// still allowing a respawn: set when the goroutine spawns,
	// cleared when it exits (clean cancel, read error unwind, or a
	// recovered panic). The old sync.Once made ANY guard death
	// permanent — a panic left route events unmonitored forever.
	// routeGuardLastExit adds a small respawn backoff so a
	// crash-looping guard can't spawn-storm.
	routeGuardRunning  atomic.Bool
	routeGuardLastExit atomic.Int64 // unixnano of last guard exit
}

// New returns a NetHealth and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*NetHealth, error) {
	cfg.applyDefaults()
	n := &NetHealth{
		cfg:       cfg,
		dnsfails:  map[string]int{},
		egressCtr: map[string]int{},
	}
	n.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_nethealth_cycles_total",
		Help: "Net-health check cycles by check and result " +
			"(ok|abort|gated|disabled|uptime_gate|open_error|restore_error).",
	}, []string{"check", "result"})
	n.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_nethealth_actions_total",
		Help: "Net-health remediation actions by check and action " +
			"(pin|unpin|restart|rule_add|rule_del|kill|restored).",
	}, []string{"check", "action"})
	if reg != nil {
		for _, c := range []prometheus.Collector{n.cycles, n.actions} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register nethealth metrics: %w", err)
			}
		}
	}
	return n, nil
}

// Name identifies the subsystem for logging.
func (n *NetHealth) Name() string { return "nethealth" }

// Run checks immediately, then every Interval until ctx is cancelled.
func (n *NetHealth) Run(ctx context.Context) {
	if !n.cfg.Enabled {
		logger().Info("nethealth disabled — idling until shutdown")
		<-ctx.Done()
		return
	}
	// Route guard: netlink-driven restore of the nebula policy
	// routing (replaces nebula-route-guard.service). Single-flight
	// via spawnRouteGuard — overlapping Runs can't double-bind the
	// socket, but a guard that died (recovered panic) is re-armed
	// by the next spawn attempt instead of staying dead forever.
	// No-ops on nodes without
	// <HostRoot>/etc/nebula/<net>/nebula-up.sh (plain workers) or
	// while `systemctl is-active nebula@<net>` is down.
	n.spawnRouteGuard(ctx)
	n.Cycle(ctx)
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Re-arm a dead guard every tick — a panic must not
			// leave route deletes unmonitored until the next
			// full Run restart.
			n.spawnRouteGuard(ctx)
			n.Cycle(ctx)
		}
	}
}

// Cycle runs one round of all checks. The DNS modules carry the
// uptime gate (WD_REQUIRES: uptime) — egress/nebula/fail2ban run
// regardless, like the shell runner. Each check additionally honours
// the runner's per-module kill switch: WD_SIG_<NAME>=off in the conf
// skips it (SignalEnabled), and the conf is re-read every cycle when
// WatchdogSrc is wired (hostconfig rewrites land next cycle).
func (n *NetHealth) Cycle(ctx context.Context) {
	defer n.stampLastRun()
	if n.cfg.WatchdogSrc != nil {
		n.cfg.Watchdog = n.cfg.WatchdogSrc.Get()
	}
	sigOn := func(name string) bool {
		return n.cfg.Watchdog == nil || n.cfg.Watchdog.SignalEnabled(name)
	}
	upOk := true
	if up, err := n.uptimeSeconds(); err == nil && up < minUptimeSeconds {
		upOk = false
	}
	if upOk {
		if sigOn(checkDNSFB) {
			n.checkDNSFallback(ctx)
		} else {
			n.cycles.WithLabelValues(checkDNSFB, "disabled").Inc()
		}
		if sigOn(checkCoreDNS) {
			n.checkCoreDNSStub(ctx)
		} else {
			n.cycles.WithLabelValues(checkCoreDNS, "disabled").Inc()
		}
	} else {
		n.cycles.WithLabelValues(checkDNSFB, "uptime_gate").Inc()
		n.cycles.WithLabelValues(checkCoreDNS, "uptime_gate").Inc()
	}
	if sigOn(checkEgress) {
		n.checkOverlayEgress(ctx)
	} else {
		n.cycles.WithLabelValues(checkEgress, "disabled").Inc()
	}
	if sigOn(checkNebula) {
		n.checkNebulaHealth(ctx)
	} else {
		n.cycles.WithLabelValues(checkNebula, "disabled").Inc()
	}
	if sigOn(checkF2B) {
		n.checkFail2ban(ctx)
	} else {
		n.cycles.WithLabelValues(checkF2B, "disabled").Inc()
	}
	if sigOn(checkClock) {
		n.checkClockSync(ctx)
	} else {
		n.cycles.WithLabelValues(checkClock, "disabled").Inc()
	}
	if sigOn(checkCT) {
		n.checkConntrack(ctx)
	} else {
		n.cycles.WithLabelValues(checkCT, "disabled").Inc()
	}
	if sigOn(checkNebTCP) {
		n.checkNebulaDirectTCP(ctx)
	} else {
		n.cycles.WithLabelValues(checkNebTCP, "disabled").Inc()
	}
}

// stampLastRun refreshes <state>/last-run every cycle — the liveness
// stamp the watchdog-stalled alert reads (BUG-H1). Deferred so even
// an early-returned cycle proves the loop is alive.
func (n *NetHealth) stampLastRun() {
	if n.cfg.WatchdogStateDir == "" {
		return
	}
	content := strconv.FormatInt(n.cfg.nowFn().Unix(), 10) + "\n"
	if err := writeFileAtomic(
		filepath.Join(n.cfg.WatchdogStateDir, fileLastRun), content); err != nil {
		logger().Debug("nethealth: last-run stamp failed",
			"dir", n.cfg.WatchdogStateDir, "error", err)
	}
}

// checkNebulaDirectTCP enforces the pref-1499 Direct-Underlay TCP
// bypass rules (ipproto tcp dport <port> lookup main) for every
// nebula_direct_tcp_ports entry — hostconfig installs them via
// nebula-up.sh + the T5b converge; this guard re-adds a rule the
// kernel lost between converges (same failure mode the netlink route
// guard covers for the overlay tables). Only runs where the nebula
// dataplane is actually deployed.
func (n *NetHealth) checkNebulaDirectTCP(ctx context.Context) {
	wd := n.watchdogConf()
	if wd == nil || !n.nebulaUpExists(wd) {
		n.cycles.WithLabelValues(checkNebTCP, "gated").Inc()
		return
	}
	for _, port := range n.cfg.NebulaDirectTCPPorts {
		if port <= 0 || port > 65535 {
			continue
		}
		p := strconv.Itoa(port)
		out, err := n.ip(ctx, "rule", "list", "pref", "1499")
		if err != nil {
			n.cycles.WithLabelValues(checkNebTCP, "open_error").Inc()
			return
		}
		if strings.Contains(out, "dport "+p+" ") ||
			strings.Contains(out, "dport "+p+"\n") ||
			strings.HasSuffix(strings.TrimSpace(out), "dport "+p) {
			continue
		}
		if _, err := n.ip(ctx, "rule", "add", "pref", "1499",
			"ipproto", "tcp", "dport", p, "lookup", "main"); err != nil {
			n.appendLog(fmt.Sprintf(
				"nebula-direct-tcp: ip rule add pref 1499 dport %s failed: %v",
				p, err))
			n.cycles.WithLabelValues(checkNebTCP, "restore_error").Inc()
			continue
		}
		n.actions.WithLabelValues(checkNebTCP, "rule_add").Inc()
		n.appendLog(fmt.Sprintf(
			"ACTION: re-added pref-1499 direct-underlay tcp dport %s rule", p))
	}
	n.cycles.WithLabelValues(checkNebTCP, "ok").Inc()
}

// --- watchdog file helpers (lib.sh parity — same contract as
// workerhygiene's: state-* latches, last-* budgets, log + slog) ---

func (n *NetHealth) appendLog(msg string) {
	logger().Info(msg)
	f, err := os.OpenFile(n.cfg.WatchdogLogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logger().Debug("nethealth: watchdog log file append failed — "+
			"line kept in agent log only",
			"path", n.cfg.WatchdogLogFile,
			"error", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", n.cfg.nowFn().Format(time.RFC3339), msg)
}

func (n *NetHealth) statePath(name string) string {
	return filepath.Join(n.cfg.WatchdogStateDir, "state-"+name)
}

func (n *NetHealth) stateExists(name string) bool {
	_, err := os.Stat(n.statePath(name))
	return err == nil
}

// writeFileAtomic writes content via a tmp file in the same dir +
// rename — the stateEnter latch pattern. A crash mid-write then can
// never leave a truncated target (the pre-atomic /etc/hosts rewrite
// could orphan a `# BEGIN` block over the node's real host entries).
//
// rename(2) has one blind spot that matters here: the TARGET of a
// file-level bind mount cannot be renamed over — the kernel returns
// EBUSY — and that is exactly how the DaemonSet mounts
// /host/etc/hosts. EXDEV (tmp and target ever landing on different
// filesystems) shares the fallback. Both degrade to a direct
// write+fsync on the target: the crash-atomicity is lost but the
// pins actually land — strictly better than never writing at all.
func writeFileAtomic(path, content string) error {
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	err := renameFile(tmp, path)
	if err == nil {
		return nil
	}
	defer os.Remove(tmp)
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.EXDEV) {
		return err
	}
	// One warn per path, not per write — a bind-mounted hosts file
	// takes the fallback on every render and would spam the log.
	if _, logged := renameFallbackLogged.LoadOrStore(path, true); !logged {
		logger().Warn("nethealth: atomic rename refused (bind-mounted "+
			"target?) — falling back to direct fsync'd write",
			"path", path, "error", err)
	}
	return writeFileDirect(path, content)
}

// renameFile is the rename(2) seam — tests stub it to force the
// EBUSY/EXDEV bind-mount fallback without a real mount.
var renameFile = os.Rename

// renameFallbackLogged remembers which paths already warned about the
// direct-write fallback — one line per path per process.
var renameFallbackLogged sync.Map

// writeFileDirect writes content straight onto path with an fsync —
// the writeFileAtomic fallback when rename(2) is refused. Truncates
// in place, so a crash can leave a partial file; only used where
// rename is provably impossible.
func writeFileDirect(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if _, err := f.WriteString(content); err != nil {
		werr = err
	} else if err := f.Sync(); err != nil {
		werr = err
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func (n *NetHealth) stateEnter(name, extra string) {
	p := n.statePath(name)
	if _, err := os.Stat(p); err == nil {
		// BUG-H6: the latch stays held — refresh its mtime so the
		// janitor's 24h latch reap can't retire an active signal.
		now := n.cfg.nowFn()
		if cerr := os.Chtimes(p, now, now); cerr != nil {
			logger().Debug("nethealth: state latch touch failed",
				"state", name, "path", p, "error", cerr)
		}
		return
	}
	content := strconv.FormatInt(n.cfg.nowFn().Unix(), 10) + "\n"
	if err := writeFileAtomic(p, content); err != nil {
		logger().Warn("nethealth: state latch write failed",
			"state", name, "path", p, "error", err)
		return
	}
	if extra != "" {
		n.appendLog(fmt.Sprintf("STATE-ENTER: %s %s", name, extra))
	} else {
		n.appendLog(fmt.Sprintf("STATE-ENTER: %s", name))
	}
}

func (n *NetHealth) stateExit(name string) {
	p := n.statePath(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		logger().Warn("nethealth: state latch remove failed",
			"state", name, "path", p, "error", err)
		return
	}
	// Drop the suspect-log dedupe budgets with the latch — a later
	// re-entry must log a fresh first line, not stay throttled by a
	// stale epoch from the previous incident. That covers the
	// latch-paired last-suspect-<name>, and the whole rest of the
	// family goes with it: the NON-latch keys (egress-probe-<ip>,
	// conntrack-parse, clock-adjtimex, ...) have no state-* twin to
	// exit with, so a cleared condition would otherwise suppress the
	// first line of a re-incident for up to suspectLogCadence. No
	// clean per-key pairing exists — a latch exit IS an incident
	// boundary, so the whole family resets; a still-held condition
	// pays at most one early re-log line.
	for _, f := range n.egressFiles(fileSuspectLog) {
		_ = os.Remove(f)
	}
	n.appendLog(fmt.Sprintf("STATE-EXIT: %s", name))
}

func (n *NetHealth) rateOK(name string, interval time.Duration) bool {
	data, err := os.ReadFile(filepath.Join(n.cfg.WatchdogStateDir, name))
	if err != nil {
		return true
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return true
	}
	return n.cfg.nowFn().Unix()-last >= int64(interval.Seconds())
}

func (n *NetHealth) rateSpend(name string) {
	p := filepath.Join(n.cfg.WatchdogStateDir, name)
	content := strconv.FormatInt(n.cfg.nowFn().Unix(), 10) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Warn("nethealth: rate budget write failed",
			"budget", name, "path", p, "error", err)
	}
}

// suspectLog emits a suspect/hold line at most once per
// suspectLogCadence per key — a last-suspect-<key> epoch file under
// the same rateOK/rateSpend convention as the action budgets
// (controllerhygiene's suspectLog parity). It replaces the per-cycle
// appendLog for lines whose condition persists: STATE-ENTER still
// announces the transition and a cadence re-reminder keeps a
// long-held condition visible in the tail. Counters, latches and
// metrics keep updating every cycle — only the LOG line is
// throttled. A latch exit drops the WHOLE last-suspect-* family —
// the latch is an incident boundary, and non-latch keys have no
// other reset path (see stateExit).
func (n *NetHealth) suspectLog(key, msg string) {
	if !n.rateOK(fileSuspectLog+key, suspectLogCadence) {
		return
	}
	n.rateSpend(fileSuspectLog + key)
	n.appendLog(msg)
}

// readFile returns trimmed file content, "" on any error.
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (n *NetHealth) uptimeSeconds() (float64, error) {
	data, err := os.ReadFile(n.cfg.UptimeFile)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("empty uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

// nameservers returns up to 3 nameserver IPs from a resolv.conf
// (shell `awk $1=="nameserver" | head -3`).
func nameservers(path string, max int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// minRTT parses the smallest "time=<ms>" from ping output — the
// shell's wd_probe_rtt (first sample is inflated by ARP/tunnel setup).
var rttRe = regexp.MustCompile(`time=([0-9.]+)`)

func minRTT(out string) float64 {
	best := -1.0
	for _, m := range rttRe.FindAllStringSubmatch(out, -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && (best < 0 || v < best) {
			best = v
		}
	}
	return best
}

// probeHTTPGet is the default probeHTTP: GET with deadline, nil on
// 2xx only (curl -sf parity for nebula stats — a wedged daemon still
// serves TCP, only the metrics endpoint failing counts).
func probeHTTPGet(ctx context.Context, url string, timeout time.Duration) error {
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// unitActive mirrors `systemctl is-enabled + is-active` — the
// runner's overlay-active probes (WD_NEBULA_ACTIVE/WD_TINC_ACTIVE).
func (n *NetHealth) unitEnabledActive(ctx context.Context, unit string) bool {
	if n.cfg.Systemd == nil {
		return false
	}
	return n.cfg.Systemd.IsEnabled(ctx, unit) && n.cfg.Systemd.IsActive(ctx, unit)
}

// --- Check: dns-fallback (20-dns-fallback.sh) ---

// pinFiles returns the sorted dnsfb-pin-* files — the source of truth
// for the managed /etc/hosts block.
func (n *NetHealth) pinFiles() []string {
	files, err := filepath.Glob(
		filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-pin-*"))
	if err != nil {
		return nil
	}
	sort.Strings(files)
	return files
}

// renderHostsBlock rewrites the managed block in HostsFile from the
// pin files. block=="" (no pins) removes the block. Returns whether
// the file changed.
func (n *NetHealth) renderHostsBlock(block string) (changed bool) {
	data, err := os.ReadFile(n.cfg.HostsFile)
	if err != nil {
		logger().Warn("nethealth: hosts file unreadable — dns-fallback "+
			"block left untouched",
			"path", n.cfg.HostsFile,
			"error", err)
		return false
	}
	cur := string(data)
	var kept []string
	var tail []string // lines inside an unterminated managed block
	inBlock := false
	hadBlock := false
	for _, line := range strings.Split(cur, "\n") {
		switch strings.TrimSpace(line) {
		case hostsBlockBegin:
			inBlock, hadBlock = true, true
			continue
		case hostsBlockEnd:
			inBlock = false
			continue
		}
		if inBlock {
			tail = append(tail, line)
			continue
		}
		kept = append(kept, line)
	}
	if inBlock {
		// BEGIN without END (truncated/corrupted file): the block
		// ran to EOF. Don't silently eat its lines — they may be
		// real host entries stranded inside a stray marker — keep
		// them as ordinary content before the (re-)written block
		// and warn so the corruption is visible.
		//
		// The exception: lines pinning a MANAGED DNSFallback name.
		// Those are stale output of an earlier managed block, not
		// foreign entries, and re-emitting them ABOVE the new block
		// would let a dead pin shadow the fresh one (first match
		// wins in /etc/hosts). They are regenerable — the block
		// carries the live pins — so they drop; genuinely foreign
		// entries still keep their rescue.
		managed := map[string]bool{}
		if n.cfg.Watchdog != nil {
			for _, e := range n.cfg.Watchdog.DNSFallback {
				managed[e.Name] = true
			}
		}
		dropped := 0
		for _, line := range tail {
			if managedPinLine(line, managed) {
				dropped++
				continue
			}
			kept = append(kept, line)
		}
		logger().Warn("nethealth: unterminated "+hostsBlockBegin+" block "+
			"in hosts file — treating EOF as block end, keeping the "+
			"tail outside the managed block",
			"path", n.cfg.HostsFile,
			"stalePinsDropped", dropped)
	}
	body := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	next := body + "\n"
	if block != "" {
		next = body + "\n" + hostsBlockBegin + "\n" + block + hostsBlockEnd + "\n"
	}
	if !hadBlock && block == "" {
		return false
	}
	if next == cur {
		return false
	}
	if err := writeFileAtomic(n.cfg.HostsFile, next); err != nil {
		logger().Warn("nethealth: hosts file write failed — dns-fallback "+
			"block not applied",
			"path", n.cfg.HostsFile,
			"error", err)
		return false
	}
	return true
}

// managedPinLine reports whether a hosts-file line pins one of the
// DNSFallback names — i.e. it is residue of an earlier managed block
// rather than a foreign entry worth rescuing from an unterminated
// block tail. Hostname fields are fields[1:] (field 0 is the IP);
// comments, blanks and malformed lines never match.
func managedPinLine(line string, managed map[string]bool) bool {
	if len(managed) == 0 {
		return false
	}
	f := strings.Fields(line)
	if len(f) < 2 || strings.HasPrefix(f[0], "#") {
		return false
	}
	for _, h := range f[1:] {
		if managed[h] {
			return true
		}
	}
	return false
}

// checkDNSFallback — sig10: DNS dead → pin fallback names into the
// managed /etc/hosts block so kubelet can still resolve the API name.
func (n *NetHealth) checkDNSFallback(ctx context.Context) {
	wd := n.cfg.Watchdog
	if len(wd.DNSFallback) == 0 {
		// Map empty → clean up block + files like the shell's else
		// (`rm -f dnsfb-*`: pin/last-good/counter files all go —
		// shell leftovers included).
		if n.renderHostsBlock("") {
			n.appendLog("ACTION: /etc/hosts dns-fallback block removed (map empty)")
		}
		for _, f := range n.egressFiles("dnsfb-") {
			_ = os.Remove(f)
		}
		n.dnsfails = map[string]int{}
		n.stateExit("dns-fallback")
		n.cycles.WithLabelValues(checkDNSFB, "ok").Inc()
		return
	}
	ns := nameservers(n.cfg.HostResolvConf, 3)
	inMap := map[string]bool{}
	for _, e := range wd.DNSFallback {
		inMap[e.Name] = true
	}
	for _, e := range wd.DNSFallback {
		lg := filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-lg-"+e.Name)
		pinf := filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-pin-"+e.Name)
		resolved := ""
		for _, server := range ns {
			ip, err := n.cfg.dnsProbe(ctx, server, e.Name)
			if err != nil {
				logger().Debug("nethealth: dns probe failed",
					"name", e.Name,
					"nameserver", server, "error", err)
				continue
			}
			if ip != "" {
				resolved = ip
				break
			}
		}
		if resolved != "" {
			if readFile(lg) != resolved {
				if err := writeFileAtomic(lg, resolved+"\n"); err != nil {
					logger().Warn("nethealth: dns last-good write "+
						"failed — fallback pick may lose the "+
						"last-known-good IP",
						"name", e.Name,
						"path", lg, "error", err)
				}
			}
			delete(n.dnsfails, e.Name)
			_ = os.Remove(pinf)
			continue
		}
		n.dnsfails[e.Name]++
		fails := n.dnsfails[e.Name]
		curIP := ""
		if pin := strings.Fields(readFile(pinf)); len(pin) >= 1 {
			curIP = pin[0]
		}
		if fails < n.cfg.ConsecNeeded && curIP == "" {
			n.appendLog(fmt.Sprintf(
				"suspect: dns-resolve %s fail via resolv.conf (check %d/%d)",
				e.Name, fails, n.cfg.ConsecNeeded))
			continue
		}
		// Over threshold or already pinned: keep a live pin, probe a
		// replacement when the current one dies — last-known-good
		// first, then map candidates (TCP probe, never ICMP — some
		// hubs filter it).
		if curIP == "" || n.cfg.tcpProbe(ctx, curIP, e.Port, 3*time.Second) != nil {
			newIP := ""
			cands := append([]string{readFile(lg)}, e.Candidates...)
			for _, c := range cands {
				if c == "" || c == curIP {
					continue
				}
				if n.cfg.tcpProbe(ctx, c, e.Port, 3*time.Second) == nil {
					newIP = c
					break
				}
			}
			if newIP != "" {
				n.appendLog(fmt.Sprintf(
					"ACTION: dns-fallback pin %s -> %s (DNS fail %dx, was '%s')",
					e.Name, newIP, fails, curIP))
				if err := writeFileAtomic(pinf,
					newIP+" "+e.Name+"\n"); err != nil {
					n.appendLog(fmt.Sprintf(
						"dns-fallback: pin file write failed for %s -> %s: %v",
						e.Name, newIP, err))
				}
				n.actions.WithLabelValues(checkDNSFB, "pin").Inc()
			} else if curIP == "" {
				n.suspectLog("dnsfb-nocand-"+e.Name, fmt.Sprintf(
					"suspect: dns-fallback %s — all candidates unreachable, not pinning",
					e.Name))
			}
			// Dead pin with no replacement → keep it (a pinned dead
			// IP is no worse than NXDOMAIN and may come back).
		}
	}
	// Prune pin files for names removed from the map — the shell
	// also dropped the matching dnsfb-ctr-* counter (the lg
	// last-known-good file stays: it is still the best hint if the
	// name ever comes back). The in-memory fail counters get the
	// same prune — otherwise a removed name's key lingers forever.
	for _, f := range n.pinFiles() {
		name := strings.TrimPrefix(filepath.Base(f), "dnsfb-pin-")
		if !inMap[name] {
			_ = os.Remove(f)
			_ = os.Remove(filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-ctr-"+name))
		}
	}
	for name := range n.dnsfails {
		if !inMap[name] {
			delete(n.dnsfails, name)
		}
	}
	// Render the managed block from the pins.
	block := ""
	for _, f := range n.pinFiles() {
		if c := readFile(f); c != "" {
			block += c + "\n"
		}
	}
	if block != "" {
		if n.renderHostsBlock(block) {
			n.appendLog("ACTION: /etc/hosts dns-fallback block updated")
			// Newly written pins mean DNS was dead — conntrack
			// entries learned on the broken path blackhole lookups
			// until expiry unless flushed now.
			n.flushStaleUDPConntrack(ctx, checkDNSFB)
		}
		n.stateEnter("dns-fallback", "")
	} else {
		if n.renderHostsBlock("") {
			n.appendLog("ACTION: /etc/hosts dns-fallback block removed (DNS OK)")
			// Unpin is a DNS-path transition too — replies for the
			// restored resolver may sit in stale udp/53 entries.
			n.flushStaleUDPConntrack(ctx, checkDNSFB)
		}
		n.stateExit("dns-fallback")
	}
	n.cycles.WithLabelValues(checkDNSFB, "ok").Inc()
}

// --- Check: coredns-stub (21-coredns-stub.sh) ---

// checkCoreDNSStub restarts the coredns local stub when resolv.conf
// points at 127.0.0.1 but the unit is down — the port adds a 5m
// cooldown (shell restarted every run; a crashlooping stub otherwise
// burns a restart every cycle).
func (n *NetHealth) checkCoreDNSStub(ctx context.Context) {
	loopback := false
	for _, server := range nameservers(n.cfg.HostResolvConf, 16) {
		if server == "127.0.0.1" {
			loopback = true
			break
		}
	}
	if !loopback || n.cfg.Systemd == nil {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	// Fail closed on probe errors: an unanswerable `cat`/is-active
	// used to read as absent/active — an error now counts as
	// present+active so a broken systemctl can never trigger (or
	// skip-gate) a coredns restart on a lie.
	exists, err := n.cfg.Systemd.Exists(ctx, "coredns.service")
	if err != nil {
		logger().Warn("nethealth: coredns existence probe failed — "+
			"treating unit as present this cycle (fail closed)",
			"unit", "coredns.service",
			"error", err)
		exists = true
	}
	if !exists {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "coredns.service")
	if err != nil {
		logger().Warn("nethealth: coredns is-active probe failed — "+
			"treating unit as active this cycle (fail closed)",
			"unit", "coredns.service",
			"error", err)
		active = true
	}
	if active {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	if !n.rateOK("last-coredns-restart", corednsRestartInterval) {
		n.suspectLog("coredns-cooldown",
			"suspect: coredns stub dead but restart cooldown (<5m), skip")
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	n.appendLog("ACTION: restarting coredns - stub dead but resolv.conf points at 127.0.0.1")
	n.rateSpend("last-coredns-restart")
	if err := n.cfg.Systemd.Restart(ctx, "coredns.service"); err != nil {
		n.appendLog(fmt.Sprintf("coredns restart failed: %v", err))
	} else {
		n.actions.WithLabelValues(checkCoreDNS, "restart").Inc()
		n.flushStaleUDPConntrack(ctx, checkCoreDNS)
	}
	n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
}

// --- Check: overlay-egress (12-overlay-egress.sh) ---

// ip runs the host `ip` tool through the runner seam. Failures are
// debug-logged here so the many best-effort callers that drop the
// error (rule adds/dels during drift heal, probe-window swaps) still
// leave a diagnostic trail — the callers that handle the error get
// it returned as before.
func (n *NetHealth) ip(ctx context.Context, args ...string) (string, error) {
	out, err := n.cfg.runHostCmd(ctx, append([]string{"ip"}, args...))
	if err != nil {
		logger().Debug("nethealth: host ip command failed",
			"args", args,
			"output", trimRunErr(out), "error", err)
	}
	return out, err
}

// ipRuleDel1500 removes a pref-1500 rule for ip across the given
// tables — the multi-table cleanup the shell runs on relay removal.
func (n *NetHealth) ipRuleDel1500(ctx context.Context, ip string, tables []int) {
	for _, t := range tables {
		_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
			ip+"/32", "lookup", strconv.Itoa(t))
	}
}

// overlayUp mirrors OVERLAY_UP = WD_TINC_ACTIVE || WD_NEBULA_ACTIVE.
func (n *NetHealth) overlayUp(ctx context.Context) bool {
	wd := n.cfg.Watchdog
	return n.unitEnabledActive(ctx, "nebula@"+wd.NebulaNet) ||
		n.unitEnabledActive(ctx, "tinc@"+wd.TincNet)
}

// ruleHasTarget reports whether `ip rule list pref 1500` output
// carries a "to <ip>" rule — shell `grep -q "to $r "`.
func ruleHasTarget(rules, ip string) bool {
	return strings.Contains(rules, "to "+ip+" ")
}

// ruleTablesFor returns every lookup table referenced by rules for ip.
func ruleTablesFor(rules, ip string) []int {
	var out []int
	for _, line := range strings.Split(rules, "\n") {
		if !strings.Contains(line, "to "+ip) {
			continue
		}
		f := strings.Fields(line)
		for i, w := range f {
			if w == "lookup" && i+1 < len(f) {
				if t, err := strconv.Atoi(f[i+1]); err == nil {
					out = append(out, t)
				}
			}
		}
	}
	return out
}

// checkOverlayEgress — sig4: conditional egress relays. Committed
// state lives in egress-state-<ip> files ("direct"|"relay"); the live
// ip rule is healed toward it each cycle. Underlay dead → relay
// immediately; underlay back → direct only after CONSEC_NEEDED fresh
// probes (anti-ping-pong hysteresis).
func (n *NetHealth) checkOverlayEgress(ctx context.Context) {
	wd := n.cfg.Watchdog
	relays := wd.OverlayEgressRelays
	table := wd.OverlayEgressTable
	if table == 0 {
		table = 100
	}
	up := n.overlayUp(ctx)
	allTables := []int{table, 100, 102, 103}

	if len(relays) == 0 || !up {
		// No overlay / empty list → remove every watchdog rule + state
		// (rules are harmless — only 0x2000-marked packets are
		// affected — but stale state files feed phantom metrics).
		for _, f := range n.egressFiles("egress-state-") {
			ip := strings.TrimPrefix(filepath.Base(f), "egress-state-")
			n.ipRuleDel1500(ctx, ip, allTables)
		}
		_, _ = n.ip(ctx, "rule", "del", "pref", "1390", "fwmark", "0x2000", "lookup", "main")
		for _, f := range n.egressFiles("egress-state-", "egress-ctr-", "egress-icmpblk-") {
			_ = os.Remove(f)
		}
		n.egressCtr = map[string]int{}
		n.cycles.WithLabelValues(checkEgress, "ok").Inc()
		return
	}

	rules, err := n.ip(ctx, "rule", "list")
	if err != nil {
		n.suspectLog("egress-rulelist", fmt.Sprintf(
			"overlay-egress: ip rule list failed: %v — cycle aborted", err))
		n.cycles.WithLabelValues(checkEgress, "abort").Inc()
		return
	}
	if !strings.Contains(rules, "fwmark 0x2000") {
		_, _ = n.ip(ctx, "rule", "add", "pref", "1390", "fwmark", "0x2000", "lookup", "main")
	}
	rules1500, err := n.ip(ctx, "rule", "list", "pref", "1500")
	if err != nil {
		// A failed list reads as "no pref-1500 rules" — every
		// relay then looks live=direct, driving redundant
		// del/add churn and a rigged probe path. Warn so the
		// blind cycle is visible.
		logger().Warn("nethealth: ip rule list pref 1500 failed — "+
			"relays read as unruled this cycle",
			"error", err)
	}

	inSet := map[string]bool{}
	for _, r := range relays {
		inSet[r] = true
	}
	for _, r := range relays {
		stf := filepath.Join(n.cfg.WatchdogStateDir, "egress-state-"+r)
		comm := readFile(stf)
		if comm != "relay" {
			comm = "direct"
		}
		live := "direct"
		if ruleHasTarget(rules1500, r) {
			live = "relay"
		}
		// Prune rules pointing at tables other than the active one —
		// an overlay flip (tinc↔nebula) leaves stale-table rules that
		// would still push traffic into the dead table.
		for _, t := range ruleTablesFor(rules1500, r) {
			if t != table {
				n.ipRuleDel1500(ctx, r, []int{t})
				n.appendLog(fmt.Sprintf(
					"cleanup: egress %s rule lookup %d stale (current table %d)", r, t, table))
			}
		}
		// Drift heal: live rule must match committed state (up/down
		// scripts can delete rules behind our back).
		if live != comm {
			var herr error
			if comm == "relay" {
				_, herr = n.ip(ctx, "rule", "add", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			} else {
				_, herr = n.ip(ctx, "rule", "del", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			}
			if herr != nil {
				// Heal failed — leave `live` as probed so the probe
				// window and the relay-dead check below see the real
				// rule state; the drift is retried next cycle.
				n.suspectLog("egress-heal-"+r, fmt.Sprintf(
					"suspect: heal egress %s rule -> %s table %d failed: %v",
					r, comm, table, herr))
			} else {
				n.appendLog(fmt.Sprintf(
					"ACTION: heal egress %s rule -> %s table %d (was %s)", r, comm, table, live))
				live = comm
				// B3: the rule change just switched the underlay path for
				// this peer — drop its stale nebula-udp conntrack so the
				// re-handshake happens on the new path now.
				n.flushPeerNebulaConntrack(ctx, checkEgress, r)
			}
		}
		// Probe the underlay under SO_MARK 0x2000 → pref 1390 → main
		// table, unaffected by the relay rule.
		icmpBlk := filepath.Join(n.cfg.WatchdogStateDir, "egress-icmpblk-"+r)
		probe := "relay"
		// unprobeable marks "no fresh evidence this cycle": set when
		// the TCP fallback was skipped because the probe-window rule
		// del failed — the commit log then says "committed to live"
		// rather than "(direct failed)".
		unprobeable := false
		if ok, _ := n.cfg.ping(ctx, r, 2, 4, true); ok {
			probe = "direct"
			_ = os.Remove(icmpBlk)
		} else if port := wd.OverlayEgressTCP[r]; port != "" {
			// ICMP filtered ≠ underlay dead — TCP fallback decides.
			// A live relay rule would route the connect via overlay,
			// so drop it for the probe window like the shell did.
			// hadRule is the POST-HEAL live state (the shell re-queried
			// `ip rule list pref 1500` here, not the pre-heal snapshot):
			// when the heal just re-added the relay rule, probing with
			// it in place would traverse the overlay and misreport
			// "direct" — the relay/direct flap this guards against.
			hadRule := live == "relay"
			ruleDropped := false
			if hadRule {
				if _, derr := n.ip(ctx, "rule", "del", "pref", "1500",
					"to", r+"/32", "lookup", strconv.Itoa(table)); derr != nil {
					// Probing with the relay rule still in place
					// would traverse the overlay and misreport
					// "direct" — skip the TCP fallback this cycle
					// rather than trust a rigged probe. Flag the
					// window unprobeable so the commit log below
					// says "kept live" instead of claiming
					// underlay evidence that was never collected.
					unprobeable = true
					logger().Warn("nethealth: probe-window rule del "+
						"failed — skipping TCP fallback probe this cycle",
						"relay", r,
						"table", table, "error", derr)
				} else {
					ruleDropped = true
				}
			}
			if !hadRule || ruleDropped {
				if n.cfg.tcpProbe(ctx, r, port, 5*time.Second) == nil {
					probe = "direct"
					if _, err := os.Stat(icmpBlk); err != nil {
						if werr := writeFileAtomic(icmpBlk,
							strconv.FormatInt(n.cfg.nowFn().Unix(), 10)+"\n"); werr != nil {
							logger().Warn("nethealth: egress "+
								"icmp-blocked marker write failed",
								"path", icmpBlk, "error", werr)
						}
						n.appendLog(fmt.Sprintf(
							"egress %s: ICMP blocked but tcp/%s alive — treat as direct (provider blocks ICMP?)", r, port))
					}
				}
			}
			if ruleDropped {
				// Restore the relay rule — a failed restore would
				// leave it removed until next cycle's drift heal,
				// so retry once inline before warning.
				_, aerr := n.ip(ctx, "rule", "add", "pref", "1500",
					"to", r+"/32", "lookup", strconv.Itoa(table))
				if aerr != nil {
					_, aerr = n.ip(ctx, "rule", "add", "pref", "1500",
						"to", r+"/32", "lookup", strconv.Itoa(table))
				}
				if aerr != nil {
					logger().Warn("nethealth: probe-window rule "+
						"restore failed — relay rule left removed "+
						"until next cycle's drift heal",
						"relay", r,
						"table", table, "error", aerr)
				}
			}
		}
		if probe == comm {
			delete(n.egressCtr, r)
		} else {
			need := 1 // underlay dead → relay NOW (route is ready)
			if probe == "direct" {
				need = n.cfg.ConsecNeeded // recovery needs hysteresis
			}
			n.egressCtr[r]++
			ctr := n.egressCtr[r]
			if ctr >= need {
				delete(n.egressCtr, r)
				if werr := writeFileAtomic(stf, probe+"\n"); werr != nil {
					// Committed/live drift: the rule change below
					// still runs; next cycle's heal converges.
					logger().Warn("nethealth: egress state commit "+
						"write failed — committed/live drift "+
						"heals next cycle",
						"relay", r,
						"path", stf, "error", werr)
				}
				if probe == "relay" {
					if unprobeable {
						// No probe ran — the commit only restates
						// what live already is. Logging "(direct
						// failed)" here would claim a dead-underlay
						// measurement the skipped TCP fallback
						// never produced.
						n.appendLog(fmt.Sprintf(
							"ACTION: egress %s -> overlay relay table %d (unprobeable window — committed to live)", r, table))
					} else {
						n.appendLog(fmt.Sprintf(
							"ACTION: egress %s -> overlay relay table %d (direct failed)", r, table))
					}
					_, _ = n.ip(ctx, "rule", "add", "pref", "1500", "to",
						r+"/32", "lookup", strconv.Itoa(table))
					n.actions.WithLabelValues(checkEgress, "rule_add").Inc()
				} else {
					n.appendLog(fmt.Sprintf(
						"ACTION: egress %s -> direct underlay (recovered)", r))
					_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
						r+"/32", "lookup", strconv.Itoa(table))
					n.actions.WithLabelValues(checkEgress, "rule_del").Inc()
				}
				live = probe
				// B3: committed state just flipped — this peer's
				// udp/<nebula-port> conntrack entries still pin the
				// old path; flush only this peer's entries.
				n.flushPeerNebulaConntrack(ctx, checkEgress, r)
			} else {
				n.suspectLog("egress-probe-"+r, fmt.Sprintf(
					"suspect: egress %s probe=%s cur=%s (check %d/%d)", r, probe, comm, ctr, need))
			}
		}
		// Serving via relay while the tunnel itself is unreachable →
		// the relay is dead too.
		if live == "relay" {
			if ok, _ := n.cfg.ping(ctx, r, 1, 4, false); !ok {
				n.suspectLog("egress-unreach-"+r, fmt.Sprintf(
					"suspect: overlay-egress unreachable %s (relay down?)", r))
			}
		}
	}
	// Cleanup state/rules for relays removed from the list.
	for _, f := range append(append(n.egressFiles("egress-state-"),
		n.egressFiles("egress-ctr-")...),
		n.egressFiles("egress-icmpblk-")...) {
		base := filepath.Base(f)
		ip := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(base,
			"egress-state-"), "egress-ctr-"), "egress-icmpblk-")
		if inSet[ip] {
			continue
		}
		n.ipRuleDel1500(ctx, ip, allTables)
		_ = os.Remove(f)
		delete(n.egressCtr, ip)
		n.appendLog(fmt.Sprintf(
			"cleanup: egress state/rule for %s (no longer in OVERLAY_EGRESS_RELAYS)", ip))
	}
	n.cycles.WithLabelValues(checkEgress, "ok").Inc()
}

// egressFiles lists state-dir files matching any prefix.
func (n *NetHealth) egressFiles(prefixes ...string) []string {
	var out []string
	for _, p := range prefixes {
		files, err := filepath.Glob(filepath.Join(n.cfg.WatchdogStateDir, p+"*"))
		if err == nil {
			out = append(out, files...)
		}
	}
	return out
}

// --- Check: nebula-health (13-nebula-health.sh) ---

// udpSocketBound parses /proc/net/udp[6] for a socket bound to port —
// `ss -uHln "sport = :PORT"` parity (UNCONN sockets included — a raw
// parse of the hex local_address field).
func (n *NetHealth) udpSocketBound(port int) bool {
	want := fmt.Sprintf(":%04X", port)
	for _, f := range []string{n.cfg.ProcNetUDP, n.cfg.ProcNetUDP6} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasSuffix(fields[1], want) {
				return true
			}
		}
	}
	return false
}

// hasIPv4Addr mirrors `ip -4 -o addr show dev <dev> | grep .` — a
// tun that failed to init has no address.
func (n *NetHealth) hasIPv4Addr(ctx context.Context, dev string) bool {
	out, err := n.ip(ctx, "-4", "-o", "addr", "show", "dev", dev)
	return err == nil && strings.TrimSpace(out) != ""
}

// nebulaRestarts restarts nebula@<net> through the shared
// last-nebula-restart budget.
func (n *NetHealth) nebulaRestart(ctx context.Context) {
	net := n.cfg.Watchdog.NebulaNet
	if n.cfg.Systemd == nil {
		n.suspectLog("nebula-no-systemd",
			"nebula restart skipped — no systemd client")
		return
	}
	if err := n.cfg.Systemd.Restart(ctx, "nebula@"+net); err != nil {
		n.appendLog(fmt.Sprintf("nebula@%s restart failed: %v", net, err))
		return
	}
	n.actions.WithLabelValues(checkNebula, "restart").Inc()
	// DNS flows pinned to conntrack entries through the dead tunnel
	// stay blackholed until expiry — flush them now.
	n.flushStaleUDPConntrack(ctx, checkNebula)
}

// rmFiles removes every state-dir file matching glob — the module's
// `rm -f $STATE_DIR/<pattern>` cleanup when its unit is inactive.
func (n *NetHealth) rmFiles(pattern string) {
	for _, f := range n.egressFiles(pattern) {
		_ = os.Remove(f)
	}
}

// pingResult bundles the per-target fanout output.
type pingResult struct {
	ok  bool
	rtt float64
}

// checkNebulaHealth — module 13: socket bound, tun addressed, stats
// answering, dataplane probes (only while nebula is the ACTIVE
// overlay — probing over tinc rules would misjudge the warm standby).
func (n *NetHealth) checkNebulaHealth(ctx context.Context) {
	wd := n.cfg.Watchdog
	net := wd.NebulaNet
	if !n.unitEnabledActive(ctx, "nebula@"+net) {
		// Nebula disabled/left mesh → drop this module's states
		// (stale files feed phantom gauges). Egress state is module
		// 12's own business.
		n.rmFiles("state-nebula-")
		n.nebulaFails, n.nebulaDpFail, n.nebulaDeg = 0, 0, 0
		n.pmtuFails = 0
		n.cycles.WithLabelValues(checkNebula, "gated").Inc()
		return
	}
	reason := ""
	dpFail := false // dataplane-dead counts its own counter
	switch {
	case !n.udpSocketBound(wd.NebulaPort):
		reason = fmt.Sprintf("nebula-no-socket udp/%d not bound", wd.NebulaPort)
	case !n.hasIPv4Addr(ctx, wd.NebulaDev):
		reason = fmt.Sprintf("nebula-no-tun-addr dev=%s", wd.NebulaDev)
	case wd.NebulaStatsURL != "":
		if err := n.cfg.probeHTTP(ctx, wd.NebulaStatsURL, 5*time.Second); err != nil {
			reason = fmt.Sprintf("nebula-stats-dead %s: %v",
				wd.NebulaStatsURL, err)
		}
	}

	// Dataplane probes — ONLY while nebula is the active overlay.
	if reason == "" && wd.OverlayActive == "nebula" &&
		(len(wd.OverlayProbeTargets)+len(wd.OverlayProbeMarkers)) > 0 {
		count := wd.OverlayProbeCount
		if count <= 0 {
			count = 3
		}
		wait := wd.OverlayProbeWait
		if wait <= 0 {
			wait = 4
		}
		// Parallel fanout like wd_ping_fanout — serial pings would
		// blow the check budget on a large mesh.
		targets := append(append(append([]string{},
			wd.OverlayProbeTargets...),
			wd.OverlayProbeMarkers...),
			wd.OverlaySiteMarkers...)
		results := map[string]pingResult{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range targets {
			t := t
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, rtt := n.cfg.ping(ctx, t, count, wait, false)
				mu.Lock()
				results[t] = pingResult{ok, rtt}
				mu.Unlock()
			}()
		}
		wg.Wait()

		dpAlive, dpTotal := 0, 0
		for _, t := range wd.OverlayProbeTargets {
			dpTotal++
			if results[t].ok {
				dpAlive++
			}
		}
		mkAlive, mkTotal := 0, 0
		var slowpath []string
		slowSet := map[string]bool{}
		for _, t := range wd.OverlaySlowpathMarkers {
			slowSet[t] = true
		}
		for _, t := range wd.OverlayProbeMarkers {
			mkTotal++
			r := results[t]
			if !r.ok {
				continue
			}
			mkAlive++
			if slowSet[t] && r.rtt >= 0 && r.rtt > wd.OverlaySlowpathRTTms {
				slowpath = append(slowpath, fmt.Sprintf("%s=%.1fms", t, r.rtt))
			}
		}
		if len(slowpath) > 0 {
			n.suspectLog("nebula-slowpath", fmt.Sprintf(
				"suspect: nebula-dataplane-slowpath (reroute via remote site) %s",
				strings.Join(slowpath, " ")))
			n.stateEnter("nebula-slowpath", strings.Join(slowpath, " "))
		} else {
			n.stateExit("nebula-slowpath")
		}
		if len(wd.OverlaySiteMarkers) > 0 {
			var siteedge []string
			for _, t := range wd.OverlaySiteMarkers {
				r := results[t]
				if !r.ok {
					siteedge = append(siteedge, t+"=dead")
					continue
				}
				if r.rtt >= 0 && r.rtt > wd.OverlaySiteedgeRTTms {
					siteedge = append(siteedge, fmt.Sprintf("%s=%.1fms", t, r.rtt))
				}
			}
			if len(siteedge) > 0 {
				n.suspectLog("nebula-siteedge", fmt.Sprintf(
					"suspect: nebula-siteedge-degraded (site-mesh edge lost) %s",
					strings.Join(siteedge, " ")))
				n.stateEnter("nebula-siteedge", strings.Join(siteedge, " "))
			} else {
				n.stateExit("nebula-siteedge")
			}
		}
		switch {
		case (dpTotal > 0 && dpAlive == 0) || (mkTotal > 0 && mkAlive == 0):
			reason = fmt.Sprintf("nebula-dataplane-dead pub=%d/%d marker=%d/%d",
				dpAlive, dpTotal, mkAlive, mkTotal)
			dpFail = true
			n.nebulaDeg = 0
			n.stateExit("nebula-degraded")
			if !n.stateExists("nebula-isolated") {
				// B3: on the isolation edge the conntrack entries
				// learned on the dead path keep the tunnel blackholed
				// — drop each affected peer's udp/<nebula-port>
				// entries to force re-handshake immediately. The peer
				// set is the FULL known set on purpose: whole-node
				// isolation means every peer's conntrack is stale.
				// NB: the disk latch means the edge won't refire
				// after an agent restart while already isolated —
				// acceptable (restart clears in-memory state but the
				// stale flows have long expired by then).
				n.flushPeerNebulaConntrack(ctx, checkNebula, nebulaPeerUnderlayIPs(wd)...)
			}
			n.stateEnter("nebula-isolated", "dataplane dead")
		case dpTotal-dpAlive >= 2 || mkTotal-mkAlive >= 2:
			n.nebulaDeg++
			need := wd.NebulaDegradedConsec
			if need <= 0 {
				need = 2
			}
			n.suspectLog("nebula-degraded", fmt.Sprintf(
				"suspect: nebula-dataplane-degraded pub=%d/%d marker=%d/%d (run %d/%d)",
				dpAlive, dpTotal, mkAlive, mkTotal, n.nebulaDeg, need))
			if n.nebulaDeg >= need {
				n.stateEnter("nebula-degraded", fmt.Sprintf(
					"pub=%d/%d marker=%d/%d", dpAlive, dpTotal, mkAlive, mkTotal))
			}
		default:
			n.nebulaDeg = 0
			n.stateExit("nebula-degraded")
			n.stateExit("nebula-isolated")
		}
		// W9-NM1: small-packet pings can pass while a DF probe at
		// near-MTU size blackholes — the double-encap path MTU
		// sits below the overlay's. Only evaluated when at least
		// one overlay target answered the small pings; total
		// overlay failure belongs to the isolated/degraded
		// verdicts above, not to a PMTU latch.
		n.checkNebulaPMTU(ctx, targets, results)
	} else {
		// overlay != nebula (or no probe config): don't probe through
		// the other overlay — clear leftover dataplane states.
		n.nebulaDeg = 0
		n.pmtuFails = 0
		n.stateExit("nebula-degraded")
		n.stateExit("nebula-slowpath")
		n.stateExit("nebula-siteedge")
		n.stateExit("nebula-isolated")
		n.stateExit("nebula-pmtu-blackhole")
	}

	if reason == "" {
		n.nebulaFails, n.nebulaDpFail = 0, 0
		n.cycles.WithLabelValues(checkNebula, "ok").Inc()
		return
	}
	fails := &n.nebulaFails
	if dpFail {
		fails = &n.nebulaDpFail
	}
	*fails++
	if *fails >= n.cfg.ConsecNeeded &&
		n.rateOK("last-nebula-restart", n.cfg.MinRestart) {
		n.appendLog(fmt.Sprintf("ACTION: restarting nebula@%s - %s (persisted %dx)",
			net, reason, *fails))
		n.rateSpend("last-nebula-restart")
		n.nebulaFails, n.nebulaDpFail = 0, 0
		n.nebulaRestart(ctx)
	} else {
		// Key on the reason's leading token so a persisting cause
		// throttles to the cadence while a NEW cause still logs at
		// once.
		n.suspectLog(strings.SplitN(reason, " ", 2)[0], fmt.Sprintf(
			"suspect: %s (check %d/%d)",
			reason, *fails, n.cfg.ConsecNeeded))
	}
	n.cycles.WithLabelValues(checkNebula, "ok").Inc()
}

// checkNebulaPMTU is the W9-NM1 double-encapsulation PMTU probe:
// small-packet overlay pings keep passing while a 1200-byte
// don't-fragment probe blackholes — the signature of a path MTU
// below the overlay's (nebula-in-nebula / wg-in-overlay double
// encapsulation leaves less headroom than the overlay MTU
// advertises). The probe only runs when at least one overlay
// target answered the normal small pings — total overlay failure
// is the isolated/degraded verdict's job, not a PMTU latch.
// ConsecNeeded consecutive DF failures latch
// state-nebula-pmtu-blackhole; a passing probe (or no alive
// target) clears it.
func (n *NetHealth) checkNebulaPMTU(ctx context.Context,
	targets []string, results map[string]pingResult) {
	target := ""
	for _, t := range targets {
		if results[t].ok {
			target = t
			break
		}
	}
	if target == "" {
		// No alive overlay peer this cycle — the isolation /
		// degraded verdicts own the diagnosis; a PMTU streak
		// cannot be measured without a reachable target.
		n.pmtuFails = 0
		n.stateExit("nebula-pmtu-blackhole")
		return
	}
	out, err := n.cfg.runHostCmd(ctx, []string{
		"ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1200", target})
	if err != nil {
		n.pmtuFails++
		n.suspectLog("nebula-pmtu-blackhole", fmt.Sprintf(
			"suspect: nebula-pmtu-blackhole df_probe_failed target=%s size=1200 (check %d/%d): %v (%s)",
			target, n.pmtuFails, n.cfg.ConsecNeeded, err,
			trimRunErr(out)))
		if n.pmtuFails >= n.cfg.ConsecNeeded {
			n.stateEnter("nebula-pmtu-blackhole",
				fmt.Sprintf("target=%s df_size=1200", target))
		}
		return
	}
	n.pmtuFails = 0
	n.stateExit("nebula-pmtu-blackhole")
}

// --- Check: fail2ban (50-fail2ban.sh) ---

// jailRe extracts the jail list / banned counts from
// fail2ban-client status output.
var (
	jailListRe = regexp.MustCompile(`Jail list:\s*(.+)`)
	bannedRe   = regexp.MustCompile(`Currently banned:\s*([0-9]+)`)
)

// checkFail2ban — unit installed but service down → fail2ban-down
// latch; per-jail banned counts go to fail2ban-banned for the
// node_fail2ban_banned_ips metric.
func (n *NetHealth) checkFail2ban(ctx context.Context) {
	if n.cfg.Systemd == nil {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	// Fail closed like coredns-stub: a failed existence probe counts
	// as present (the check still runs its other evidence — the
	// banned-metrics collector below does not need systemd), and a
	// failed is-active leaves the down-latch untouched rather than
	// entering or clearing it on a guess.
	exists, err := n.cfg.Systemd.Exists(ctx, "fail2ban.service")
	if err != nil {
		logger().Warn("nethealth: fail2ban existence probe failed — "+
			"treating unit as present this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
		exists = true
	}
	if !exists {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "fail2ban.service")
	if err != nil {
		logger().Warn("nethealth: fail2ban is-active probe failed — "+
			"down-latch left unchanged this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
	} else if !active {
		n.suspectLog("fail2ban-down",
			"suspect: fail2ban-down (unit exists but service inactive)")
		n.stateEnter("fail2ban-down", "service=inactive")
		// A stopped jail protects nothing — restart it under the
		// last-fail2ban-restart budget (30m) instead of only latching.
		if n.rateOK("last-fail2ban-restart", f2bRestartInterval) {
			n.appendLog("ACTION: restarting fail2ban.service - unit exists but service inactive")
			n.rateSpend("last-fail2ban-restart")
			if err := n.cfg.Systemd.Restart(ctx, "fail2ban.service"); err != nil {
				n.appendLog(fmt.Sprintf("fail2ban.service restart failed: %v", err))
			} else {
				n.actions.WithLabelValues(checkF2B, "restart").Inc()
			}
		}
	} else {
		n.stateExit("fail2ban-down")
	}
	bannedFile := filepath.Join(n.cfg.WatchdogStateDir, "fail2ban-banned")
	out, err := n.cfg.runMountCmd(ctx, []string{"fail2ban-client", "status"})
	if err != nil {
		// Client missing/failed → remove the metric file (no stale
		// series — absent, not 0).
		n.suspectLog("fail2ban-client", fmt.Sprintf(
			"fail2ban: fail2ban-client status failed: %v (%s) — banned metrics dropped",
			err, trimRunErr(out)))
		_ = os.Remove(bannedFile)
		n.cycles.WithLabelValues(checkF2B, "ok").Inc()
		return
	}
	var pairs []string
	if m := jailListRe.FindStringSubmatch(out); m != nil {
		for _, j := range strings.Split(m[1], ",") {
			j = strings.TrimSpace(j)
			if j == "" {
				continue
			}
			cnt := "0"
			// runMountCmd (nsenter -t 1 -m -n) like the aggregate
			// call — fail2ban-client and its socket only exist on
			// the host, so runHostCmd (netns only) can never reach
			// them containerized and the jail silently read "0".
			st, err := n.cfg.runMountCmd(ctx,
				[]string{"fail2ban-client", "status", j})
			if err != nil {
				logger().Warn("nethealth: fail2ban per-jail status "+
					"failed — banned count reported as 0",
					"jail", j,
					"output", trimRunErr(st), "error", err)
			} else if b := bannedRe.FindStringSubmatch(st); b != nil {
				cnt = b[1]
			}
			pairs = append(pairs, j+"="+cnt)
		}
	}
	if len(pairs) > 0 {
		if err := writeFileAtomic(bannedFile,
			strings.Join(pairs, " ")+"\n"); err != nil {
			logger().Warn("nethealth: fail2ban banned-count write "+
				"failed — node_fail2ban_banned_ips stale this cycle",
				"path", bannedFile,
				"error", err)
		}
	} else {
		_ = os.Remove(bannedFile)
	}
	n.cycles.WithLabelValues(checkF2B, "ok").Inc()
}

// --- Check: clock-sync (H1) ---

// checkClockSync — H1: the kernel's own clock discipline via a
// read-only adjtimex(2) (modes==0 needs no CAP_SYS_TIME). The clock
// is unhealthy when the kernel reports STA_UNSYNC (no sync source
// achieved) or the estimated error exceeds 500ms — a silently
// drifting clock breaks TLS/cert verification and raft leases long
// before anything else on the node notices.
//
// Consecutive failing cycles >= ConsecNeeded arm the clock-unsync
// latch and — under the 30m last-ntp-restart budget — restart the
// node's sync daemon (whichever of timesyncd/chrony/chronyd is
// installed). An adjtimex error aborts the cycle WITHOUT touching
// the counter: an EPERM/seccomp-blocked read must not false-latch.
func (n *NetHealth) checkClockSync(ctx context.Context) {
	var tx unix.Timex
	if _, err := n.cfg.adjtimexFn(&tx); err != nil {
		n.suspectLog("clock-adjtimex",
			fmt.Sprintf("clock-sync: adjtimex failed: %v", err))
		n.cycles.WithLabelValues(checkClock, "abort").Inc()
		return
	}
	bad := ""
	switch {
	case tx.Status&unix.STA_UNSYNC != 0:
		bad = "kernel reports STA_UNSYNC"
	case tx.Esterror > clockMaxEsterrorUS:
		bad = fmt.Sprintf("esterror %dus exceeds %dus",
			tx.Esterror, clockMaxEsterrorUS)
	}
	if bad == "" {
		n.clockFails = 0
		n.stateExit("clock-unsync")
		n.cycles.WithLabelValues(checkClock, "ok").Inc()
		return
	}
	n.clockFails++
	if n.clockFails < n.cfg.ConsecNeeded {
		n.appendLog(fmt.Sprintf("suspect: clock-unsync %s (check %d/%d)",
			bad, n.clockFails, n.cfg.ConsecNeeded))
		n.cycles.WithLabelValues(checkClock, "ok").Inc()
		return
	}
	n.stateEnter("clock-unsync", bad)
	if n.rateOK("last-ntp-restart", ntpRestartInterval) {
		n.restartNTPDaemon(ctx)
	} else {
		n.suspectLog("clock-unsync", "suspect: clock-unsync persists "+
			"but ntp restart cooldown (<30m), skip")
	}
	n.cycles.WithLabelValues(checkClock, "ok").Inc()
}

// restartNTPDaemon restarts whichever clock-sync daemon the node
// runs — systemd-timesyncd (Debian/Ubuntu) or chrony/chronyd — under
// the last-ntp-restart budget. The budget is spent on the restart
// attempt itself; a node without any sync unit only gets the latch
// (the daemon may be managed by other means).
func (n *NetHealth) restartNTPDaemon(ctx context.Context) {
	if n.cfg.Systemd == nil {
		n.suspectLog("ntp-no-systemd",
			"ntp restart skipped — no systemd client")
		return
	}
	// Pick the node's ACTUAL sync daemon, not just an installed one:
	// timesyncd's unit file ships with systemd on every
	// Debian/Ubuntu host — installed ≠ in use — so UnitExists alone
	// would restart a disabled timesyncd on a chrony node and give
	// the box two clock-discipline daemons fighting over adjtimex.
	// Preference: enabled+active (the live daemon), then
	// enabled-only (crashed — needs the restart most), then
	// active-only (live but unmanaged enablement). A unit that
	// merely exists never qualifies.
	units := []string{
		"systemd-timesyncd.service", "chrony.service", "chronyd.service",
	}
	pick := ""
	for _, u := range units {
		if n.unitEnabledActive(ctx, u) {
			pick = u
			break
		}
	}
	if pick == "" {
		for _, u := range units {
			if n.cfg.Systemd.IsEnabled(ctx, u) {
				pick = u
				break
			}
		}
	}
	if pick == "" {
		for _, u := range units {
			if n.cfg.Systemd.IsActive(ctx, u) {
				pick = u
				break
			}
		}
	}
	if pick == "" {
		// The restart budget is intentionally NOT spent here —
		// there is nothing to restart — but the line is cadence-
		// throttled so a unit-less node doesn't re-log every cycle.
		n.suspectLog("no-sync-unit", "clock-unsync but no "+
			"enabled/active sync unit found (timesyncd/chrony/"+
			"chronyd all disabled or absent)")
		return
	}
	n.appendLog(fmt.Sprintf(
		"ACTION: restarting %s - clock unsynchronized (persisted %dx)",
		pick, n.clockFails))
	n.rateSpend("last-ntp-restart")
	if err := n.cfg.Systemd.Restart(ctx, pick); err != nil {
		n.appendLog(fmt.Sprintf("%s restart failed: %v", pick, err))
		return
	}
	n.actions.WithLabelValues(checkClock, "restart").Inc()
}

// --- Check: conntrack-guard (H2) ---

// checkConntrack — H2: nf_conntrack table pressure. Once the table
// fills, the NAT path drops NEW connections silently (nf_conntrack:
// table full, dropping packet) — a classic gray failure: established
// flows keep working while everything new blackholes. The latch arms
// above 0.90 used and only clears below 0.80 so a hovering counter
// can't flap it. Missing /proc entries mean the module isn't loaded
// → no table to pressure, drop any stale latch.
func (n *NetHealth) checkConntrack(ctx context.Context) {
	usedStr := readFile(n.cfg.ConntrackCountFile)
	maxStr := readFile(n.cfg.ConntrackMaxFile)
	if usedStr == "" || maxStr == "" {
		n.stateExit("conntrack-pressure")
		n.cycles.WithLabelValues(checkCT, "gated").Inc()
		return
	}
	used, errU := strconv.ParseFloat(usedStr, 64)
	max, errM := strconv.ParseFloat(maxStr, 64)
	if errU != nil || errM != nil || max <= 0 {
		n.suspectLog("conntrack-parse", fmt.Sprintf(
			"conntrack-guard: unparseable conntrack values count=%q max=%q — cycle aborted",
			usedStr, maxStr))
		n.cycles.WithLabelValues(checkCT, "abort").Inc()
		return
	}
	ratio := used / max
	if n.stateExists("conntrack-pressure") {
		if ratio < conntrackExitRatio {
			n.appendLog(fmt.Sprintf(
				"conntrack-pressure cleared (used=%.0f max=%.0f ratio=%.2f)",
				used, max, ratio))
			n.stateExit("conntrack-pressure")
		}
	} else if ratio > conntrackEnterRatio {
		n.appendLog(fmt.Sprintf(
			"suspect: conntrack-pressure used=%.0f max=%.0f ratio=%.2f > %.2f",
			used, max, ratio, conntrackEnterRatio))
		n.stateEnter("conntrack-pressure",
			fmt.Sprintf("used=%.0f max=%.0f ratio=%.2f", used, max, ratio))
	}
	n.cycles.WithLabelValues(checkCT, "ok").Inc()
}

// flushPeerNebulaConntrack drops stale udp/<nebula-port> conntrack
// entries bound to specific peer underlay IPs — B3: after a peer
// becomes isolated (state-nebula-isolated) or its egress path just
// switched (overlay-egress direct↔relay), conntrack entries learned
// on the dead path pin the tunnel until expiry. Deleting only the
// affected peers' entries forces an immediate Nebula re-handshake on
// the new path without touching healthy peers' flows.
// Best-effort like flushStaleUDPConntrack — a missing conntrack
// binary or a denied delete logs and moves on, never fails a cycle.
// check attributes the flush to the calling check (conntrack-guard
// is only the table-pressure probe).
func (n *NetHealth) flushPeerNebulaConntrack(ctx context.Context, check string, peers ...string) {
	port := n.cfg.Watchdog.NebulaPort
	if port <= 0 {
		port = 45670
	}
	dport := strconv.Itoa(port)
	seen := map[string]bool{}
	for _, p := range peers {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		// Both tuple directions must go: `-d <peer>` evicts flows WE
		// initiated toward the peer; `-s <peer>` evicts peer-initiated
		// flows (orig src=peer -> our IP:<port>) whose surviving reply
		// direction would otherwise keep our outbound packets pinned
		// on the dead path. Same runMountCmd seam as
		// flushStaleUDPConntrack — the host's conntrack binary on the
		// real conntrack table; each delete is independently
		// best-effort (no-match is a fine "failure").
		for _, sel := range [][]string{{"-d", p}, {"-s", p}} {
			args := append([]string{"conntrack", "-D", "-p", "udp",
				"--dport", dport}, sel...)
			out, err := n.cfg.runMountCmd(ctx, args)
			if err != nil {
				n.appendLog(fmt.Sprintf("conntrack nebula-peer flush %s skipped: %v (%s) [%s]",
					p, err, trimRunErr(out), sel[0]))
				continue
			}
			n.actions.WithLabelValues(check, "flush_peer").Inc()
		}
		n.appendLog(fmt.Sprintf(
			"ACTION: flushed stale udp/%d conntrack entries for peer %s", port, p))
	}
}

// nebulaPeerUnderlayIPs returns the peer underlay IPs the watchdog
// conf knows about — OVERLAY_PROBE_TARGETS (remote public IPs probed
// through the tunnel) plus OVERLAY_EGRESS_RELAYS (relay peers). These
// are the -d destinations conntrack records for udp/<nebula-port>
// flows; marker IPs are overlay addresses conntrack never sees.
func nebulaPeerUnderlayIPs(wd *watchdogconf.Config) []string {
	out := append([]string{}, wd.OverlayProbeTargets...)
	return append(out, wd.OverlayEgressRelays...)
}

// flushStaleUDPConntrack drops stale udp/53 conntrack entries after
// a DNS-path transition (dns-fallback pins written, coredns-stub or
// nebula@ just restarted). NATed DNS replies bound to a now-dead
// endpoint's conntrack entry keep blackholing lookups until the
// entry expires — deleting them makes the fix effective immediately.
// Best-effort only: a missing conntrack binary or a denied delete
// logs and moves on, it never fails the cycle. check attributes the
// flush to the calling check.
func (n *NetHealth) flushStaleUDPConntrack(ctx context.Context, check string) {
	// runMountCmd (nsenter -t 1 -m -n) is required — runHostCmd only
	// joins the host NET namespace, so `conntrack` would resolve
	// against the container image (which does not ship
	// conntrack-tools). The host mount ns reaches the host binary;
	// the host net ns operates on the real conntrack table.
	out, err := n.cfg.runMountCmd(ctx,
		[]string{"conntrack", "-D", "-p", "udp", "--dport", "53"})
	if err != nil {
		n.appendLog(fmt.Sprintf("conntrack udp/53 flush skipped: %v (%s)",
			err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(check, "flush").Inc()
	n.appendLog("ACTION: flushed stale udp/53 conntrack entries")
}
