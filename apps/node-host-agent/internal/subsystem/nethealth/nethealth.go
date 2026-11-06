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
// platform/hostexec nsenter-wraps them into host PID 1's namespaces
// when containerized, plain exec on the host — and are fully
// fakeable in tests. DNS and TCP probes are Go-native and
// injectable.
package nethealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
	purgeBudget             = time.Hour // shell last-purge-* rate window
	// suspectLogCadence is the re-reminder interval suspectLog
	// applies to suspect/hold lines whose condition persists:
	// STATE-ENTER announces the transition and the raw line then
	// repeats at most this often — a held condition must not re-log
	// every cycle for weeks (controllerhygiene's suspectLog parity).
	suspectLogCadence = time.Hour

	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"
	// W12-KR3: the per-CPU conntrack stat table — insert_failed /
	// drop / early_drop column sums drive the stale-UDP flush.
	defaultConntrackStatFile = "/proc/net/stat/nf_conntrack"
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

// Config carries the nethealth knobs — all test-injectable. Per-node
// values come from Watchdog (the parsed node-watchdog.conf); nil →
// empty config (every check idles on defaults like the shell did on
// nodes without a conf file).
type Config struct {
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
	// ConntrackStatFile is /proc/net/stat/nf_conntrack — the
	// per-CPU insert_failed/drop counters the W12-KR3 spike
	// detector reads (module absent → no file → detector idles).
	ConntrackStatFile string
	HostRoot          string // "/" = already on host (no nsenter)
	Watchdog          *watchdogconf.Config
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
	// runHostCmd executes a host binary (ip, ping): hostexec NSNet —
	// nsenter -t 1 -n -- <argv> when HostRoot != "/", plain exec on
	// the host itself. Netns only — the binaries are shipped in the
	// container image.
	runHostCmd func(ctx context.Context, argv []string) (string, error)
	// runMountCmd is runHostCmd with the host mount ns (hostexec
	// NSMountNet): needed for binaries+state that only exist on the
	// host, e.g. fail2ban-client talking to
	// /run/fail2ban/fail2ban.sock.
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
	// socket factory — default is platform/routewatch.Bind: binds
	// RTMGRP_IPV4_ROUTE|RTMGRP_IPV4_RULE in the host netns, directly
	// when the pod netns IS the host's (hostNetwork, same inode as
	// /proc/1/ns/net), else setns into pid-1's netns (hostPID — no
	// /host/proc mount needed).
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
	if c.ConntrackStatFile == "" {
		c.ConntrackStatFile = defaultConntrackStatFile
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
	// Both host-exec defaults share one platform/hostexec Runner —
	// the single nsenter seam: NSNet for binaries shipped in the
	// container image (ip, ping — the old `-t 1 -n`), NSMountNet for
	// host-only binaries and their host state (fail2ban-client,
	// conntrack, nebula-up.sh — the old `-t 1 -m -n`). ExecCombined
	// keeps the old CombinedOutput contract — caller-visible output
	// includes stderr (trimRunErr diagnostics) — and the default
	// 30s timeout matches the previous inline bound. The Config
	// fields stay the call indirection so tests can still re-stub
	// n.cfg.runHostCmd/runMountCmd after New.
	hostRunner := hostexec.New(hostexec.Config{HostRoot: c.HostRoot})
	if c.runHostCmd == nil {
		c.runHostCmd = func(ctx context.Context, argv []string) (string, error) {
			return hostRunner.ExecCombined(ctx, hostexec.NSNet,
				argv[0], argv[1:]...)
		}
	}
	if c.runMountCmd == nil {
		c.runMountCmd = func(ctx context.Context, argv []string) (string, error) {
			return hostRunner.ExecCombined(ctx, hostexec.NSMountNet,
				argv[0], argv[1:]...)
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
					err = errors.New("no A records")
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
		// probee.HTTPGet is the old probeHTTPGet verbatim — the
		// nebula stats target is plaintext http so the shared
		// insecure-TLS client is a superset with zero delta.
		c.probeHTTP = probee.HTTPGet
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

	// state is the shared hoststate Store — every state-*/last-*/
	// dnsfb-*/egress-*/fail2ban-* file and the watchdog log append
	// goes through it (the single lib.sh-parity implementation).
	state *hoststate.Store

	dnsfails     map[string]int // per DNS_FALLBACK_MAP name
	nebulaFails  int            // socket/tun/stats fails
	nebulaDpFail int            // dataplane-dead fails
	nebulaDeg    int            // dataplane-degraded runs
	pmtuFails    int            // consecutive DF-probe failures (W9-NM1)
	clockFails   int            // consecutive unsynced adjtimex reads
	egressCtr    map[string]int // per relay probe!=committed counter
	// nebulaSiteedgeRun counts consecutive cycles the siteedge
	// marker set keeps failing — the siteedge LATCH arms on the
	// first detection, but the W12-NM2 per-peer conntrack flush
	// waits for ConsecNeeded confirmed runs like the degraded path.
	nebulaSiteedgeRun int
	// ctStatPrev is the last-cycle sum of the nf_conntrack
	// insert_failed+drop+early_drop columns; ctStatSeen separates
	// "first read" (baseline only) from a real delta — the spike
	// detector must not flush on a counter jump across an agent
	// restart vs an unset baseline.
	ctStatPrev uint64
	ctStatSeen bool

	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action

	// groups is the ordered per-Cycle dispatch table — initChecks
	// fills it; the order + the uptime-gated first group preserve
	// the shell runner's module order (20/21 alone carried
	// WD_REQUIRES:uptime).
	groups []checks.Group

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
	// The Now closure must read n.cfg.nowFn at call time — tests
	// re-stub the clock after New() and the store has to observe it
	// (hoststate.Store.Now contract; controllerhygiene parity).
	n.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return n.cfg.nowFn() }, logger)
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
	n.initChecks()
	return n, nil
}

// Name identifies the subsystem for logging.
func (n *NetHealth) Name() string { return "nethealth" }

// Run checks immediately, then every Interval until ctx is cancelled.
func (n *NetHealth) Run(ctx context.Context) {
	// Route guard: netlink-driven restore of the nebula policy
	// routing (replaces nebula-route-guard.service). Single-flight
	// via spawnRouteGuard — overlapping Runs can't double-bind the
	// socket, but a guard that died (recovered panic) is re-armed
	// by the next spawn attempt instead of staying dead forever.
	// No-ops on nodes without
	// <HostRoot>/etc/nebula/<net>/nebula-up.sh (plain workers) or
	// while `systemctl is-active nebula@<net>` is down.
	n.spawnRouteGuard(ctx)
	cycle.Every("nethealth", n.cfg.Interval, func(ctx context.Context) {
		// Re-arm a dead guard every tick — a panic must not
		// leave route deletes unmonitored until the next
		// full Run restart.
		n.spawnRouteGuard(ctx)
		n.Cycle(ctx)
	}).Run(ctx)
}

// initChecks builds the ordered dispatch table Cycle drives — the
// workerhygiene initChecks pattern. Order + grouping are
// load-bearing: the uptime gate covers ONLY the two DNS modules
// (20/21 carried WD_REQUIRES: uptime); the rest ran regardless,
// like the shell runner. Each entry's Name is the check* constant —
// the prometheus `check` label AND the WD_SIG_<NAME> key.
func (n *NetHealth) initChecks() {
	n.groups = []checks.Group{
		{
			GateOK: n.uptimeOK,
			Entries: []checks.Entry{
				{Name: checkDNSFB, Run: n.checkDNSFallback},
				{Name: checkCoreDNS, Run: n.checkCoreDNSStub},
			},
		},
		{
			Entries: []checks.Entry{
				{Name: checkEgress, Run: n.checkOverlayEgress},
				{Name: checkNebula, Run: n.checkNebulaHealth},
				{Name: checkF2B, Run: n.checkFail2ban},
				{Name: checkClock, Run: n.checkClockSync},
				{Name: checkCT, Run: n.checkConntrack},
				{Name: checkNebTCP, Run: n.checkNebulaDirectTCP},
			},
		},
	}
}

// uptimeOK is the 20/21 WD_REQUIRES:uptime group gate — a read
// error opens it (the shell's `[ $UP -lt $MIN ]` test on an empty
// UPTIME failed the same way: the modules ran).
func (n *NetHealth) uptimeOK() bool {
	up, err := hostutil.UptimeSeconds(n.cfg.UptimeFile)
	return err != nil || up >= minUptimeSeconds
}

// Cycle runs one round of all checks through the declared dispatch
// table. Each check honours the runner's per-module kill switch:
// WD_SIG_<NAME>=off in the conf skips it (SignalEnabled), and the
// conf is re-read every cycle when WatchdogSrc is wired (hostconfig
// rewrites land next cycle).
func (n *NetHealth) Cycle(ctx context.Context) {
	// Deferred so even an early-returned cycle proves the loop is
	// alive (BUG-H1 — Store.StampLastRun no-ops on an empty dir).
	defer n.state.StampLastRun()
	if n.cfg.WatchdogSrc != nil {
		n.cfg.Watchdog = n.cfg.WatchdogSrc.Get()
	}
	sigOn := func(name string) bool {
		return n.cfg.Watchdog == nil || n.cfg.Watchdog.SignalEnabled(name)
	}
	checks.Dispatch(ctx, sigOn, n.cycles, n.groups)
}

// --- watchdog file helpers (lib.sh parity) ---
//
// The on-disk contract itself lives in platform/hoststate — n.state
// is the single Store implementation of state_enter/state_exit,
// rate_ok/rate_spend, the last-suspect-* dedupe budgets, the
// watchdog log append and the last-run stamp (BUG-H1). Atomic file
// writes go through platform/hostutil.

// stateExit removes state-<name> if present and logs the
// transition — clears the NPD permanent condition — plus the
// nethealth divergence, named on the Store:
// Store.ExitClearAllSuspects drops the WHOLE last-suspect-* family
// with the latch. The NON-latch keys (egress-probe-<ip>,
// conntrack-parse, clock-adjtimex, ...) have no state-* twin to exit
// with, so a cleared condition would otherwise suppress the first
// line of a re-incident for up to suspectLogCadence — a latch exit
// IS an incident boundary; a still-held condition pays at most one
// early re-log line.
func (n *NetHealth) stateExit(name string) {
	n.state.ExitClearAllSuspects(name)
}

// --- shared helpers ---

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

// unitActive mirrors `systemctl is-enabled + is-active` — the
// runner's overlay-active probes (WD_NEBULA_ACTIVE/WD_TINC_ACTIVE).
func (n *NetHealth) unitEnabledActive(ctx context.Context, unit string) bool {
	if n.cfg.Systemd == nil {
		return false
	}
	return n.cfg.Systemd.IsEnabled(ctx, unit) && n.cfg.Systemd.IsActive(ctx, unit)
}
