// config.go — the nethealth knobs: the Defaults table, the Config
// struct and applyDefaults' env→contract resolution. Split out of
// nethealth.go.
package nethealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Defaults mirror the shell modules + DaemonSet host mounts.
const (
	defaultInterval     = 2 * time.Minute
	defaultConsecNeeded = 2
	defaultMinRestart   = 30 * time.Minute
	defaultHostRoot     = "/"
	defaultSysClassNet  = "/sys/class/net"
	minUptimeSeconds    = 300

	// suspectLogCadence throttles repeat suspect lines so a
	// persisting cause doesn't spam the watchdog log every cycle
	// for weeks (controllerhygiene's suspectLog parity).
	suspectLogCadence = time.Hour

	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile  = "/host/var/log/node-watchdog.log"
	// The resolv/hosts defaults hardcode the "/host" prefix — the
	// DaemonSet mount layout (config_env.go's hostPath joins are the
	// standalone-correct env defaults; applyDefaults only backstops
	// hand-rolled Configs).
	defaultHostResolvConf     = "/host/etc/resolv.conf"
	defaultHostsFile          = "/host/etc/hosts"
	defaultProcNetUDP         = "/proc/1/net/udp"
	defaultProcNetUDP6        = "/proc/1/net/udp6"
	defaultUptimeFile         = "/proc/uptime"
	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"
	// /proc/1/net/ — the host net namespace under hostPID:true
	// (same contract as the ProcNetUDP{,6} defaults above).
	defaultConntrackStatFile = "/proc/1/net/stat/nf_conntrack"
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
	// Base is the shared watchdog-subsystem block — the cadence,
	// state dir/log, host root, systemd client, watchdog conf +
	// reloader and clock splice (subframe.FromDeps).
	subframe.Base
	HostResolvConf     string // host resolv.conf (DNS probe source)
	HostsFile          string // host /etc/hosts (managed block)
	ProcNetUDP         string // host /proc/1/net/udp (socket check)
	ProcNetUDP6        string // host /proc/1/net/udp6
	UptimeFile         string // host /proc/uptime (20/21 gate)
	ConntrackCountFile string // nf_conntrack_count (entries used)
	ConntrackMaxFile   string // nf_conntrack_max (table size)
	// ConntrackStatFile is /proc/net/stat/nf_conntrack — the
	// per-CPU insert_failed/drop counters the conntrack-port-pressure spike
	// detector reads (module absent → no file → detector idles).
	ConntrackStatFile string
	ConsecNeeded      int
	MinRestart        time.Duration
	// NebulaDirectTCPPorts is the nebula_direct_tcp_ports list the
	// pref-1499 route guard enforces — TCP dport on these ports
	// bypasses the overlay (direct underlay). Nil → the default
	// [22 6443 8132 9443 39901].
	NebulaDirectTCPPorts []int
	// TextfileDir is the node-exporter drop dir (NODE_HOST_AGENT_
	// TEXTFILE_DIR via hostctx) — "" falls back to the HostRoot-
	// derived dir the MTU blackhole gauge used before the env
	// override existed.
	TextfileDir string

	// Seams — nil gets production defaults.
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
	// socket factory — default is subsystem/nethealth/routewatch.Bind: binds
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
	// rulesFn dumps pid's policy-routing rules through netlink —
	// the Go-native replacement for the overlay-egress check's two
	// `ip rule list` nsenter forks per cycle (netlinkx.Rules binds
	// a handle inside the host netns). Writes (rule add/del) stay
	// on runHostCmd — netlinkx is read-only by contract.
	rulesFn func(pid int) ([]netlink.Rule, error)
	// linkAddrsFn lists the addresses on one link in pid's netns —
	// the netlinkx read behind the nebula tun-address probe (the
	// `ip -o addr show dev` fork replacement). Same rulesFn
	// contract: reads only, pid 1 = host netns.
	linkAddrsFn func(pid int, name string) ([]netlink.Addr, error)
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
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
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
				// Pass the resolver's network through — the stub
				// retries TCP when a UDP answer comes back
				// truncated (TC bit); pinning UDP would downgrade
				// that retry to a second truncating query and
				// misread a healthy resolver as dead.
				Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(dctx, network, net.JoinHostPort(nameserver, "53"))
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
		// insecure-TLS client is a superset with zero delta. The
		// closure adapts the seam type to HTTPGet's variadic
		// optional client (default package client, nil injected).
		c.probeHTTP = func(ctx context.Context, url string,
			timeout time.Duration) error {
			return probee.HTTPGet(ctx, url, timeout)
		}
	}
	if c.sysClassNet == "" {
		c.sysClassNet = defaultSysClassNet
	}
	if c.rulesFn == nil {
		c.rulesFn = netlinkx.Rules
	}
	if c.linkAddrsFn == nil {
		c.linkAddrsFn = netlinkx.LinkAddrs
	}
	if c.adjtimexFn == nil {
		c.adjtimexFn = unix.Adjtimex
	}
}
