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
// Host commands (ip/ping/fail2ban-client) run through one seam —
// nsenter-wrapped into the host net namespace when containerized,
// plain exec on the host — and are fully fakeable in tests. DNS and
// TCP probes are Go-native and injectable.
package nethealth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
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
	defaultConsecNeeded     = 2
	defaultMinRestart       = 30 * time.Minute
	corednsRestartInterval  = 5 * time.Minute
	purgeBudget             = time.Hour // shell last-purge-* rate window
)

// Check names — prometheus `check` label + log context.
const (
	checkDNSFB   = "dns-fallback"
	checkCoreDNS = "coredns-stub"
	checkEgress  = "overlay-egress"
	checkNebula  = "nebula-health"
	checkF2B     = "fail2ban"
)

const hostsBlockBegin = "# BEGIN node-watchdog-dns"
const hostsBlockEnd = "# END node-watchdog-dns"

// Config carries the nethealth knobs — all test-injectable. Per-node
// values come from Watchdog (the parsed node-watchdog.conf); nil →
// empty config (every check idles on defaults like the shell did on
// nodes without a conf file).
type Config struct {
	Enabled          bool          // false → Run idles until ctx done
	Interval         time.Duration // check cadence
	WatchdogStateDir string        // state-*/egress-*/dnsfb-* files
	WatchdogLogFile  string        // appended watchdog log (NPD filelog)
	HostResolvConf   string        // host resolv.conf (DNS probe source)
	HostsFile        string        // host /etc/hosts (managed block)
	ProcNetUDP       string        // host /proc/1/net/udp (socket check)
	ProcNetUDP6      string        // host /proc/1/net/udp6
	UptimeFile       string        // host /proc/uptime (20/21 gate)
	HostRoot         string        // "/" = already on host (no nsenter)
	Watchdog         *watchdogconf.Config
	// WatchdogSrc, when set, re-reads the conf file every Cycle so
	// hostconfig rewrites (OVERLAY_*, DNS_FALLBACK_MAP, WD_SIG_*
	// kill switches) apply live instead of only at agent start.
	WatchdogSrc  *watchdogconf.Reloader
	Systemd      *systemd.Client // nil → systemd checks degrade keep-only
	ConsecNeeded int
	MinRestart   time.Duration

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
}

// NetHealth runs the network checks on one ticker.
type NetHealth struct {
	cfg Config

	dnsfails     map[string]int // per DNS_FALLBACK_MAP name
	nebulaFails  int            // socket/tun/stats fails
	nebulaDpFail int            // dataplane-dead fails
	nebulaDeg    int            // dataplane-degraded runs
	egressCtr    map[string]int // per relay probe!=committed counter

	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action
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
		Help: "Net-health check cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	n.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_nethealth_actions_total",
		Help: "Net-health remediation actions by check and action " +
			"(pin|unpin|restart|rule_add|rule_del|kill).",
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
		<-ctx.Done()
		return
	}
	n.Cycle(ctx)
	t := time.NewTicker(n.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
}

// --- watchdog file helpers (lib.sh parity — same contract as
// workerhygiene's: state-* latches, last-* budgets, log + slog) ---

func (n *NetHealth) appendLog(msg string) {
	slog.Info(msg, "subsystem", "nethealth")
	f, err := os.OpenFile(n.cfg.WatchdogLogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
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

func (n *NetHealth) stateEnter(name, extra string) {
	p := n.statePath(name)
	if _, err := os.Stat(p); err == nil {
		return
	}
	content := strconv.FormatInt(n.cfg.nowFn().Unix(), 10) + "\n"
	tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
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
		return
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
	_ = os.WriteFile(p, []byte(content), 0o644)
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
		return false
	}
	cur := string(data)
	var kept []string
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
		if !inBlock {
			kept = append(kept, line)
		}
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
	return os.WriteFile(n.cfg.HostsFile, []byte(next), 0o644) == nil
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
			if ip, err := n.cfg.dnsProbe(ctx, server, e.Name); err == nil && ip != "" {
				resolved = ip
				break
			}
		}
		if resolved != "" {
			if readFile(lg) != resolved {
				_ = os.WriteFile(lg, []byte(resolved+"\n"), 0o644)
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
				"suspect: dns-resolve %s fail qua resolv.conf (check %d/%d)",
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
				_ = os.WriteFile(pinf, []byte(newIP+" "+e.Name+"\n"), 0o644)
				n.actions.WithLabelValues(checkDNSFB, "pin").Inc()
			} else if curIP == "" {
				n.appendLog(fmt.Sprintf(
					"suspect: dns-fallback %s — moi candidate deu unreachable, khong pin",
					e.Name))
			}
			// Dead pin with no replacement → keep it (a pinned dead
			// IP is no worse than NXDOMAIN and may come back).
		}
	}
	// Prune pin files for names removed from the map — the shell
	// also dropped the matching dnsfb-ctr-* counter (the lg
	// last-known-good file stays: it is still the best hint if the
	// name ever comes back).
	for _, f := range n.pinFiles() {
		name := strings.TrimPrefix(filepath.Base(f), "dnsfb-pin-")
		if !inMap[name] {
			_ = os.Remove(f)
			_ = os.Remove(filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-ctr-"+name))
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
		}
		n.stateEnter("dns-fallback", "")
	} else {
		if n.renderHostsBlock("") {
			n.appendLog("ACTION: /etc/hosts dns-fallback block removed (DNS OK)")
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
	if !loopback || n.cfg.Systemd == nil ||
		!n.cfg.Systemd.UnitExists("coredns.service") ||
		n.cfg.Systemd.IsActive(ctx, "coredns.service") {
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	if !n.rateOK("last-coredns-restart", corednsRestartInterval) {
		n.appendLog("suspect: coredns stub dead nhung restart cooldown (<5m), skip")
		n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
		return
	}
	n.appendLog("ACTION: restarting coredns - stub dead nhung resolv.conf tro 127.0.0.1")
	n.rateSpend("last-coredns-restart")
	if err := n.cfg.Systemd.Restart(ctx, "coredns.service"); err != nil {
		n.appendLog(fmt.Sprintf("coredns restart failed: %v", err))
	} else {
		n.actions.WithLabelValues(checkCoreDNS, "restart").Inc()
	}
	n.cycles.WithLabelValues(checkCoreDNS, "ok").Inc()
}

// --- Check: overlay-egress (12-overlay-egress.sh) ---

// ip runs the host `ip` tool through the runner seam.
func (n *NetHealth) ip(ctx context.Context, args ...string) (string, error) {
	return n.cfg.runHostCmd(ctx, append([]string{"ip"}, args...))
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
		n.cycles.WithLabelValues(checkEgress, "abort").Inc()
		return
	}
	if !strings.Contains(rules, "fwmark 0x2000") {
		_, _ = n.ip(ctx, "rule", "add", "pref", "1390", "fwmark", "0x2000", "lookup", "main")
	}
	rules1500, _ := n.ip(ctx, "rule", "list", "pref", "1500")

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
					"cleanup: egress %s rule lookup %d stale (table hien tai %d)", r, t, table))
			}
		}
		// Drift heal: live rule must match committed state (up/down
		// scripts can delete rules behind our back).
		if live != comm {
			if comm == "relay" {
				_, _ = n.ip(ctx, "rule", "add", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			} else {
				_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			}
			n.appendLog(fmt.Sprintf(
				"ACTION: heal egress %s rule -> %s table %d (was %s)", r, comm, table, live))
			live = comm
		}
		// Probe the underlay under SO_MARK 0x2000 → pref 1390 → main
		// table, unaffected by the relay rule.
		icmpBlk := filepath.Join(n.cfg.WatchdogStateDir, "egress-icmpblk-"+r)
		probe := "relay"
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
			if hadRule {
				_, _ = n.ip(ctx, "rule", "del", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
			}
			if n.cfg.tcpProbe(ctx, r, port, 5*time.Second) == nil {
				probe = "direct"
				if _, err := os.Stat(icmpBlk); err != nil {
					_ = os.WriteFile(icmpBlk,
						[]byte(strconv.FormatInt(n.cfg.nowFn().Unix(), 10)+"\n"), 0o644)
					n.appendLog(fmt.Sprintf(
						"egress %s: ICMP blocked nhung tcp/%s song — tinh direct (provider chan ICMP?)", r, port))
				}
			}
			if hadRule {
				_, _ = n.ip(ctx, "rule", "add", "pref", "1500", "to",
					r+"/32", "lookup", strconv.Itoa(table))
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
				_ = os.WriteFile(stf, []byte(probe+"\n"), 0o644)
				if probe == "relay" {
					n.appendLog(fmt.Sprintf(
						"ACTION: egress %s -> overlay relay table %d (direct failed)", r, table))
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
			} else {
				n.appendLog(fmt.Sprintf(
					"suspect: egress %s probe=%s cur=%s (check %d/%d)", r, probe, comm, ctr, need))
			}
		}
		// Serving via relay while the tunnel itself is unreachable →
		// the relay is dead too.
		if live == "relay" {
			if ok, _ := n.cfg.ping(ctx, r, 1, 4, false); !ok {
				n.appendLog(fmt.Sprintf("suspect: overlay-egress unreachable %s (relay down?)", r))
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
			"cleanup: egress state/rule cho %s (khong con trong OVERLAY_EGRESS_RELAYS)", ip))
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
		n.appendLog("nebula restart skipped — no systemd client")
		return
	}
	if err := n.cfg.Systemd.Restart(ctx, "nebula@"+net); err != nil {
		n.appendLog(fmt.Sprintf("nebula@%s restart failed: %v", net, err))
		return
	}
	n.actions.WithLabelValues(checkNebula, "restart").Inc()
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
		n.cycles.WithLabelValues(checkNebula, "gated").Inc()
		return
	}
	reason := ""
	dpFail := false // dataplane-dead counts its own counter
	switch {
	case !n.udpSocketBound(wd.NebulaPort):
		reason = fmt.Sprintf("nebula-no-socket udp/%d chua bound", wd.NebulaPort)
	case !n.hasIPv4Addr(ctx, wd.NebulaDev):
		reason = fmt.Sprintf("nebula-no-tun-addr dev=%s", wd.NebulaDev)
	case wd.NebulaStatsURL != "" &&
		n.cfg.probeHTTP(ctx, wd.NebulaStatsURL, 5*time.Second) != nil:
		reason = fmt.Sprintf("nebula-stats-dead %s", wd.NebulaStatsURL)
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
			n.appendLog(fmt.Sprintf(
				"suspect: nebula-dataplane-slowpath (reroute qua site xa) %s",
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
				n.appendLog(fmt.Sprintf(
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
			n.stateEnter("nebula-isolated", "dataplane dead")
		case dpTotal-dpAlive >= 2 || mkTotal-mkAlive >= 2:
			n.nebulaDeg++
			need := wd.NebulaDegradedConsec
			if need <= 0 {
				need = 2
			}
			n.appendLog(fmt.Sprintf(
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
	} else {
		// overlay != nebula (or no probe config): don't probe through
		// the other overlay — clear leftover dataplane states.
		n.nebulaDeg = 0
		n.stateExit("nebula-degraded")
		n.stateExit("nebula-slowpath")
		n.stateExit("nebula-siteedge")
		n.stateExit("nebula-isolated")
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
		n.appendLog(fmt.Sprintf("suspect: %s (check %d/%d)",
			reason, *fails, n.cfg.ConsecNeeded))
	}
	n.cycles.WithLabelValues(checkNebula, "ok").Inc()
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
	if n.cfg.Systemd == nil || !n.cfg.Systemd.UnitExists("fail2ban.service") {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	if !n.cfg.Systemd.IsActive(ctx, "fail2ban.service") {
		n.appendLog("suspect: fail2ban-down (unit co nhung service khong active)")
		n.stateEnter("fail2ban-down", "service=inactive")
	} else {
		n.stateExit("fail2ban-down")
	}
	bannedFile := filepath.Join(n.cfg.WatchdogStateDir, "fail2ban-banned")
	out, err := n.cfg.runMountCmd(ctx, []string{"fail2ban-client", "status"})
	if err != nil {
		// Client missing/failed → remove the metric file (no stale
		// series — absent, not 0).
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
			if st, err := n.cfg.runHostCmd(ctx,
				[]string{"fail2ban-client", "status", j}); err == nil {
				if b := bannedRe.FindStringSubmatch(st); b != nil {
					cnt = b[1]
				}
			}
			pairs = append(pairs, j+"="+cnt)
		}
	}
	if len(pairs) > 0 {
		_ = os.WriteFile(bannedFile,
			[]byte(strings.Join(pairs, " ")+"\n"), 0o644)
	} else {
		_ = os.Remove(bannedFile)
	}
	n.cycles.WithLabelValues(checkF2B, "ok").Inc()
}
