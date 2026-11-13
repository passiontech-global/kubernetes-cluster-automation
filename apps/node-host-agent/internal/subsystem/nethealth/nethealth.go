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
//
// The nebula checks live in the nebula subpackage (same log
// identity, deps bundle wired in nebula_bridge.go).
package nethealth

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/nebula"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

// Check names — prometheus `check` label + log context. The two
// nebula labels are owned by the nebula subpackage (the metric-name
// contract lives next to the code emitting them).
const (
	checkDNSFB   = "dns-fallback"
	checkCoreDNS = "coredns-stub"
	checkEgress  = "overlay-egress"
	checkNebula  = nebula.CheckNebula
	checkF2B     = "fail2ban"
	checkClock   = "clock-sync"
	checkCT      = "conntrack-guard"
	checkNebTCP  = nebula.CheckNebTCP
)

// NetHealth runs the network checks on one ticker.
type NetHealth struct {
	cfg Config

	// state is the shared hoststate Store — every state-*/last-*/
	// dnsfb-*/egress-*/fail2ban-* file and the watchdog log append
	// goes through it (the single lib.sh-parity implementation).
	state *hoststate.Store

	dnsfails ledger.StreakLedger // per DNS_FALLBACK_MAP name
	// dnsok counts consecutive successful DNS probes per name — the
	// unpin streak. The pin drops only after ConsecNeeded
	// consecutive successes (symmetric with dnsfails' pin-on gate);
	// a single lucky resolution must not tear the managed block out.
	dnsok      ledger.StreakLedger // per DNS_FALLBACK_MAP name
	clockFails int                 // consecutive unsynced adjtimex reads
	egressCtr  ledger.StreakLedger // per relay probe!=committed counter
	// ctStatPrev is the last-cycle sum of the nf_conntrack
	// insert_failed+drop+early_drop columns; ctStatSeen separates
	// "first read" (baseline only) from a real delta — the spike
	// detector must not flush on a counter jump across an agent
	// restart vs an unset baseline. ctInsertPrev/ctInsertSeen are
	// the insert_failed-ONLY twin feeding the surgical UNREPLIED
	// udp flush (conntrackInsertSpike).
	ctStatPrev   uint64
	ctStatSeen   bool
	ctInsertPrev uint64
	ctInsertSeen bool

	// neb is the nebula subpackage's deps bundle (see
	// nebula_bridge.go) — the nebula checks' counters and prober
	// state live on it, per-instance like the rest of NetHealth.
	neb *nebula.Deps

	cycles  *prometheus.CounterVec // check, result
	actions *prometheus.CounterVec // check, action

	// groups is the ordered per-Cycle dispatch table — initChecks
	// fills it; the order + the uptime-gated first group preserve
	// the shell runner's module order (20/21 alone carried
	// WD_REQUIRES:uptime).
	groups []subframe.Group

	// routeGuardRunning keeps the route guard single-flight while
	// still allowing a respawn: set when the goroutine spawns,
	// cleared when it exits (clean cancel, read error unwind, or a
	// recovered panic). The old sync.Once made ANY guard death
	// permanent — a panic left route events unmonitored forever.
	// routeGuardLastExit adds a small respawn backoff so a
	// crash-looping guard can't spawn-storm.
	routeGuardRunning  atomic.Bool
	routeGuardLastExit atomic.Int64 // unixnano of last guard exit
	// routeGuardSetnsDead latches a terminal setns failure: the
	// environment cannot enter the host netns, and every respawn
	// would lock an OS thread + open two ns fds just to fail again —
	// the guard stays dead (log line records it) until restart.
	routeGuardSetnsDead atomic.Bool
}

// New returns a NetHealth and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*NetHealth, error) {
	cfg.applyDefaults()
	n := &NetHealth{
		cfg: cfg,
	}
	// The store binds the shared timex.Cell — a post-New
	// cfg.Clock.Set is observed by it (hoststate.Store.Now
	// contract; controllerhygiene parity).
	n.state = cfg.Store(logger)
	n.cycles, n.actions = subframe.Counters("nethealth",
		"Net-health check cycles by check and result "+
			"(ok|abort|gated|disabled|uptime_gate|open_error|restore_error).",
		"Net-health remediation actions by check and action "+
			"(pin|unpin|restart|rule_add|rule_del|kill|restored).")
	if err := subframe.RegisterAll(reg, n.cycles, n.actions); err != nil {
		return nil, fmt.Errorf("register nethealth metrics: %w", err)
	}
	n.neb = newNebulaDeps(n)
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
	n.groups = []subframe.Group{
		{
			GateOK: n.uptimeOK,
			Entries: []subframe.Entry{
				{Name: checkDNSFB, Run: n.checkDNSFallback},
				{Name: checkCoreDNS, Run: n.checkCoreDNSStub},
			},
		},
		{
			Entries: []subframe.Entry{
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
	up, err := procfs.UptimeSeconds(n.cfg.UptimeFile)
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
	// cfg.Watchdog is owned by the Cycle goroutine alone: only
	// in-cycle checks read the field, and only when WatchdogSrc
	// is wired does BeginCycle move it. Off-Cycle goroutines
	// (routeGuard, mtuProbeLoop) NEVER read it — watchdogConf()
	// routes them through the mutexed reloader instead
	// (workerhygiene's feederWatchdogConf parity).
	_, sigOn := n.cfg.BeginCycle()
	subframe.Dispatch(ctx, sigOn, n.cycles, n.groups)
}
