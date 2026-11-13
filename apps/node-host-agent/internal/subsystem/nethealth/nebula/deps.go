// deps.go — the deps bundle the nebula checks run against: the
// parent nethealth subsystem's telemetry handles, state store,
// seams and counters, wired by the parent's nebula_bridge.go. The
// closure fields stay LIVE — they read the parent Config on every
// call, so a post-New re-stub (the tests re-stub n.cfg.ping and
// friends after New) is observed like it was when this code was
// methods on NetHealth. Parent-side helpers (nsenter `ip`, unit
// probes, the conntrack flushes, trimRunErr) remain owned by the
// parent package and are handed over as function values.
package nebula

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Check-name constants — the prometheus `check` label values. The
// parent nethealth package aliases these for the subframe.Group
// registration (single source of truth for the metric-name
// contract); keep the values byte-identical to the shell module
// names they port.
const (
	CheckNebula = "nebula-health"
	CheckNebTCP = "nebula-direct-tcp"
)

// suspectLogCadence mirrors the parent nethealth suspectLogCadence
// (time.Hour) — the throttling window every SuspectLog in the
// nebula checks shares with the rest of the subsystem.
const suspectLogCadence = time.Hour

// Body-level aliases — the moved code keeps its original identifier
// names; the exported constants above are the contract the parent
// registration aliases.
const (
	checkNebula = CheckNebula
	checkNebTCP = CheckNebTCP
)

// Deps bundles everything the nebula checks consume from the parent
// nethealth subsystem. Parent-only consumer: the parent constructs
// it in New and reaches it through one-line delegating wrappers, so
// the subframe.Group registration order stays byte-identical.
type Deps struct {
	Cycles  *prometheus.CounterVec // check, result
	Actions *prometheus.CounterVec // check, action
	State   *hoststate.Store

	// Consecutive-failure/run counters moved off NetHealth with the
	// nebula checks (socket/tun/stats vs dataplane streaks, the
	// overlay-mtu-guard DF streak, the siteedge confirm run).
	NebulaFails  int // socket/tun/stats fails
	NebulaDpFail int // dataplane-dead fails
	NebulaDeg    int // dataplane-degraded runs
	PMTUFails    int // consecutive DF-probe failures (overlay-mtu-guard)
	// SiteedgeRun counts consecutive cycles the siteedge
	// marker set keeps failing — the siteedge LATCH arms on the
	// first detection, but the nebula-conntrack-flush per-peer conntrack flush
	// waits for ConsecNeeded confirmed runs like the degraded path.
	SiteedgeRun int

	// MTU is the nebula-mtu-blackhole prober state (see
	// mtu_blackhole.go) — per-instance, so its lifetime is the
	// parent NetHealth's own and no global keyed map is needed.
	MTU MTUProbeState

	// Config values — closures over the parent Config so post-New
	// edits (tests assign cfg.Watchdog, cfg.Systemd, ...) stay live.
	Watchdog             func() *watchdogconf.Config // the cycle-time conf snapshot (cfg.Watchdog)
	WatchdogConf         func() *watchdogconf.Config // the mutexed reloader (off-Cycle goroutines)
	Systemd              func() *systemd.Client
	ConsecNeeded         func() int
	MinRestart           func() time.Duration
	NebulaDirectTCPPorts func() []int
	ProcNetUDP           func() string
	ProcNetUDP6          func() string
	HostRoot             func() string
	Interval             func() time.Duration // effective cadence, default applied
	TextfileDir          func() string
	TextfileDirOverride  func() string // parent test override var
	Clock                func() *timex.Cell

	// Transport seams (the parent Config's unexported func fields).
	RunHostCmd  func(ctx context.Context, argv []string) (string, error)
	RunMountCmd func(ctx context.Context, argv []string) (string, error)
	Ping        func(ctx context.Context, ip string, count, waitSec int, marked bool) (bool, float64)
	ProbeHTTP   func(ctx context.Context, url string, timeout time.Duration) error

	// Parent-side helpers the nebula checks compose.
	IP func(ctx context.Context, args ...string) (string, error)
	// LinkAddrs lists the addresses on one netns link — the
	// netlinkx read behind hasIPv4Addr (the `ip -o addr show dev`
	// replacement; callers pass pid 1 for the host netns).
	LinkAddrs func(pid int, name string) ([]netlink.Addr, error)
	// Rules dumps pid's policy-routing rules — the netlinkx.Rules
	// read behind CheckNebulaDirectTCP (the per-cycle
	// `ip rule list pref 1499` fork replacement; pid 1 = host
	// netns). Writes stay on the IP seam — netlinkx is read-only.
	Rules                    func(pid int) ([]netlink.Rule, error)
	StateExit                func(name string)
	UnitEnabledActive        func(ctx context.Context, unit string) bool
	NebulaUpExists           func(wd *watchdogconf.Config) bool
	EgressFiles              func(prefixes ...string) []string
	FlushStaleUDPConntrack   func(ctx context.Context, check string)
	FlushPeerNebulaConntrack func(ctx context.Context, check string, peers ...string)
	TrimRunErr               func(out string) string
}

// MTUState returns this instance's prober state.
func (n *Deps) MTUState() *MTUProbeState {
	return &n.MTU
}
