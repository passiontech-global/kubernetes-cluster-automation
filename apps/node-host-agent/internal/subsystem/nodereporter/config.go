// config.go — the nodereporter knobs: the NPD-parity defaults
// (interval, staleness/lookback/dedup windows, watchdog paths, the
// NPD-monitor port paths) and the Config struct + applyDefaults.
// Split out of nodereporter.go so the Reporter/Cycle file stays
// under the ~500-LOC bar; the env surface lives in config_env.go.
package nodereporter

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Defaults mirror the removed NPD config and the DaemonSet host mounts.
const (
	defaultInterval = 30 * time.Second
	// defaultStaleThreshold is check-watchdog-fresh.sh's 1200s: the
	// watchdog run timer is dead / hangs when last-run is older.
	defaultStaleThreshold = 20 * time.Minute
	// defaultLogLookback is the NPD filelog "lookback": 5m" — on the
	// first scan after (re)start only lines newer than this are
	// replayed, so deploy gaps don't silently lose ACTION events while
	// ancient history isn't re-emitted.
	defaultLogLookback = 5 * time.Minute
	// defaultEventDedupTTL bounds the series-aggregation window —
	// roughly the apiserver event TTL (1h). After it, an identical
	// reason+message creates a fresh Event object.
	defaultEventDedupTTL = time.Hour

	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultWatchdogLogFile  = "/host/var/log/node-watchdog.log"
	defaultEventNamespace   = "default" // node events conventionally land in default

	// defaultCycleTimeout is the per-Cycle hard bound Run applies —
	// controllerhygiene's runCycle parity. The ticker loop calls
	// Cycle synchronously, so without the bound one hung child
	// freezes the reporter forever: 2026-11-06 all six agents wedged
	// mid-Cycle during an apiserver flap (subsystem_up stayed 1,
	// logs stopped, NodeCondition lastHeartbeatTime froze ~17h; only
	// a pod delete recovered). Every kube/journal call in Cycle is
	// ctx-aware, so the deadline actually interrupts the stall;
	// host file reads can't be, but they were never the wedge.
	defaultCycleTimeout = 5 * time.Minute
	// defaultHeartbeatInterval is how often syncConditions
	// re-patches lastHeartbeatTime on its NodeConditions even when
	// nothing else changed — the heartbeat is the reporter-liveness
	// signal cluster-side checks trust (node-hang-precordon refuses
	// a condition whose heartbeat froze). ~4 cycles at the default
	// Interval keeps the stamp fresh while staying well under the
	// controller's 10m staleness window.
	defaultHeartbeatInterval = 2 * time.Minute

	// NPD-monitor port defaults — see the npd subpackage. The
	// DaemonSet runs hostPID and bind-mounts host /dev/kmsg at
	// /dev/kmsg, so /proc/1/mounts and /proc/uptime are already the
	// HOST tables (a container procfs would only see the pod's
	// mount ns).
	defaultHostRoot           = "/host" // nsenter boundary for journalctl
	defaultKmsgFile           = "/dev/kmsg"
	defaultProcMountsFile     = "/proc/1/mounts"
	defaultProcUptimeFile     = "/proc/uptime"
	defaultKubeletJournalUnit = "k0sworker.service"
)

// defaultReadonlyTargets are the host mountpoints the
// readonly-monitor port watches; defaultReadonlyFSTypes restricts
// the check to real disk filesystems.
var (
	defaultReadonlyTargets = []string{"/", "/var", "/var/lib/k0s", "/var/openebs"}
	defaultReadonlyFSTypes = []string{"ext4", "xfs", "btrfs"}
)

// Config carries the reporter knobs — all test-injectable.
type Config struct {
	// Base is the shared watchdog-subsystem block — sync cadence,
	// the host latch dir (state-*, installed, last-run), the
	// appended node-watchdog log the filelog monitor tails
	// (filelog parity), the host fs root and the clock cell
	// splice (subframe.FromDeps).
	subframe.Base
	NodeName string // this node (spec.nodeName) — conditions + events attach here
	Client   kubernetes.Interface
	// Systemd is the SHARED host-systemd client (wiring's sdClient via
	// hostctx.Deps) — the journald monitors read through it instead of
	// the reporter building its own connection. nil → applyDefaults
	// builds an owned client (tests, hand-built configs).
	Systemd *systemd.Client

	// CycleTimeout is the per-Cycle deadline Run applies around each
	// Cycle: Run calls Cycle synchronously inside the ticker loop,
	// so a kube/journal call that ignores the client timeout would
	// otherwise stall the reporter indefinitely (the 2026-11-06
	// ~17h fleet wedge). <=0 → defaultCycleTimeout (5m).
	CycleTimeout time.Duration
	// HeartbeatInterval is how often lastHeartbeatTime on the
	// reporter's NodeConditions is refreshed even when Status and
	// Reason are unchanged — the stamp is the reporter-liveness
	// evidence consumers like node-hang-precordon use to distrust a
	// condition whose writer may be dead. <=0 →
	// defaultHeartbeatInterval (2m).
	HeartbeatInterval time.Duration
	EventNamespace    string        // ns the Events are created in
	StaleThreshold    time.Duration // last-run age → WatchdogStale=True
	LogLookback       time.Duration // first-scan replay window (NPD lookback parity)
	EventDedupTTL     time.Duration // series-aggregation window per reason+message

	// --- NPD monitor port (the npd subpackage) ---
	KmsgFile           string   // kernel ring source; <HostRoot>/dev/kmsg is the fallback
	ProcMountsFile     string   // host mount table (hostPID → /proc/1/mounts)
	ProcUptimeFile     string   // host uptime for the kmsg first-scan lookback
	KubeletJournalUnit string   // journald unit the kubelet-stale monitor tails
	ReadonlyTargets    []string // mountpoints watched for unexpected ro
	ReadonlyFSTypes    []string // fstypes the ro check applies to

	// journalFetch runs `journalctl <args>` on the host (nsenter
	// wrapper when HostRoot != "/") — nil builds the default via the
	// systemd package; tests substitute a fake.
	journalFetch func(ctx context.Context, args ...string) (string, error)
	ownedSD      *systemd.Client
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.CycleTimeout <= 0 {
		c.CycleTimeout = defaultCycleTimeout
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = defaultHeartbeatInterval
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.WatchdogLogFile == "" {
		c.WatchdogLogFile = defaultWatchdogLogFile
	}
	if c.EventNamespace == "" {
		c.EventNamespace = defaultEventNamespace
	}
	if c.StaleThreshold <= 0 {
		c.StaleThreshold = defaultStaleThreshold
	}
	if c.LogLookback <= 0 {
		c.LogLookback = defaultLogLookback
	}
	if c.EventDedupTTL <= 0 {
		c.EventDedupTTL = defaultEventDedupTTL
	}
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.KmsgFile == "" {
		c.KmsgFile = defaultKmsgFile
	}
	if c.ProcMountsFile == "" {
		c.ProcMountsFile = defaultProcMountsFile
	}
	if c.ProcUptimeFile == "" {
		c.ProcUptimeFile = defaultProcUptimeFile
	}
	if c.KubeletJournalUnit == "" {
		c.KubeletJournalUnit = defaultKubeletJournalUnit
	}
	if len(c.ReadonlyTargets) == 0 {
		c.ReadonlyTargets = defaultReadonlyTargets
	}
	if len(c.ReadonlyFSTypes) == 0 {
		c.ReadonlyFSTypes = defaultReadonlyFSTypes
	}
	if c.journalFetch == nil {
		// The SHARED wiring client when wired — one D-Bus connection
		// for the whole process; the reporter's own connection would
		// duplicate it for zero benefit. Only hand-built configs
		// (tests) still get an owned client.
		sd := c.Systemd
		if sd != nil {
			c.journalFetch = func(ctx context.Context, args ...string) (string, error) {
				return sd.Exec(ctx, "journalctl", args...)
			}
		} else {
			sd := systemd.New(systemd.Config{HostRoot: c.HostRoot,
				ScrubSystemdEnv: true})
			c.ownedSD = sd
			c.journalFetch = func(ctx context.Context, args ...string) (string, error) {
				return sd.Exec(ctx, "journalctl", args...)
			}
		}
	}
	if c.Clock == nil {
		c.Clock = timex.NewCell(nil)
	}
}
