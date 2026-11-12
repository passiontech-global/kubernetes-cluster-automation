// Package npd holds the node-problem-detector monitor ports —
// kernel-monitor (the kmsg ring tail with the journalctl -k
// fallback), the kubelet-stale journald monitor and the readonly
// mounts monitor — split out of nodereporter's conditions/events
// core (the hostmetrics/kernelfail wdeps precedent). Monitor owns
// only the sources' tail state — the kmsg Tailer, the journald µs
// cursors and the monitor-computed condition latches; reporting
// goes through the parent-supplied Sink (Events, problem_counter,
// evidence latches) and the late-bound Deps (cfg snapshot, journald
// exec, clock), both crossed as fields the parent wires in New so
// config reads and test stubs swapped onto the parent Config after
// construction still land.
package npd

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
)

// Config is the monitor half of nodereporter.Config — the
// NPD-monitor knobs. None of them are env-driven (the parent's
// applyDefaults owns the values; ConfigFromEnv never touches them).
// The DaemonSet runs hostPID and bind-mounts host /dev/kmsg at
// /dev/kmsg, so /proc/1/mounts and /proc/uptime are already the
// HOST tables (a container procfs would only see the pod's mount
// ns).
type Config struct {
	KmsgFile           string        // kernel ring source; <HostRoot>/dev/kmsg is the fallback
	HostRoot           string        // host fs root for the kmsg fallback + journalctl boundary
	ProcMountsFile     string        // host mount table (hostPID → /proc/1/mounts)
	ProcUptimeFile     string        // host uptime for the kmsg first-scan lookback
	KubeletJournalUnit string        // journald unit the kubelet-stale monitor tails
	ReadonlyTargets    []string      // mountpoints watched for unexpected ro
	ReadonlyFSTypes    []string      // fstypes the ro check applies to
	LogLookback        time.Duration // first-scan replay window (NPD lookback parity)
}

// Deps is everything the Monitor needs from the parent reporter —
// the seams crossed as late-bound closures (kernelfail's Deps
// precedent) so the parent's test stubs swapped onto its Config
// post-New still land.
type Deps struct {
	// Cfg returns the current monitor config — bound over the
	// parent Config and re-read per sync so cfg edits land live.
	Cfg func() Config
	// JournalFetch runs `journalctl <args>` against the host
	// journal — the parent's journalFetch seam (the nsenter wrapper
	// when HostRoot != "/"). Bound over the Config field so a
	// post-New stub swap still lands.
	JournalFetch journalwatch.ExecFunc
	// Now reads the shared clock cell.
	Now func() time.Time
}

// Sink is the reporter side the monitors report into — Kubernetes
// Events, problem_counter increments and watchdog-state evidence
// latches. The parent adapts its emitEvent/problemCounter/
// hoststate.Store to it.
type Sink interface {
	// EmitEvent creates or aggregates one Warning Event on the node.
	EmitEvent(ctx context.Context, reason, note string) error
	// BumpCounter increments problem_counter{reason} — one
	// increment per matched line, NPD parity.
	BumpCounter(reason string)
	// EnterLatch records a state-<name> evidence latch via the
	// shared watchdog-state contract.
	EnterLatch(name, evidence string)
}

// Cond is one evaluated NPD-monitor NodeCondition — same
// type/default/True reason+message contract as the upstream
// conditions[] declarations; GaugeReason is the problem_gauge
// reason label for the True state (the NPD permanent-rule reason).
type Cond struct {
	Type        corev1.NodeConditionType
	Status      corev1.ConditionStatus
	Reason      string
	Message     string
	GaugeReason string
}

// Monitor owns the three NPD monitor ports and their tail state —
// the kmsg Tailer (handle, carry, backlog gates), the shared
// journalwatch Multiplexer cursors and the monitor-computed
// condition latches. Not goroutine-safe — the parent's Cycle loop
// is the only driver.
type Monitor struct {
	deps Deps

	// journal is the ONE shared `journalctl -o json` tail both
	// journald consumers poll — the kubelet-stale monitor's
	// _SYSTEMD_UNIT match and the kernel fallback's
	// _TRANSPORT=kernel match (journalctl -k's own match, applied
	// client-side) fan out of a single exec per poll window instead
	// of two journalctl forks per cycle. The shared __CURSOR and
	// per-subscriber pending queues live inside the mux.
	journal *journalwatch.Multiplexer

	kmsgTail        *kmsg.Tailer // the /dev/kmsg tail — handle, carry, backlog gates
	kmsgScanned     bool         // mirrors the tail's caught-up flag (kernelLines)
	kmsgJournalMode bool         // permanent fallback once kmsg can't be opened

	// Permanent-condition bookkeeping — KernelDeadlock latches True
	// for the process lifetime (NPD permanent parity);
	// ReadonlyFilesystem follows the live mounts.
	// kernelDeadlockEventSent tracks the transition Event separately
	// from the latch: the latch sets unconditionally on the first
	// signature (the CONDITION must not wait on the Events API) while
	// a refused emit stays pending and retries — journal entries
	// requeue, kmsg records retry on the next matching line.
	kernelDeadlock          bool
	kernelDeadlockMsg       string
	kernelDeadlockEventSent bool
	readonlyFS              bool
	readonlyFSMsg           string
	// seeded marks the ONE startup seed pass SeedConditions runs —
	// the parent's syncConditions calls it every cycle, but only the
	// first may fold the live conditions in. Re-seeding each pass
	// would re-assert ReadonlyFilesystem=True from a STALE api
	// snapshot every cycle, permanently masking the live mount scan
	// that is supposed to clear it after a remount-rw. KernelDeadlock
	// is permanent-class so a one-shot seed is also all it needs.
	seeded bool
}

// New returns the monitor set. The kmsg Tailer opens its device
// lazily on the first kernel sync — Paths re-reads the config per
// (re)open so cfg/test re-points stay live.
func New(d Deps) *Monitor {
	m := &Monitor{deps: d}
	m.journal = journalwatch.New(d.JournalFetch)
	m.journal.Now = d.Now
	// The kernel fallback subscribes from birth: its pending queue
	// accumulates _TRANSPORT=kernel entries even while kmsg owns the
	// source (bounded by the mux cap, oldest dropped), so the
	// fallback's first drain replays exactly the lookback window —
	// the same coverage the old `journalctl -k --since` first fetch
	// gave — instead of missing the gap between kmsg failure and
	// subscription.
	// Subscribe cannot fail on a constant non-empty id.
	_ = m.journal.Subscribe(journalSubKernel, func(e journalwatch.Entry) bool {
		return e.Transport == "kernel"
	})
	m.kmsgTail = kmsg.NewTailer(kmsg.TailerOptions{
		Paths: func() []string {
			c := m.cfg()
			return kmsg.DevicePaths(c.KmsgFile, c.HostRoot)
		},
		DrainCap:   maxKmsgReadBytes,
		PendingCap: maxKmsgPendingBytes,
		// A never-terminated record keeps its tail — same carry
		// policy as the watchdog filelog tail.
		PendingTrimTail: true,
	})
	return m
}

// Close releases the lazily-opened kmsg handle — the parent's Run
// defers it so subsystem shutdown doesn't leak the descriptor.
func (m *Monitor) Close() {
	m.kmsgTail.Close()
}

// SeedConditions folds the node's LIVE conditions into the monitor
// latches ONCE — the first syncConditions pass after startup (the
// parent's per-cycle call is a no-op after that via the seeded
// flag). Without it a restarted agent evaluates kernelDeadlock/
// readonlyFS as False and PATCHES the node's True values away:
// KernelDeadlock is permanent-class (NPD parity — it must survive
// an agent restart), and ReadonlyFilesystem would flap False for
// one cycle before the next mount scan recomputes it. Seeding is
// set-only — a condition the monitors themselves cleared stays
// cleared — and it must run exactly once: a per-cycle re-seed
// re-reads the apiserver's LAST-WRITTEN condition, so a remounted-
// rw filesystem would keep being re-asserted True from stale state
// and never recover.
func (m *Monitor) SeedConditions(conds []corev1.NodeCondition) {
	if m.seeded {
		return
	}
	m.seeded = true
	for _, c := range conds {
		switch c.Type {
		case condKernelDeadlock:
			if c.Status == corev1.ConditionTrue {
				if !m.kernelDeadlock {
					m.kernelDeadlock = true
					m.kernelDeadlockMsg = c.Message
				}
				// The previous instance's transition Event either
				// landed or is unrecoverable — don't re-emit.
				m.kernelDeadlockEventSent = true
			}
		case condReadonlyFS:
			if c.Status == corev1.ConditionTrue && !m.readonlyFS {
				m.readonlyFS = true
				m.readonlyFSMsg = c.Message
			}
		}
	}
}

// cfg is the current monitor config snapshot.
func (m *Monitor) cfg() Config { return m.deps.Cfg() }

// EvalConditions computes the wanted state of the two NPD
// conditions — same default/True reason+message contract as the
// upstream conditions[] declarations. The parent's syncConditions
// merges this set alongside the watchdog latch conditions into ONE
// apiserver round-trip per cycle (the former split issued a
// GET+PATCH each).
func (m *Monitor) EvalConditions() []Cond {
	kd := Cond{Type: condKernelDeadlock, Status: corev1.ConditionFalse,
		Reason: kernelDeadlockDefaultReason, Message: kernelDeadlockDefaultMsg,
		GaugeReason: kernelDeadlockProblemReason}
	if m.kernelDeadlock {
		kd.Status = corev1.ConditionTrue
		kd.Reason = kernelDeadlockProblemReason
		kd.Message = m.kernelDeadlockMsg
	}
	ro := Cond{Type: condReadonlyFS, Status: corev1.ConditionFalse,
		Reason: readonlyDefaultReason, Message: readonlyDefaultMsg,
		GaugeReason: readonlyProblemReason}
	if m.readonlyFS {
		ro.Status = corev1.ConditionTrue
		ro.Reason = readonlyProblemReason
		ro.Message = m.readonlyFSMsg
	}
	return []Cond{kd, ro}
}
