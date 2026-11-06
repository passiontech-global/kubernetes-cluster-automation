// deps.go — the check-facing dependency surface. Deps is everything
// a Check reaches through its injected pointer: the live config
// (seams re-stubbed by tests post-New), the procfs view, the
// hoststate store, the journal-blindness tracker, the prometheus
// vecs, the mutable state genuinely shared BETWEEN checks (or poked
// by name from tests), and the node_agent_* textfile series the
// guards write and the Cycle-end writer reads.
//
// This is the shared half of the workerhygiene per-domain split:
// every domain package (kubelet, pods, ctr, cilium, guards, runtime)
// gets the same *Deps — there is deliberately ONE deps type, not
// per-domain projections, because the shared-state class below is
// what actually couples the checks (the cilium family shares
// CiliumAgentKilled, the streak counters are a documented test
// surface, and the textfile writer reads several domains' series
// fields). All fields are exported: parent-package tests promote
// them through the embedded *Deps as h.<Field>.
package wdeps

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// Series is the node_agent_* textfile surface: the fields the six
// runtime-resource guards (runtime package) write each cycle —
// gauges refreshed, counters accumulated in-agent — and
// WriteNodeAgentPromTextfile reads at end of Cycle. Its only
// cross-check reader is that one writer, so it gets its own type:
// embedded by value so the check/test field contract
// (d.CgroupDyingDescendants, h.CgroupDyingDescendants in tests)
// still promotes — the boundary says who OWNS each field without
// churning call sites.
type Series struct {
	CgroupDyingDescendants int64   // max nr_dying_descendants seen
	CgroupReclaimRuns      int64   // drop_caches+memory.reclaim runs
	SystemdSessionsTotal   int64   // logind session files seen
	SystemdSessionsStale   int64   // closing/abandoned sessions >2h
	SystemdDbusLatencySec  float64 // timed systemctl is-system-running
	SystemdSessionsReaped  int64   // loginctl terminate-session count
	OverlayFSStaleMounts   int64   // stale-overlay pod detections
	DiskIOUtilRatio        float64 // max whole-disk io_ticks util
	DiskWriteAwaitMs       float64 // per-write await across whole disks
	IOPSIFullAvg60         float64 // /proc/pressure/io full avg60
	IOPSIFullAvg300        float64 // /proc/pressure/io full avg300
	IOThrottledProcs       int64   // pids reniced+ioniced to idle
	ConntrackLiberalFixes  int64   // nf_conntrack_tcp_be_liberal writes
	UnlinkedOpenFileBytes  int64   // deleted-but-open regular-file bytes held
	UnlinkedOpenFileCount  int64   // deleted-but-open regular files (deduped)
	KubepodsSwapUsedBytes  int64   // kubepods.slice memory.swap.current
	// KubeletPLEGLastSeenAgeSec is the kubelet_pleg_last_seen_seconds
	// gauge passthrough — seconds since PLEG last observed a container
	// state change; KubeletPLEGDiscardEvents is the cumulative
	// kubelet_pleg_discard_events counter.
	KubeletPLEGLastSeenAgeSec float64
	KubeletPLEGDiscardEvents  int64
	// PodCgroupMemoryThrottled counts pod cgroups caught in
	// memory.high throttle (W12-KR1), PodCgroupPIDsMaxUtilRatio is
	// the worst pids.current/pids.max across pod cgroups.
	PodCgroupMemoryThrottled  int64
	PodCgroupPIDsMaxUtilRatio float64
	// KubeletStorageOperationErrors is the
	// storage_operation_errors_total counter passthrough (W12-KR4)
	// — summed across the volume_plugin/operation labels of the
	// kubelet :10250/metrics scrape.
	KubeletStorageOperationErrors int64
}

// Deps is the shared state every Check consumes — the split's
// answer to the old `h *Hygiene` back-ref. Check structs hold a
// `d *Deps` and read config/proc/state/metrics through it, never
// touching the orchestrator. Hygiene embeds *Deps so the same
// fields also resolve as h.<Field> — the test contract
// (e.h.CiliumAgentKilled, h.<check>.Fails, h.Cfg.Seams re-stubs,
// h.<series field> reads) keeps compiling.
//
// Three ownership classes live here:
//
//   - Injected seams — Cfg, Proc, State, JournalReads and the
//     prometheus vecs: built/registered in New, consumed by checks,
//     re-stubbed by tests through Cfg.Seams.
//   - Cross-check shared state — fields more than one check (or a
//     check plus Cycle orchestration) genuinely shares:
//     TaskMapBuilds, CiliumAgentKilled (cilium family → envoy), and
//     the OrphanHostPath gauges. Per-component streak counters do
//     NOT live here — each Check (and the kubelet Feeder) owns its
//     own Fails/WdFails field.
//   - Textfile series surface — the embedded Series struct: the
//     node_agent_* values with exactly one writer family (the
//     runtime-resource guards) and one reader (the Cycle-end
//     textfile writer).
type Deps struct {
	Cfg Config
	// Proc is the /proc view bound to Cfg.ProcRoot — the shared
	// platform/procfs helpers (pid listing, cmdline/environ/stat
	// reads, liveness) the checks all go through.
	Proc procfs.FS

	// State is the shared hoststate.Store for the watchdog state-dir
	// contract (state-* latches, last-* rate budgets, installed/
	// last-run heartbeat, watchdog log appends). Its clock is a
	// closure over the LIVE Cfg.Seams.NowFn so post-construction test
	// stubs still apply; its RateTrySpend mutex serialises the
	// feeder-vs-Cycle check+spend pairs the old rateMu guarded
	// (TOCTOU double-restart on the shared last-* budgets).
	State *hoststate.Store

	// JournalReads is the journal-unreadable accounting — every
	// journal read (k0sworker snapshot + A5 probes) is classified
	// into it; the tracker fires the state-journal-unreadable latch
	// on persistent blindness while journal storage exists.
	JournalReads journalwatch.Tracker

	// Series — the W10 node_agent_* textfile surface (see the type
	// doc). Embedded, not named, so guards keep writing
	// d.<Field> and tests keep reading h.<Field>.
	Series

	// TaskMapBuilds counts BuildTaskMap invocations — cross-check by
	// construction (tasksOnce shares one build per Cycle between the
	// teardown, stall and dns checks) and a test surface.
	TaskMapBuilds int

	// CiliumAgentKilled is shared between the cilium check family
	// and the envoy check: KillCiliumAgent sets it (the agent kill
	// can come from the cilium, cilium-init or wg-peers check —
	// whichever wins the shared last-cilium-restart budget first),
	// and the envoy check restarts cilium-envoy the same cycle so
	// its xDS listener can't hold a stale socket across the agent
	// restart. Cycle resets it before the checks run.
	CiliumAgentKilled bool

	// Wave-10 ST2 gauge values — shared between OrphanHPCheck
	// (writes them each cycle) and WriteNodeAgentPromTextfile
	// (reads them at end of Cycle); tests poke them too.
	OrphanHostPathBytes int64
	OrphanHostPathDirs  int

	Cycles          *prometheus.CounterVec // check, result
	Actions         *prometheus.CounterVec // check, action
	CiliumAllocated prometheus.Gauge       // cilium IPAM allocated IPs (38)
	CiliumLeaked    prometheus.Gauge       // allocated − in-use (38)
	// CtrIngestsCleaned counts ingest dirs removed by the A3 GC.
	CtrIngestsCleaned prometheus.Counter
}
