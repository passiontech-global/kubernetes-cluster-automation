// deps.go — the check-facing dependency surface. Deps is everything
// a Check reaches through its embedded pointer: the live config
// (seams re-stubbed by tests post-New), the procfs view, the
// hoststate store, the journal-blindness tracker, the prometheus
// vecs, and the small set of mutable state that is genuinely shared
// BETWEEN checks (or poked by name from pre-Check tests).
package workerhygiene

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// deps is the shared state every Check consumes — the refactor's
// answer to the old `h *Hygiene` back-ref. Check structs hold a
// `d *deps` and read config/proc/state/metrics through it, never
// touching the orchestrator. Hygiene embeds *deps so the same
// fields also resolve as h.<field> — the pre-Check test contract
// (e.h.stallFails, e.h.ciliumAgentKilled, h.cfg.Seams re-stubs)
// keeps compiling unchanged.
//
// Remaining seam for a per-domain package split: this struct IS
// the boundary. A kubelet/cilium/ctr/disk sub-package would take a
// *deps (or a per-domain projection of it) in its constructor; what
// blocks the move today is only the cross-check shared state kept
// here — ciliumAgentKilled (cilium family → envoy), the named
// streak counters tests poke (stallFails, ciliumInitFails,
// ciliumIPAMFails, ciliumWGFails, kubeletWdFails,
// kubeletFeederWasActive, taskMapBuilds), the orphanHostPath gauges
// the Cycle textfile writer reads, journalReads, and the metric
// vecs — plus the named-check-field test contract on Hygiene.
// Splitting means either exporting these or moving the tests; the
// check code itself is already package-clean.
type deps struct {
	cfg Config
	// proc is the /proc view bound to cfg.ProcRoot — the shared
	// platform/procfs helpers (pid listing, cmdline/environ/stat
	// reads, liveness) the checks all go through.
	proc procfs.FS

	// state is the shared hoststate.Store for the watchdog state-dir
	// contract (state-* latches, last-* rate budgets, installed/
	// last-run heartbeat, watchdog log appends). Its clock is a
	// closure over the LIVE cfg.Seams.nowFn so post-construction test
	// stubs still apply; its RateTrySpend mutex serialises the
	// feeder-vs-Cycle check+spend pairs the old rateMu guarded
	// (TOCTOU double-restart on the shared last-* budgets).
	state *hoststate.Store

	// In-memory consecutive counters — the shell kept these as
	// consecutive-* files; in-agent state survives between cycles and
	// an agent restart just re-arms the count (bounded by Interval).
	// Most streaks live on their Check structs now; the four below
	// stay shared because pre-Check tests poke them by name
	// (e.h.stallFails et al. — more than five call sites each, so
	// keeping the field beats churning the test contract).
	stallFails      int // kubelet-stall streak (stallCheck)
	ciliumInitFails int // cilium-init-stuck streak (ciliumInitCheck)
	ciliumIPAMFails int // cilium-ipam streak (ciliumIPAMCheck)
	ciliumWGFails   int // cilium_wg0 peer-deficit streak (ciliumWGCheck)
	// kubeletWdFails is the T15 feeder's consecutive-fail counter —
	// in-memory like the others (the shell counted within one feeder
	// process anyway; an agent restart re-arms bounded by the 15s tick).
	kubeletWdFails int
	// kubeletFeederWasActive tracks the last tick's activation state
	// so a false→true flip (node re-added to systemd_watchdog_hosts,
	// unit file reinstalled, WD_SIG lifted) drops a stale partial
	// fail-streak instead of counting it toward a restart.
	kubeletFeederWasActive bool
	taskMapBuilds          int // buildTaskMap invocation count (tests)

	// journalReads is the journal-unreadable accounting — every
	// journal read (k0sworker snapshot + A5 probes) is classified
	// into it; the tracker fires the state-journal-unreadable latch
	// on persistent blindness while journal storage exists.
	journalReads journalwatch.Tracker
	// ciliumAgentKilled is shared between the cilium check family
	// and the envoy check: killCiliumAgent sets it (the agent kill
	// can come from the cilium, cilium-init or wg-peers check —
	// whichever wins the shared last-cilium-restart budget first),
	// and the envoy check restarts cilium-envoy the same cycle so
	// its xDS listener can't hold a stale socket across the agent
	// restart. Cycle resets it before the checks run.
	ciliumAgentKilled bool

	// Wave-10 ST2 gauge values — shared between orphanHPCheck
	// (writes them each cycle) and writeNodeAgentPromTextfile
	// (reads them at end of Cycle); tests poke them too.
	orphanHostPathBytes int64
	orphanHostPathDirs  int

	cycles          *prometheus.CounterVec // check, result
	actions         *prometheus.CounterVec // check, action
	ciliumAllocated prometheus.Gauge       // cilium IPAM allocated IPs (38)
	ciliumLeaked    prometheus.Gauge       // allocated − in-use (38)
	// ctrIngestsCleaned counts ingest dirs removed by the A3 GC.
	ctrIngestsCleaned prometheus.Counter
}
