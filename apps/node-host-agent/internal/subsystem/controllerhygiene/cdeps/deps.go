// deps.go — the check-facing dependency surface. Deps is everything
// a Check reaches through its injected pointer: the live config
// (seams re-stubbed by tests post-New), the procfs view, the mTLS
// apiserver client + its credential fingerprint, the hoststate
// store, the journal-blindness tracker, the remediate rate mutex,
// the watchdogconf refresh bookkeeping, and the prometheus
// vecs/gauges.
//
// This is the shared half of the controllerhygiene per-domain split:
// every domain package (kine, apiserver, etcd, pki, oom, feeder)
// gets the same *Deps — there is deliberately ONE deps type, not
// per-domain projections, because the shared state below is what
// actually couples the checks (the journal tracker is classified
// into by several checks' journal reads, the rate mutex guards the
// feeder remediate budget, and the metric vecs count every check's
// cycles/actions). All fields are exported: parent-package and
// domain test files promote them through the embedded *Deps as
// h.<Field>.
package cdeps

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// Deps is the shared state every Check consumes — the split's
// answer to the old `h *Hygiene` back-ref. Check structs hold a
// `d *Deps` and read config/proc/state/metrics through it, never
// touching the orchestrator. Hygiene embeds *Deps so the same
// fields also resolve as h.<Field> — the test contract (cfg seam
// re-stubs, h.State, h.JournalReads, the EtcdDB*/Cycles gauges)
// keeps compiling.
type Deps struct {
	Cfg    Config
	Proc   procfs.FS    // /proc view bound to Cfg.ProcRoot
	Client *http.Client // mTLS client for rv probes; nil when creds absent
	CredFP string       // credential-file fingerprint the client was built from

	// State is the shared hoststate Store — every state-*/last-*/
	// consecutive-*/last-suspect-* file and the watchdog log append
	// goes through it (the single lib.sh-parity implementation).
	State *hoststate.Store

	// RateMu serialises the remediate G5 check + G6 budget spend:
	// the last-restart epoch file stays the cross-process contract,
	// but the in-process read-compare-write still needs a mutex or
	// two overlapping remediate passes can both see "allowed" in
	// the same window (TOCTOU double-restart). Held only around
	// the file check+mkdir+write, never across systemctl —
	// workerhygiene rateTrySpend parity.
	RateMu sync.Mutex

	// JournalReads is the journal-unreadable accounting — every
	// JournalText result is classified into it; the tracker fires
	// the state-journal-unreadable latch on persistent blindness.
	JournalReads journalwatch.Tracker

	// WdApplied records the watchdogconf parse the conf-derived knobs
	// were last refreshed from — BUG-H9's "only move fields that
	// still carry the previous conf value" rule needs the previous
	// parse.
	WdApplied *watchdogconf.Config

	Cycles    *prometheus.CounterVec // check, result
	Actions   *prometheus.CounterVec // check, action
	RVGap     prometheus.Gauge
	KineConns prometheus.Gauge
	// KineStuckConns counts kine's DB-port sockets wedged in
	// CLOSE_WAIT/FIN_WAIT2 or retransmitting (kine-orphaned-conn-watch) — the
	// orphaned-connection half of the pool guard the conn count
	// alone cannot see.
	KineStuckConns prometheus.Gauge
	OOMWindow      prometheus.Gauge
	Feeding        prometheus.Gauge
	// Etcdguard gauges — only set when <K0sDir>/bin/etcdctl +
	// pki/etcd/ca.crt exist (embedded-etcd controllers).
	EtcdDBSize  prometheus.Gauge
	EtcdDBUse   prometheus.Gauge
	EtcdNospace prometheus.Gauge
	// TerminatedWatchers is the relist-storm 410-Gone relist-storm
	// series — the local apiserver's
	// apiserver_terminated_watchers_total mirrored each cycle. It is
	// a CounterFunc (the mirrored series is cumulative — the
	// textfile half of the same name declares TYPE counter) serving
	// the last scraped value held in TerminatedWatchersVal, so a
	// scrape that loses the family keeps serving the real last
	// reading instead of fabricating zero.
	TerminatedWatchers    prometheus.Collector
	TerminatedWatchersVal atomic.Uint64 // math.Float64bits of the last scrape
	// EtcdSnapAge is the backup-health etcd snapshot freshness gauge
	// (embedded-etcd controllers).
	EtcdSnapAge prometheus.Gauge
	// KonnReadyBackends is the konnectivity-server ready-backend
	// gauge — konnectivity_network_proxy_server_ready_backend_
	// connections scraped each cycle, -1 on scrape failure.
	KonnReadyBackends prometheus.Gauge
}

// SingleController reports whether this node's control plane is a
// single-controller topology (spof-streak): TotalControllers is the
// explicit override (0 = auto — an unset Hub.PeerAPI means no peer
// exists to fence against, i.e. one controller).
func (d *Deps) SingleController() bool {
	if d.Cfg.TotalControllers > 0 {
		return d.Cfg.TotalControllers == 1
	}
	return d.Cfg.Hub.PeerAPI == ""
}

// StreakCycles returns the consecutive-failure streak a restart
// gate must pass — doubled on a single-controller topology so a
// transient flap cannot bounce the only apiserver (spof-streak).
func (d *Deps) StreakCycles(base int) int {
	if d.SingleController() {
		return base * spofStreakMultiplier
	}
	return base
}
