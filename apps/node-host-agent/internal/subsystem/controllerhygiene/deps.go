// deps.go — the check-facing dependency surface. Deps is everything
// a Check reaches through its embedded pointer: the live config
// (seams re-stubbed by tests post-New), the procfs view, the mTLS
// apiserver client + its credential fingerprint, the hoststate
// store, the journal-blindness tracker, the remediate rate mutex,
// the watchdogconf refresh bookkeeping, the cross-cycle
// kcmQuietSince stamp, and the prometheus vecs/gauges.
package controllerhygiene

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// deps is the shared state every Check consumes — the refactor's
// answer to the old `h *Hygiene` back-ref. Check structs hold a
// `d *deps` and read config/proc/state/metrics through it, never
// touching the orchestrator. Hygiene embeds *deps so the same
// fields also resolve as h.<field> — the pre-Check test contract
// (e.h.cfg seam re-stubs, e.h.state, e.h.journalReads, the
// etcdDB*/cycles gauges) keeps compiling unchanged.
type deps struct {
	cfg    Config
	proc   procfs.FS    // /proc view bound to cfg.ProcRoot
	client *http.Client // mTLS client for rv probes; nil when creds absent
	credFP string       // credential-file fingerprint the client was built from

	// state is the shared hoststate Store — every state-*/last-*/
	// consecutive-*/last-suspect-* file and the watchdog log append
	// goes through it (the single lib.sh-parity implementation).
	state *hoststate.Store

	// rateMu serialises the remediate G5 check + G6 budget spend:
	// the last-restart epoch file stays the cross-process contract,
	// but the in-process read-compare-write still needs a mutex or
	// two overlapping remediate passes can both see "allowed" in
	// the same window (TOCTOU double-restart). Held only around
	// the file check+mkdir+write, never across systemctl —
	// workerhygiene rateTrySpend parity.
	rateMu sync.Mutex

	// journalReads is the journal-unreadable accounting — every
	// journalText result is classified into it; the tracker fires the
	// state-journal-unreadable latch on persistent blindness.
	journalReads journalwatch.Tracker

	// wdApplied records the watchdogconf parse the conf-derived knobs
	// were last refreshed from — BUG-H9's "only move fields that still
	// carry the previous conf value" rule needs the previous parse.
	wdApplied *watchdogconf.Config
	// kcmQuietSince is the first cycle the KCM read leader+idle —
	// leader-without-workers only counts as frozen after
	// CPFreezeQuietFor (W8-CP3).
	kcmQuietSince time.Time

	cycles    *prometheus.CounterVec // check, result
	actions   *prometheus.CounterVec // check, action
	rvGap     prometheus.Gauge
	kineConns prometheus.Gauge
	oomWindow prometheus.Gauge
	feeding   prometheus.Gauge
	// etcdguard gauges — only set when <K0sDir>/bin/etcdctl +
	// pki/etcd/ca.crt exist (embedded-etcd controllers).
	etcdDBSize  prometheus.Gauge
	etcdDBUse   prometheus.Gauge
	etcdNospace prometheus.Gauge
}
