// check.go — the Check contract + the ordered dispatch-table
// builder initChecks (the workerhygiene check.go/deps.go pattern).
// Unlike workerhygiene there is no cycleEnv: the controllerhygiene
// checks share no per-cycle inputs — everything they consume is
// already on deps — so Run takes only ctx and the entries bind the
// Check's method directly.
package controllerhygiene

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
)

// Check is one hygiene probe+remedy pair. Name() is the prometheus
// `check` label AND the log-context key — it must equal the check*
// constant the counters/logs already use so latch names, metric
// label values and log lines stay identical. Run executes one
// round and must never panic: implementations reach the shared
// seams (procfs view, mTLS client, state store, journal tracker,
// metrics, cfg knobs) through their *deps (deps.go — the
// check-facing dependency surface) and keep their streak
// bookkeeping on disk (consecutive-* files stay the cross-process
// contract with any still-deployed shell watchdog pieces).
type Check interface {
	Name() string
	Run(ctx context.Context)
}

// bind is initChecks's single declaration point for one check: it
// stores the instance in its named field slot (tests and the
// old-shape forwarders still reach them by name) AND appends the
// dispatch entry to the group's list — slot, name and table row
// used to be maintained in two parallel lists that could drift.
// Bind-call order inside a group IS the dispatch order; the group
// boundary is where the target entries slice switches.
func bind[C Check](slot *C, c C, entries *[]checks.Entry, name string) {
	*slot = c
	*entries = append(*entries, checks.Entry{Name: name, Run: c.Run})
}

// initChecks builds the ordered dispatch table Cycle drives — the
// workerhygiene initChecks pattern. Order + grouping are
// load-bearing: the 60s-timer guards (kine pool, OOM loop) had no
// uptime gate in shell and run first; only the module-22 checks
// carried WD_REQUIRES: uptime. The controllerhygiene checks carry
// no WD_SIG kill switch (the shell timers had none) — Dispatch gets
// a nil sigOn and every entry runs.
func (h *Hygiene) initChecks() {
	// Group 1 — ungated. etcdguard sits with the 60s-timer
	// guards: an embedded etcd that hit quota during boot needs
	// the guard BEFORE the 20min wedge grace, and hosts without
	// etcdctl no-op. W8-CP3/CP4 are ungated like the guards too —
	// a frozen KCM/scheduler or a stale PKI reload must not wait
	// out the module-22 boot grace; both probes are read-only
	// until their own consecutive-cycle + rate budgets pass.
	var ungated []checks.Entry
	bind(&h.kinePool, &kinePoolCheck{d: h.deps}, &ungated, checkKinePool)
	bind(&h.oomLoop, &oomLoopCheck{d: h.deps}, &ungated, checkOOMLoop)
	bind(&h.etcd, &etcdGuardCheck{d: h.deps}, &ungated, checkEtcd)
	// The W10-CP2/W10-CP5 ride-alongs share the cp-freeze dispatch
	// slot — cpFreezeCheck.Run invokes them before its own probe so
	// they keep the pre-uptime-gate position they had as inlined
	// calls (same pre-Check order). They stay named fields (the
	// forwarders reach them) but get no table row of their own —
	// built first, then handed to cpFreeze explicitly.
	h.kineStorage = &kineStorageCheck{d: h.deps}
	h.kubeCert = &kubeCertCheck{d: h.deps}
	bind(&h.cpFreeze, &cpFreezeCheck{
		d:           h.deps,
		kineStorage: h.kineStorage,
		kubeCert:    h.kubeCert,
	}, &ungated, checkCPFreeze)
	bind(&h.pkiDrift, &pkiDriftCheck{d: h.deps}, &ungated, checkPKIDrift)

	// Group 2 — WD_REQUIRES: uptime unit:k0scontroller — the
	// 20min post-boot grace before the destructive wedge/TTL
	// checks. The skip counts ONCE under checkHub — the label
	// the gated cycle always reported.
	var gated []checks.Entry
	bind(&h.hub, &apiserverHubCheck{d: h.deps}, &gated, checkHub)
	bind(&h.kineTTL, &kineTTLCheck{d: h.deps}, &gated, checkKineTTL)

	h.groups = []checks.Group{
		{Entries: ungated},
		{
			GateOK:    h.uptimeOK,
			GateLabel: checkHub,
			Entries:   gated,
		},
	}
}
