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

// initChecks builds the ordered dispatch table Cycle drives — the
// workerhygiene initChecks pattern. Order + grouping are
// load-bearing: the 60s-timer guards (kine pool, OOM loop) had no
// uptime gate in shell and run first; only the module-22 checks
// carried WD_REQUIRES: uptime. The controllerhygiene checks carry
// no WD_SIG kill switch (the shell timers had none) — Dispatch gets
// a nil sigOn and every entry runs.
func (h *Hygiene) initChecks() {
	h.kinePool = &kinePoolCheck{d: h.deps}
	h.oomLoop = &oomLoopCheck{d: h.deps}
	h.etcd = &etcdGuardCheck{d: h.deps}
	// The W10-CP2/W10-CP5 ride-alongs share the cp-freeze dispatch
	// slot — cpFreezeCheck.Run invokes them before its own probe so
	// they keep the pre-uptime-gate position they had as inlined
	// calls (same pre-Check order).
	h.kineStorage = &kineStorageCheck{d: h.deps}
	h.kubeCert = &kubeCertCheck{d: h.deps}
	h.cpFreeze = &cpFreezeCheck{
		d:           h.deps,
		kineStorage: h.kineStorage,
		kubeCert:    h.kubeCert,
	}
	h.pkiDrift = &pkiDriftCheck{d: h.deps}
	h.hub = &apiserverHubCheck{d: h.deps}
	h.kineTTL = &kineTTLCheck{d: h.deps}
	h.groups = []checks.Group{
		{
			Entries: []checks.Entry{
				{Name: checkKinePool, Run: h.kinePool.Run},
				{Name: checkOOMLoop, Run: h.oomLoop.Run},
				// etcdguard is in the ungated group like
				// kine-pool/oomloop — an embedded etcd that hit
				// quota during boot needs the guard BEFORE the
				// 20min wedge grace, and hosts without etcdctl
				// no-op.
				{Name: checkEtcd, Run: h.etcd.Run},
				// W8-CP3/CP4 are ungated like the 60s-timer
				// guards: a frozen KCM/scheduler or a stale PKI
				// reload must not wait out the module-22 boot
				// grace — both probes are read-only until their
				// own consecutive-cycle + rate budgets pass.
				{Name: checkCPFreeze, Run: h.cpFreeze.Run},
				{Name: checkPKIDrift, Run: h.pkiDrift.Run},
			},
		},
		{
			// WD_REQUIRES: uptime unit:k0scontroller — 20min
			// grace after boot before the destructive wedge/TTL
			// checks. The skip counts ONCE under checkHub —
			// the label the gated cycle always reported.
			GateOK:    h.uptimeOK,
			GateLabel: checkHub,
			Entries: []checks.Entry{
				{Name: checkHub, Run: h.hub.Run},
				{Name: checkKineTTL, Run: h.kineTTL.Run},
			},
		},
	}
}
