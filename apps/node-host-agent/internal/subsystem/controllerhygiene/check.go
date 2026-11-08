// check.go — the ordered dispatch-table builder initChecks (the
// workerhygiene initChecks pattern). The Check contract itself lives
// in cdeps/check.go — the canonical name table the domain packages
// share.
package controllerhygiene

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/etcd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/oom"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/pki"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/storelocal"
)

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
	add := func(c cdeps.Check, entries *[]checks.Entry) {
		h.checks = append(h.checks, c)
		*entries = append(*entries, checks.Entry{Name: c.Name(), Run: c.Run})
	}
	add(storelocal.NewPool(h.Deps), &ungated)
	add(oom.NewLoop(h.Deps), &ungated)
	add(etcd.NewGuard(h.Deps), &ungated)
	// The W10-CP2/W10-CP5 ride-alongs share the cp-freeze dispatch
	// slot — FreezeCheck.Run invokes them before its own probe so
	// they keep the pre-uptime-gate position they had as inlined
	// calls (same pre-Check order). They are registered in h.checks
	// (the Check accessor + domain tests reach them) but get no
	// table row of their own — built first, then handed to the
	// freeze check explicitly.
	storage := storelocal.NewStorage(h.Deps)
	kubecert := pki.NewKubeCert(h.Deps)
	h.checks = append(h.checks, storage, kubecert)
	add(apiserver.NewFreeze(h.Deps, storage, kubecert), &ungated)
	add(pki.NewDrift(h.Deps), &ungated)

	// Group 2 — WD_REQUIRES: uptime unit:k0scontroller — the
	// 20min post-boot grace before the destructive wedge/TTL
	// checks. The skip counts ONCE under checkHub — the label
	// the gated cycle always reported.
	var gated []checks.Entry
	add(apiserver.NewHub(h.Deps), &gated)
	add(storelocal.NewTTL(h.Deps), &gated)

	h.groups = []checks.Group{
		{Entries: ungated},
		{
			GateOK:    h.uptimeOK,
			GateLabel: cdeps.CheckHub,
			Entries:   gated,
		},
	}
}
