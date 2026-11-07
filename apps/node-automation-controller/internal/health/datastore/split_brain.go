// split_brain.go — the W12-SC2(i) multi-master split-brain
// signature of the stateful-masterless-services check: a
// master-role Service carrying >1 Ready endpoint two consecutive
// sweeps (an operator relabeling flap settles inside one) raises
// node_automation_stateful_service_multiple_masters — two pods
// answering the master role at once is an election split. Split out
// of stateful_masterless_services.go — see that file for the check
// and its Run.
package datastore

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// W12-SC2 — split-brain: a master-role Service carrying >1
// Ready endpoint must hold this many consecutive sweeps — an
// operator relabeling flap settles inside one.
const statefulMultiMasterMinStreak = 2

var (
	// W12-SC2 — the split-brain signal: 1 while a master-role
	// Service routes to more than one Ready pod for two consecutive
	// sweeps (two pods answering the master role at once).
	statefulServiceMultipleMastersGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_stateful_service_multiple_masters",
		Help: "1 while a master-role Service reports >1 Ready endpoints for >=2 consecutive sweeps — a multi-master split brain.",
	}, []string{"namespace", "service", "statefulset"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		statefulServiceMultipleMastersGauge)
}

// splitBrainWatch is the W12-SC2(i) multi-master signature's
// watchdog state (serial sweep — unguarded):
//   - streak: "ns/svc/sts" → consecutive sweeps the master-role
//     Service showed >1 Ready endpoints — a split-brain must hold
//     two sweeps to outlive a relabeling flap.
//   - emitted: the emitted-gauge ledger for
//     statefulServiceMultipleMastersGauge — a split-brain that
//     resolves loses its series via DeleteLabelValues.
type splitBrainWatch struct {
	streak  state.StreakLedger
	emitted state.GaugeLedger[string]
}

// eval records this sweep's ready-endpoint count for the candidate
// and flags the gauge once the >1 streak reaches the two-sweep
// minimum — the finding lands on the check's report, the series on
// the signature's.
func (w *splitBrainWatch) eval(c masterSvc, key string, nReady int,
	rep, sigRep *probefw.SweepReport) {
	// W12-SC2(i) — multi-master split brain: >1 Ready endpoint
	// on the master role two sweeps running. A relabeling flap
	// settles inside one sweep; two pods answering the role at
	// once is an election split.
	if nReady > 1 {
		if w.streak.Hit(key) >= statefulMultiMasterMinStreak {
			sigRep.Flag(statefulServiceMultipleMastersGauge, key,
				[]string{c.ns, c.svc, c.sts.Name})
			rep.Find(key + "(multiple_masters)")
		}
	} else {
		w.streak.Reset(key)
	}
}
