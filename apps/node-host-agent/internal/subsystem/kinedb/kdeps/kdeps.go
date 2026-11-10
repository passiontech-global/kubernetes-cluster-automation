// Package kdeps is the shared dependency surface of the kinedb
// per-domain split — the same role cdeps plays for
// controllerhygiene and wdeps for workerhygiene. The three kine DB
// VM loops (probe, compact-guard, maint — see the parent kinedb
// package doc for the shell-script lineage) are independent
// cadences, but they share one Config, one metric registry mirror,
// one GuardStateDir/hoststate store, one container-runtime exec
// plumbing (psql inside the postgres container is how EVERY check
// talks to postgres), one stack-.env credential read and one
// top-churn hand-off (the probe samples it, the guard emits it).
// That shared half lives here so no domain package needs to import
// a sibling — the arrows are probe|compact|maint -> kdeps ->
// platform only.
package kdeps

import (
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
)

// Deps is the shared state every domain loop consumes — the split's
// answer to the old `k *KineDB` receiver. The probe/compact/maint
// worker structs each hold a `d *Deps` and read config, metrics,
// the state store and the exec/psql plumbing through it, never
// touching the facade. All fields are exported: the root KineDB
// embeds *Deps so the same fields also resolve as k.<Field> —
// the test contract (cfg seam re-stubs, k.Cfg, k.State) keeps
// compiling.
type Deps struct {
	Cfg Config
	M   *Metrics

	// State is the hoststate Store bound to GuardStateDir — the
	// last-* rate budgets (last-pgb-restart, last-dead-tuple-vacuum,
	// last-kine-analyze) go through its RateOK/RateSpend/RateTrySpend.
	State *hoststate.Store

	// ChurnTop is the kine-churn top-5 churn result computed by the
	// probe loop (churn window watermark lives in GuardStateDir)
	// and emitted by the guard cycle into kine-compact-guard.prom.
	// ChurnKeys is the W24 per-object twin: the same window sampled
	// GROUP BY full key (not the /registry/<group>/<resource>
	// prefix) so an SSA managedFields ping-pong names its exact
	// victim object on kine_db_top_hotkey_revisions_5m{key}.
	// ChurnMu guards both slice headers — probe and compact-guard
	// cycles run on separate goroutines (Run spawns one loop each).
	ChurnMu   sync.RWMutex
	ChurnTop  []ChurnEntry
	ChurnKeys []ChurnKeyEntry
}

// ChurnEntry is one resource prefix's revision count in the last
// churn window — ordered by count desc, top churnTopN only.
type ChurnEntry struct {
	Resource string
	Revs     int64
}

// ChurnKeyEntry is one full Kine object key's revision count in the
// last churn window (the "/registry/" prefix already stripped) —
// ordered by count desc, top churnTopN only, and only keys with
// >= churnKeyMinRevs revisions (the ping-pong floor — below it a
// hot key is ordinary write volume, not an SSA fight).
type ChurnKeyEntry struct {
	Key  string
	Revs int64
}

// NewDeps applies the Config defaults, builds the collector mirror
// and binds the GuardStateDir hoststate store — the construction
// the facade's New and the kdepstest fixture both need (the facade
// alone registers the collectors on a registry).
func NewDeps(cfg Config) (*Deps, error) {
	if err := cfg.ApplyDefaults(); err != nil {
		return nil, err
	}
	d := &Deps{Cfg: cfg, M: NewMetrics()}
	// GuardStateDir is the subsystem-private compact-guard dir, not
	// the shared WatchdogStateDir, and there is no log file —
	// the explicit-argument StoreAt form covers it.
	d.State = subframe.StoreAt(cfg.GuardStateDir, "", cfg.Clock, logger)
	return d, nil
}
