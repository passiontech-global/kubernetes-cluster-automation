// cluster_health_probes.go — the sweep module root: Setup and the
// prober. The 48 checks it drives live in per-domain subpackages
// under internal/health on top of the shared probefw framework; the
// roster itself is a registry concern — every check is a CheckReg
// row in internal/registry (the 45 always-on rows plus the three
// gated gitops rows), collected into Deps.CheckRegs in
// registry order, which IS the sweep order:
//
//   - ported — the five kuberhealthy "passive" HealthChecks that used
//     to run as periodic checker Pods in the kuberhealthy namespace
//     (infrastructure/base/kuberhealthy/checks/ in
//     passiontech-fluxcd). The sixth check in that dir,
//     cronjob-checker, is deliberately NOT ported — cronjob-catchup
//     already sweeps CronJobs cluster-wide.
//   - watchdogs — the workqueue/control-plane watchdogs:
//     kcm-workqueue-watchdog (C6) detects a kube-controller-manager
//     whose leader Lease still renews while its object controllers
//     stop reconciling — a "gray" failure a dead-KCM check cannot
//     see — plus operator-workqueue-watchdog (operator-workqueue-watchdog, which
//     AUTO-HEALS: outside a maintenance window the stuck leader pod
//     is deleted, 1h cooldown persisted on the Lease), the
//     scheduler watchdog and the mesh control-plane watchdog.
//   - nodehealth — node/pod/namespace wedge checks (node-hang
//     pre-cordon, image-pull storm, stranded local-PV pods, wedged
//     terminating namespaces).
//   - nethealth — network control-plane checks (coredns upstream,
//     linkerd endpoint sync + protocol-detection stall, cilium BPF
//     map pressure + node IPAM exhaustion).
//   - datastore — datastore operator health (scylla, rabbitmq
//     quorum + suspended listener, dragonfly sync storm, percona
//     quorum, stateful-masterless-services stateful-masterless-services, OLM subscriptions,
//     PVC resize stalls pvc-resize).
//   - gitops — argocd-app-stuck, flux-helmrelease-retries,
//     kargo-promotion-health plus the three gated gitops rows
//     (flux-kustomization-health, workload-scale-flapping,
//     imagepull-secret-auditor).
//
// Layout: each check lives in its domain package alongside its state
// maps and the NewXxxCheck constructor that builds it; the
// registry's health CheckReg rows are the single sweep-order roster.
// Adding a check is two touch points — a CheckReg row + the
// constructor in the check's file — instead of the five (constant,
// prober field, lastPass seed, constructor literal, checks row) the
// monolithic prober needed.
//
// Metric contract: results go out on the SAME series kuberhealthy
// exported — kuberhealthy_check{check,namespace,status} and
// kuberhealthy_check_seconds_since_success{check,namespace} — under
// the original HealthCheck names and the literal "kuberhealthy"
// namespace label, so the KuberhealthyCheckFailed /
// KuberhealthyCheckStale PrometheusRule alerts keep firing with zero
// PromQL or dashboard changes.
//
// Error accounting: a check FAIL is the product — it is reported via
// metrics and logged, never as a run error. Only apiserver/client
// failures count against the queue's run-error counters (IncError,
// same pattern as cronjob-catchup's dedupe List). A cancelled sweep
// context (SIGTERM mid-cycle) aborts the run silently — it is a
// shutdown, not a health signal, so no FAIL series and no run error
// are emitted for it.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// healthProbeConfigFromEnv resolves the check knobs once at Setup.
// It fills the sweep-level Timeouts itself and pulls each domain's
// knobs from the package that consumes them — the ported
// kuberhealthy checks' fields from the ported.*ConfigFromEnv
// resolvers, the kcm-workqueue-watchdog knobs from
// watchdogs.KCMConfigFromEnv, the cilium and linkerd nethealth knobs
// from the nethealth resolvers (without them the checks read
// zero-value thresholds).
func healthProbeConfigFromEnv() probefw.Config {
	return probefw.Config{
		Timeouts: probefw.TimeoutsConfig{
			// envx.GetenvDuration floors every duration knob at
			// 1s (the retired helpers accepted any d > 0) —
			// sub-second probe timeouts and persistence windows
			// were already pathological, so the tightened bound
			// changes no sane configuration.
			Check: envx.GetenvDuration("HEALTH_CHECK_TIMEOUT", 30*time.Second),
			// Bounds one check's share of the serial sweep — a hung
			// apiserver call used to stretch the whole cycle; past
			// the deadline the check's context is cancelled (the
			// in-flight call unwinds) and the sweep moves on. The
			// check's own error still surfaces as FAIL/infra, so
			// reporting semantics are unchanged — only the wait is
			// bounded.
			PerCheck: envx.GetenvDuration("HEALTH_PER_CHECK_TIMEOUT", 2*time.Minute),
		},
		DNS:         ported.DNSConfigFromEnv(),
		HTTPContent: ported.HTTPContentConfigFromEnv(),
		Pods:        ported.PodsConfigFromEnv(),
		Quota:       ported.QuotaConfigFromEnv(),
		KCM:         watchdogs.KCMConfigFromEnv(),
		Cilium:      nethealth.CiliumConfigFromEnv(),
		Datastore:   datastore.ConfigFromEnv(),
		Linkerd:     nethealth.LinkerdConfigFromEnv(),
	}
}

// checkEntry is one roster row: the check name — the
// kuberhealthy_check label value alerts key on — and the check
// instance Run() invokes.
type checkEntry struct {
	name  string
	check probefw.Check
}

// sharedHealsMaxAge bounds the shared Deps.Heals cooldown ledger —
// every self-healing check stamps into it, mostly under pod and
// controller names that die with the workload, so the sweep prunes
// stamps older than the widest cooldown the ledger serves (1h: the
// mesh watchdog's cilium-operator bounce; every other stamp is 30m).
const sharedHealsMaxAge = time.Hour

// clusterHealthProber is the thin sweep runner: the shared deps, the
// check registry run() iterates (built once at construction in the
// historical sweep order — each check instance colocates its own
// state with its logic in its own package), and the kuberhealthy
// series reporter. Check names are metric label values and must not
// change.
type clusterHealthProber struct {
	*probefw.Deps

	// boot stamps prober construction — report() lazily seeds a
	// never-passed check's staleness from boot (the semantics the
	// old 27-entry boot literal encoded), matching kuberhealthy's
	// count-from-check-creation behavior.
	boot time.Time

	// lastPass tracks the last OK per check name for the
	// seconds_since_success gauge — it holds REAL passes only; a
	// check with no entry yet counts staleness from p.boot (see
	// report), so a check that never passed still reports a growing
	// staleness. run() prunes names the swept roster no longer
	// carries, so a future dynamic roster cannot strand entries for
	// retired checks (bounded by construction today — the roster is
	// built once at boot). Deliberately NOT a state.CooldownSet/
	// FirstSeenLedger: this is an informational success clock for
	// the seconds_since_success gauge, not a suppression window —
	// there is no cooldown to gate and no streak to mature.
	lastPass map[string]time.Time

	// checks is the run() roster — built once at construction from
	// the collected CheckRegs in the order SetupModules collected
	// them (registry order — the historical sweep order).
	checks []checkEntry
}

// newClusterHealthProber wires the sweep runner from the module's
// registry-stamped Deps: probefw.NewDeps centralizes the shared
// check dependencies (clients, seams, the Prom client) and
// d.CheckRegs carries the roster SetupModules collected from the
// selected, enabled check rows — a mistyped registration fails boot
// here instead of silently dropping the check (see
// check_modules.go).
func newClusterHealthProber(d shared.Deps, cfg probefw.Config) (*clusterHealthProber, error) {
	// NodeReader is the manager's cached client; a nil Mgr (the
	// literally-constructed test Deps shape shared.Deps documents)
	// leaves it nil — the documented fall-back-to-ListNodes posture.
	var nodeReader kube.CachedNodeReader
	if d.Mgr != nil {
		nodeReader = d.Mgr.GetClient()
	}
	deps := probefw.NewDeps(d.Name, d.CS, d.Dyn, nodeReader, cfg)
	deps.Maintenance = d.Maintenance
	// The metadata client feeds ListPartialOrFallback's preferred
	// path (AllReplicaSets and the metadata-only censuses) — nil
	// keeps the CS/Dyn fallback the test Deps shape relies on.
	deps.Meta = d.Meta
	p := &clusterHealthProber{
		Deps:     deps,
		boot:     time.Now(),
		lastPass: map[string]time.Time{},
	}
	if err := p.appendCheckRegs(d.CheckRegs); err != nil {
		return nil, err
	}
	return p, nil
}

// Setup registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the registration gate lives
// in CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false"
// opts out); setupModules evaluates it and stamps Deps.Disabled —
// disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern. dyn feeds the CRD scans inside the
// self-healing checks (operator-workqueue-watchdog/stateful-masterless-services) — wired like every other
// dynamic-client module. Deps.CheckRegs carries the whole check
// roster — the registrations SetupModules collected from the
// selected, enabled check rows — a mistyped one fails boot here,
// not silently.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, setupConfigFromEnv, func(cfg setupConfig) error {
		p, err := newClusterHealthProber(d, cfg.probes)
		if err != nil {
			return err
		}
		// Surface the resolved HEALTH_* knobs once at registration so an
		// operator can tell from the logs which targets/thresholds the
		// checks run with (an unparseable env value silently falls back
		// to the default — the effective value is what matters here).
		logf.Log.WithName(d.Name).Info("registered",
			// checks surfaces the roster size — a -modules selection
			// that picks cluster-health-probes without any check row
			// sweeps an empty roster, which only this line reveals.
			"checks", len(p.checks),
			"interval", cfg.interval, "perCheckTimeout", p.Cfg.Timeouts.PerCheck,
			"dnsHostnames", p.Cfg.DNS.Hostnames,
			"checkTimeout", p.Cfg.Timeouts.Check, "httpURL", p.Cfg.HTTPContent.URL,
			"httpExpectedContent", p.Cfg.HTTPContent.Expected,
			"podCheckNamespace", p.Cfg.Pods.Namespace,
			"maxPodRestarts", p.Cfg.Pods.MaxRestarts,
			"podSkipDuration", p.Cfg.Pods.SkipDuration,
			"quotaThreshold", p.Cfg.Quota.Threshold,
			"kcmLeaseMaxAge", p.Cfg.KCM.LeaseMaxAge,
			"kcmFreezeMinAge", p.Cfg.KCM.FreezeMinAge)
		return shared.AddPeriodic(d.Mgr, d.Name, cfg.interval, p.run)
	})
}

// setupConfig couples the resolved per-check knobs with the sweep
// interval so SetupWithConfig can hand both to register as one value.
type setupConfig struct {
	probes   probefw.Config
	interval time.Duration
}

// setupConfigFromEnv resolves every module knob. SetupWithConfig runs
// it BEFORE the Deps.Disabled gate so knob-parse warnings still fire
// for a gated-off module — the codebase's parse-before-gate contract.
func setupConfigFromEnv() setupConfig {
	return setupConfig{
		probes: healthProbeConfigFromEnv(),
		// envx.GetenvDuration rejects <1s (the retired helper accepted
		// any d > 0) — a sub-second sweep interval was already a
		// hot-loop bug, never a sane setting.
		interval: envx.GetenvDuration("CLUSTER_HEALTH_PROBES_INTERVAL", 5*time.Minute),
	}
}

// checkParallelism bounds the sweep's worker pool — the B9
// head-of-line fix: 53 serial checks meant 3-4 slow Prometheus or
// cross-DC checks at the head of the roster delayed every
// fast-breaker check behind them by 6-10 minutes. Six concurrent
// checks keep one hung census from stretching the cycle while the
// per-check PerCheck deadline still bounds each member's share.
// Every shared mutable the pool touches is guarded: Deps.Heals is a
// locked CooldownSet, the maintenance verdict memoizes under its own
// mutex, and the sweep snapshot's memos lock per kind — the pool only
// removes the roster's serialization.
const checkParallelism = 6

// checkOutcome is one finished check's result, slotted by roster
// index. Workers write only their own slot; the report loop replays
// the slots in roster order so metric/log ordering stays the
// deterministic serial contract regardless of completion order.
type checkOutcome struct {
	name     string
	ran      bool
	pass     bool
	why      string
	infra    error
	timedOut bool
}

func (p *clusterHealthProber) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// One fresh cluster-state snapshot per sweep: the ~40 checks
	// that census pods/nodes/EndpointSlices/Services/Namespaces used
	// to each issue their own full LIST (~17 pod + ~11 node LISTs
	// per cycle); the ctx-carried memoizer turns that into one LIST
	// per resource per run. Checks invalidate it on their own
	// mutations via Deps.InvalidateSweep.
	ctx = probefw.WithSweepSnapshot(ctx)
	// Deps.Heals accumulates one stamp per healed target under keys
	// that outlive the object (pod/controller names) — bound the
	// shared ledger once per sweep at the widest cooldown it serves.
	p.Heals.PruneExpired(p.Now(), sharedHealsMaxAge)
	// lastPass is keyed by check name, so record the names this pass
	// actually sweeps — the prune after the loop needs the roster's
	// live set (the stateful-masterless pattern: prune the ledger
	// against the pass's seen keys).
	seen := make(map[string]bool, len(p.checks))
	for _, c := range p.checks {
		seen[c.name] = true
	}

	// Bounded worker pool: each check runs under its own PerCheck
	// deadline — a hung apiserver call still cancels only that
	// check's share — and slots its verdict into outcomes[idx].
	// Workers never fail (a check's error is the product, carried in
	// the outcome), so the group's error is always nil and g.Wait
	// just joins the pool.
	outcomes := make([]checkOutcome, len(p.checks))
	var g errgroup.Group
	g.SetLimit(checkParallelism)
	for i := range p.checks {
		idx, entry := i, p.checks[i]
		g.Go(func() error {
			// A cancelled sweep context (SIGTERM during
			// rollout/shutdown) is not a health signal: the slot
			// stays empty so no verdict is invented for a check the
			// dying pod never ran — the surviving leader's next
			// cycle reports it.
			if ctx.Err() == nil {
				outcomes[idx] = runCheckIsolated(entry, ctx,
					p.Cfg.Timeouts.PerCheck)
			}
			return nil
		})
	}
	_ = g.Wait()

	// A cancelled sweep context (SIGTERM during rollout/shutdown) is
	// not a health signal: emitting FAIL=1 or a run error now would
	// leave fake series behind on the dying pod. Bail out silently —
	// the surviving leader's next cycle reports (completed workers'
	// slots included: half a sweep's series is still half a fake
	// signal).
	if err := ctx.Err(); err != nil {
		log.V(1).Info("sweep context cancelled — bailing without reporting",
			"error", err)
		return nil // cancelled ctx is not a run error — bail silently
	}

	// Report in roster order — the ops contract's deterministic
	// series/log ordering — regardless of the order the pool
	// finished the checks in.
	for _, o := range outcomes {
		if !o.ran {
			continue // unreachable post-Wait without cancellation
		}
		if o.timedOut {
			log.Info("health check exceeded per-check timeout",
				"check", o.name)
		}
		p.report(o.name, o.pass)
		// A check FAIL is the product — it is reported via metrics and
		// logged, never as a run error. Only apiserver/client failures
		// count against the queue's run-error counters.
		if o.infra != nil {
			metrics.IncError(p.Name)
			log.Error(o.infra, "health check probe errored — marked FAIL",
				"check", o.name)
		} else if !o.pass {
			log.Info("health check FAIL", "check", o.name, "reason", o.why)
		}
	}
	// Drop lastPass entries for checks the pass did not sweep — a
	// cancelled sweep bails above without pruning, so only a full
	// pass shrinks the ledger.
	for name := range p.lastPass {
		if !seen[name] {
			delete(p.lastPass, name)
		}
	}
	return nil
}

// runCheckIsolated runs one check under its PerCheck deadline with a
// panic guard: a panic inside any of the ~50 check bodies used to
// take down the whole binary — one bad nil-map write in a single
// check killed every module the process hosts. The recovered panic
// surfaces as the check's Infra error (FAIL + queue IncError via the
// normal report path) so the sweep keeps its accounting contract:
// the check failed, the run did not.
func runCheckIsolated(entry checkEntry, ctx context.Context,
	perCheck time.Duration) (out checkOutcome) {

	out = checkOutcome{name: entry.name, ran: true}
	defer func() {
		if r := recover(); r != nil {
			out = checkOutcome{
				name:  entry.name,
				ran:   true,
				infra: fmt.Errorf("check panicked: %v", r),
			}
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, perCheck)
	defer cancel()
	res := entry.check.Run(cctx)
	out.pass = res.Pass
	out.why = res.Why
	out.infra = res.Infra
	out.timedOut = cctx.Err() == context.DeadlineExceeded
	return out
}

// report updates the kuberhealthy-compatible series for one check.
func (p *clusterHealthProber) report(name string, ok bool) {
	now := p.Now()
	if ok {
		p.lastPass[name] = now
	}
	// Lazy seed: a check with no recorded pass yet counts staleness
	// from prober boot — the semantics the old boot-time lastPass
	// literal encoded — so a never-passing check still alerts stale.
	last, seeded := p.lastPass[name]
	if !seeded {
		last = p.boot
	}
	since := now.Sub(last).Seconds()
	metrics.ObserveHealthCheck(name, ok, since)
}
