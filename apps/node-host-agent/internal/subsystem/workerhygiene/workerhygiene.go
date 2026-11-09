// Package workerhygiene ports the worker-only node-watchdog shell
// modules (WD_REQUIRES: uptime k0sworker) into one agent subsystem.
// This file is the orchestrator only — the checks live in
// per-domain packages under workerhygiene/:
//
//   - kubelet/ — kubelet.go (05 stall, 06 watch-wedge),
//     kubelet_feeder.go (T15 healthz feeder + remediate),
//     kubelet_syncloop.go (A4 PLEG + containerd-sock probes)
//   - pods/    — pod_teardown.go (36 teardown, 30 konnectivity,
//     33 dns-resolv)
//   - ctr/     — ctr_tasks.go (31 tasks), ctr_images.go (37 image
//     healer), ctr_ingest_gc.go (39 ingest GC), ctr_shims.go (shared
//     shim scope) + ctr_meta.go (meta-db-corruption meta.db corruption)
//   - cilium/  — cilium_*.go (32 agent, 35 init-stuck, 38 IPAM, B1
//     envoy, B4 MTU, cilium-wg-peer-gc WG peers, envoy-xds-lrp LRP DNS)
//   - guards/  — dstate_scopes.go (A2 zombie, d-state-storm D-state, systemd-scopes
//     scopes), psi_thrash.go (psi-memory-thrash), journald.go (A5),
//     spegel.go / calico.go / cni_netns.go (spegel-mirror/calico-hygiene, cni-netns-gc)
//   - runtime/ — runtime_<name>.go (the eight runtime-resource
//     guards, one file each — see runtime_common.go for the family
//     overview),
//     disk_bloat.go (disk-bloat), deep_failure_checks.go (deep-failure-checks)
//   - wdeps/   — the shared dependency surface (Config/Seams, Deps,
//     CycleEnv, Check, the CtrTask machinery, the journal tracker,
//     the node_agent_* textfile writer). The Config domain groups
//     are split into wdeps/config_<domain>.go.
//
// Differences from the shell versions (documented, behaviour-equivalent):
//   - `k0s ctr tasks ls` / `tasks kill` is replaced by scanning the
//     containerd runtime-v2 task dirs + sandbox-controller shim dirs:
//     config.json carries io.kubernetes.pod.uid / .container.name and
//     init.pid the host pid — the node-side ground truth the modules
//     already used for teardown verification. No ctr socket needed.
//   - /proc reads go through ProcRoot (default /proc — the DaemonSet
//     runs hostPID so in-pod /proc IS host /proc).
//   - consecutive-* counters are in-memory (agent restarts are rare;
//     the hysteresis cost of losing one count is bounded by Interval).
//   - One pod LIST per cycle feeds all three checks — the shell
//     queried per module; sharing gives one consistent apiserver
//     verdict and halves API calls.
package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// walkResult is one memoized WalkBytes call in the per-cycle cache.
type walkResult struct {
	total     int64
	truncated bool
}

// Hygiene runs the worker checks on one ticker. It is the
// orchestrator only: everything the checks consume (config, procfs
// view, state store, journal tracker, metric vecs, cross-check
// shared state) lives on the embedded *wdeps.Deps — see
// wdeps/deps.go. The embed keeps the test contract compiling:
// h.Cfg, h.CiliumAgentKilled, h.<series field> etc. promote
// through it.
type Hygiene struct {
	*wdeps.Deps

	// envCell is the per-cycle CycleEnv cell the dispatch entries
	// read through: initChecks builds the checks.Entry table ONCE
	// (each Run closes over this cell, not a per-cycle env) and
	// Cycle assigns a fresh CycleEnv into it each round. Dispatch
	// runs synchronously in the Cycle goroutine and no check
	// retains the pointer past its Run call, so the swap is
	// race-free — the controllerhygiene/nethealth static-table
	// pattern.
	envCell *wdeps.CycleEnv

	// checks is the ordered check list initChecks fills — Check
	// walks it for the domain test packages (wdepstest.Check is
	// the typed path; the old per-check named fields are gone).
	checks []wdeps.Check

	// groups is the static dispatch table initChecks builds once —
	// a single UNGATED checks.Group (the unit-file and uptime gates
	// return early in Cycle and workerActive gates inside each
	// check, so nothing maps onto Group.GateOK). Entry order IS
	// checks order — load-bearing.
	groups []checks.Group

	// feeder is the T15 kubelet watchdog feeder — not a Check (it
	// runs on its own faster ticker Spawned from Run, outside the
	// dispatch list) but owned here so tests reach its streak
	// through Feeder().
	feeder *kubelet.Feeder
}

// The subsystem-convention export surface cmd/agent wires against:
// Config and EnvDeps alias the canonical wdeps types so
// workerhygiene.Config IS wdeps.Config (no drift possible), and
// ConfigFromEnv forwards to the env resolution that lives in wdeps
// beside the defaults it fills. The name stays here because the
// subsystem convention puts it next to New.
type (
	Config  = wdeps.Config
	EnvDeps = wdeps.EnvDeps
)

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob workerhygiene
// reads — implementation lives in wdeps (it owns the Config
// defaults).
func ConfigFromEnv(d EnvDeps) Config { return wdeps.ConfigFromEnv(d) }

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	if cfg.Client == nil {
		// The first Cycle LIST would nil-pointer panic — the check
		// contract is "never panic", so reject at construction.
		return nil, errors.New("workerhygiene: Config.Client is required")
	}
	cfg.ApplyDefaults()
	d := &wdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
	// The store binds the shared timex.Cell over Seams.Host (NOT the
	// promoted Base.Clock — the live seam stays there): tests re-stub
	// via h.Cfg.Seams.Host.Clock.Set after New returns and the store
	// observes the new clock (hoststate.New doc).
	d.State = subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		cfg.Seams.Host.Clock, logger)
	// Streak contract lives in journalwatch.NewUnreadableTrackerForOwner:
	// each hygiene persists its OWN consecutive-journal-unreadable-<owner>
	// streak file and holds the shared state-journal-unreadable latch
	// under its own id — one side's failed read never inflates or
	// resets the other's count, while the latch FILE still arbitrates
	// the single shared episode (Store's multi-owner ExitFrom).
	d.JournalReads = journalwatch.NewUnreadableTrackerForOwner(
		d.State, cfg.Journal.Dirs, cfg.Journal.UnreadableNeeded,
		journalwatch.OwnerWorkerHygiene)

	d.Cycles, d.Actions = subframe.Counters("workerhygiene",
		"Worker-hygiene check cycles by check and result (ok|abort|gated).",
		"Worker-hygiene remediation actions by check and action "+
			"(force_delete|pod_delete|sigkill|pause_kill|restart|rm_dir|shim_kill|image_rm|remediate|sighup|swap_cap|agent_kill).")
	d.CiliumAllocated = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_allocated_ips",
		Help: "IPv4 addresses cilium IPAM reports allocated on this node.",
	})
	d.CiliumLeaked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_leaked_ips",
		Help: "Allocated cilium IPs not held by a non-hostNetwork Running pod on this node (leaked).",
	})
	d.CtrIngestsCleaned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_ctr_ingests_cleaned_total",
		Help: "Stale containerd content ingest dirs removed by the ingest GC (39).",
	})

	h := &Hygiene{Deps: d, envCell: &wdeps.CycleEnv{}}
	if err := subframe.RegisterAll(reg,
		d.Cycles, d.Actions, d.CiliumAllocated, d.CiliumLeaked,
		d.CtrIngestsCleaned); err != nil {
		return nil, fmt.Errorf("register workerhygiene metrics: %w", err)
	}
	h.initChecks()
	h.feeder = kubelet.NewFeeder(d)
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "workerhygiene" }

// Check returns the registered check with the given wdeps.Check*
// name, or nil. This is the exported path to check state — the
// domain test packages (package X_test beside the check) reach
// their check's streak/latch bookkeeping through it via
// wdepstest.Check.
func (h *Hygiene) Check(name string) wdeps.Check {
	for _, c := range h.checks {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// Feeder returns the T15 kubelet watchdog feeder — the exported
// path to its state for the domain test packages.
func (h *Hygiene) Feeder() *kubelet.Feeder { return h.feeder }

// Run checks immediately, then every Interval until ctx is cancelled.
// The T15 kubelet watchdog feeder runs on its own faster ticker in
// parallel — the controllerhygiene runFeeder pattern (shell had a
// dedicated systemd unit looping every ~15s).
func (h *Hygiene) Run(ctx context.Context) {
	// The tick self-gates on Feeder.Active() each round, so a
	// node dropped from systemd_watchdog_hosts (unit file pruned) or
	// a WD_SIG_KUBELET_WATCHDOG=off conf rewrite idles without an
	// agent restart. cycle.Spawn owns the feeder lifecycle: the
	// feeder runs on a ctx derived from ctx, a feeder panic is
	// recovered + logged inside the goroutine (the agent's recover
	// only wraps Run itself — a feeder defect must not take the
	// daemon down), and stop() cancels the child ctx THEN waits.
	// Deferring stop makes Run's return coincide with the feeder's
	// exit on EVERY exit path — panic unwinding included (the
	// "cancel before wait" argument lives on cycle.Spawn), so a
	// restarted Run never stacks a second feeder and callers may
	// tear down cfg paths on return. Spawn starts the goroutine
	// before returning, so even a first-Cycle panic unwinds past a
	// registered stop that tears the running feeder down.
	stop := cycle.Spawn(ctx, "workerhygiene kubelet watchdog feeder",
		func(fctx context.Context) { h.feeder.Run(fctx) })
	defer stop()
	cycle.Every("workerhygiene", h.Cfg.Interval, h.runCycle).Run(ctx)
}

// runCycle executes one Cycle under the per-cycle deadline
// (Config.CycleTimeout). Run drives Cycle synchronously inside the
// ticker loop (controllerhygiene runCycle parity), so without the
// bound a single hung child — a wedged systemd.Active, a stalled
// pod LIST, a containerd task-map walk on a dead runtime — would
// starve every later check for as long as it hangs. Every spawned
// command and HTTP probe is CommandContext/request-ctx aware, so
// cancellation actually interrupts the stall. Hitting the deadline
// is a degraded cycle, not a failure — it is logged so a
// silently-starved guard shows up in the watchdog tail.
func (h *Hygiene) runCycle(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, h.Cfg.CycleTimeout)
	defer cancel()
	h.Cycle(cctx)
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		h.State.AppendLogWarn(fmt.Sprintf(
			"workerhygiene: cycle deadline %s exceeded — "+
				"stalled check(s) aborted", h.Cfg.CycleTimeout))
	}
}

// Cycle runs one round of every check in the ordered dispatch
// list. The k0sworker unit file gates everything (WD_REQUIRES:
// k0sworker) — controllers and test envs without the unit are a
// silent no-op. Each check must never panic and degrades to no-op
// on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.Cfg.K0sWorkerUnitFile); err != nil {
		h.Cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	// uptime gate (WD_REQUIRES: uptime k0sworker — the shell also
	// required uptime >= 1200s): a freshly rebooted node gets grace
	// before any destructive check runs — Terminating ages surviving
	// a reboot must not trigger action inside the first minutes.
	if up, err := h.Proc.UptimeSeconds(); err == nil && up < wdeps.MinUptimeSeconds {
		h.Cycles.WithLabelValues("all", "uptime_gate").Inc()
		return
	}
	// One LIST feeds teardown + konnectivity-pod-lookup + dns checks.
	// The field selector is still sent (production pre-filter) but the
	// node match is re-checked per pod — the fake clientset ignores
	// selectors, and a wrong match is a wrong kill.
	pods, apiOK := h.listNodePods(ctx)
	// The containerd task map reads EVERY task dir's config.json —
	// build it lazily, at most once per cycle, shared between the
	// teardown, stall and dns checks. Most cycles neither needs it (no
	// pod Terminating, no dns-pod running) so it stays unbuilt. The
	// second return is the root-reachability flag: false = a task
	// root could not be listed, so "zero live tasks" verdicts are
	// unverifiable (teardown fails closed).
	var tasks map[string][]wdeps.CtrTask
	tasksComplete := true
	tasksOnce := func() (map[string][]wdeps.CtrTask, bool) {
		if tasks == nil {
			tasks, tasksComplete = h.BuildTaskMap()
		}
		return tasks, tasksComplete
	}
	// One /proc pid-dir listing feeds every per-cycle process scan
	// (konnectivity proxy-agent sweep, ctr-tasks orphan shims +
	// per-dir leftover kills, zombie-storm count) — independent
	// ReadDir sweeps were 3-5 full walks of a several-thousand-entry
	// dir. Lazy like the task map: most cycles never need it.
	var pids []int
	pidsLogged := false
	pidsOnce := func() []int {
		if pids == nil {
			// ReadDir-order pids. Same retry shape as the old
			// procPIDs closure: an error leaves the cache nil,
			// so the same cycle's later pidsOnce calls retry
			// the read. The delta is observability only — the
			// first failure per cycle warns, where the old
			// code swept zero pids silently (indistinguishable
			// from a genuinely empty /proc).
			if p, err := h.Proc.PIDs(); err != nil {
				if !pidsLogged {
					h.State.AppendLogWarn(fmt.Sprintf(
						"proc pid listing failed — process scans skipped this pass: %v", err))
					pidsLogged = true
				}
			} else {
				pids = p
			}
		}
		return pids
	}
	// The k0sworker journal snapshot is shared between 05/06 — the
	// runner dumped it once per run for the same reason (journald is
	// slow on CPU-starved nodes; two windows could disagree). Lazy:
	// an idle cycle never touches journald.
	journal := ""
	journalSet := false
	journalOnce := func() string {
		if !journalSet {
			journalSet = true
			j, err := h.Cfg.Seams.Host.JournalFn(ctx)
			switch {
			case err != nil:
				h.State.AppendLog(fmt.Sprintf("k0sworker journal snapshot failed: %v", err))
				h.NoteJournalRead(false,
					fmt.Sprintf("snapshot failed: %v", err))
			case journalwatch.FilesGone(j):
				h.NoteJournalRead(false,
					"journalctl reports no journal files")
			case strings.TrimSpace(j) != "":
				h.NoteJournalRead(true, "")
				// err==nil && empty: a quiet 10m window is
				// ambiguous (A5's unfiltered probe owns the
				// disambiguation) — it neither counts the
				// streak nor clears it.
			}
			journal = j
		}
		return journal
	}
	// Refresh the conf every cycle when a source is wired — hostconfig
	// rewrites /etc/node-watchdog.conf mid-run (WD_SIG_* kill switches,
	// API_BACKENDS); the runner re-sourced it every run.
	wd, sigOn := h.Cfg.BeginCycle()
	if wd != nil && h.Cfg.WatchdogSrc != nil {
		h.Cfg.APIBackends = wd.APIBackendIPs()
	}
	// workerActive is the WD_REQUIRES k0sworker gate for ALL worker
	// checks — a node where k0sworker is intentionally down/inactive
	// skips every check exactly like the runner did. A nil Systemd
	// client (tests, unwired agent) can't answer → treat as active
	// so the checks still run on their other evidence. A client that
	// answers with an ERROR (dbus down, systemctl missing) is
	// different from nil — the gate is wired but unverifiable, so
	// fail closed: gate the checks off this cycle rather than risk
	// hygiene actions on a possibly intentionally-downed worker.
	workerActive := true
	if h.Cfg.Systemd != nil {
		if active, err := h.Cfg.Systemd.Active(ctx, "k0sworker.service"); err != nil {
			logger().Warn("workerhygiene: k0sworker is-active probe "+
				"failed — worker checks gated off this cycle "+
				"(fail closed)",
				"unit", "k0sworker.service", "error", err)
			workerActive = false
		} else {
			workerActive = active
		}
	}
	// B1: an agent kill this cycle also restarts cilium-envoy — the
	// flag is reset before any check runs.
	h.CiliumAgentKilled = false
	// The dispatch table is static — initChecks built the
	// checks.Entry slice once and each Run reads the env through
	// h.envCell, so Cycle only refreshes the cell's contents: the
	// pod LIST, the workerActive gate and the lazy once-per-cycle
	// snapshots. Each once-closure still captures THIS cycle's
	// vars, so a stale env can never leak into the next round, and
	// Dispatch is synchronous on this goroutine with no check
	// retaining the env pointer past Run — the swap is race-free.
	// A single UNGATED group: the unit-file and uptime gates return
	// early above, and workerActive gates inside each check
	// (per-check cycles{check,"gated"}) — none map onto
	// Group.GateOK, whose skip counts "uptime_gate" and would
	// starve the "disabled" count of a kill-switched check.
	// WD_SIG_<NAME>=off counts cycles{check,"disabled"} exactly
	// like the old run gate.
	// WalkBytes results memoize per cycle too — the disk-bloat scan
	// and the writable-layer scan walk the same overlayfs snapshot
	// and pod-volume dirs; the cache halves the IO on the disk that
	// is already full. Lazy like the other once-snapshots: an idle
	// cycle never walks anything.
	walkCache := map[string]walkResult{}
	walkOnce := func(root string) (int64, bool) {
		if r, ok := walkCache[root]; ok {
			return r.total, r.truncated
		}
		total, truncated := h.WalkBytes(root)
		walkCache[root] = walkResult{total: total, truncated: truncated}
		return total, truncated
	}
	*h.envCell = wdeps.CycleEnv{
		Pods:         pods,
		APIOK:        apiOK,
		WorkerActive: workerActive,
		TasksOnce:    tasksOnce,
		PidsOnce:     pidsOnce,
		JournalOnce:  journalOnce,
		WalkOnce:     walkOnce,
	}
	checks.Dispatch(ctx, sigOn, h.Cycles, h.groups)
	// node_agent_* gauges — one textfile per cycle carrying the
	// OOM/conntrack counters and the orphan-hostpath measurements
	// the checks above just refreshed.
	h.WriteNodeAgentPromTextfile()
	// BUG-H1: the periodic watchdog heartbeat lives HERE now —
	// nodereporter used to refresh last-run every Cycle, which made
	// its own WatchdogStale probe permanently blind. The hygiene
	// Cycle owns the refresh (controllerhygiene/nethealth do the
	// same on non-worker nodes); gated early-returns above skip it
	// so a node where the checks never ran does not claim a run.
	h.State.Heartbeat()
}

// listNodePods lists pods scheduled to this node; apiOK=false means
// the LIST failed — checks treat it as "apiserver unreachable"
// (inconclusive: keep counters/latches, never act).
func (h *Hygiene) listNodePods(ctx context.Context) ([]corev1.Pod, bool) {
	list, err := h.Cfg.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.Cfg.NodeName,
	})
	if err != nil {
		h.State.AppendLog(fmt.Sprintf(
			"suspect: pod list failed node=%s: %v — pod checks inconclusive this cycle",
			h.Cfg.NodeName, err))
		return nil, false
	}
	pods := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NodeName == h.Cfg.NodeName {
			pods = append(pods, list.Items[i])
		}
	}
	return pods, true
}
