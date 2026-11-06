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
//   - ctr/     — ctr_tasks.go (31 tasks, 37 image healer, 39 ingest
//     GC) + ctr_meta.go (W10-KR3 meta.db corruption)
//   - cilium/  — cilium_*.go (32 agent, 35 init-stuck, 38 IPAM, B1
//     envoy, B4 MTU, W5.6 WG peers, W7-H3 LRP DNS)
//   - guards/  — dstate_scopes.go (A2 zombie, W7-H1 D-state, W7-H2
//     scopes), psi_thrash.go (W2), journald.go (A5),
//     spegel_calico_netns.go (W7-H4/H7, W9 netns)
//   - runtime/ — runtime_resource_guards.go (the six W10 guards),
//     disk_bloat.go (W6.3), deep_failure_checks.go (W10-KR1/ST2)
//   - wdeps/   — the shared dependency surface (Config/Seams, Deps,
//     CycleEnv, Check, the CtrTask machinery, the journal tracker,
//     the node_agent_* textfile writer) — the seam deps.go
//     documented as the blocker for this split.
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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/pods"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Hygiene runs the worker checks on one ticker. It is the
// orchestrator only: everything the checks consume (config, procfs
// view, state store, journal tracker, metric vecs, cross-check
// shared state) lives on the embedded *wdeps.Deps — see
// wdeps/deps.go. The embed keeps the test contract compiling:
// h.Cfg, h.StallFails, h.CiliumAgentKilled etc. promote through it.
type Hygiene struct {
	*wdeps.Deps

	// checks is the ordered per-Cycle dispatch list — initChecks
	// fills it; the order preserves the sequence the checks ran
	// before the table existed. Cycle wraps it into a checks.Group
	// for platform/checks.Dispatch (the Entry.Run closures bind
	// the per-cycle env — see Cycle). The checks are also named
	// fields so tests can reach per-check state and the old
	// Hygiene-method forwarders resolve without a list walk.
	checks           []wdeps.Check
	stall            *kubelet.StallCheck
	watch            *kubelet.WatchWedgeCheck
	teardown         *pods.PodTeardownCheck
	konn             *pods.KonnCheck
	dns              *pods.DNSResolvCheck
	syncloop         *kubelet.SyncloopCheck
	ctrsock          *kubelet.CtrsockCheck
	ctrTasks         *ctr.CtrTasksCheck
	ingestGC         *ctr.IngestGCCheck
	cilium           *cilium.CiliumCheck
	ciliumInit       *cilium.CiliumInitCheck
	ctrImages        *ctr.CtrImagesCheck
	ciliumIPAM       *cilium.CiliumIPAMCheck
	ciliumEnvoy      *cilium.CiliumEnvoyCheck
	ciliumMTU        *cilium.CiliumMTUCheck
	ciliumWG         *cilium.CiliumWGCheck
	diskBloat        *runtime.DiskBloatCheck
	journald         *guards.JournaldCheck
	zombies          *guards.ZombieStormCheck
	dstate           *guards.DstateCheck
	scopes           *guards.ScopesCheck
	ciliumLRP        *cilium.CiliumLRPCheck
	spegel           *guards.SpegelCheck
	calico           *guards.CalicoCheck
	cniNetns         *guards.CNINetnsCheck
	psiThrash        *guards.PSIThrashCheck
	ctrMeta          *ctr.CtrMetaCheck
	hostOOM          *runtime.HostOOMCheck
	orphanHP         *runtime.OrphanHPCheck
	cgroupDying      *runtime.CgroupDyingCheck
	systemdSessions  *runtime.SystemdSessionCheck
	overlayFSStale   *runtime.OverlayFSStaleCheck
	ioPressure       *runtime.IOPressureCheck
	conntrackLiberal *runtime.ConntrackLiberalCheck
	clockJump        *runtime.ClockJumpCheck
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	if cfg.Client == nil {
		// The first Cycle LIST would nil-pointer panic — the check
		// contract is "never panic", so reject at construction.
		return nil, errors.New("workerhygiene: Config.Client is required")
	}
	cfg.ApplyDefaults()
	d := &wdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
	// Now MUST close over the live config field, not the cfg
	// parameter: tests re-stub h.Cfg.Seams.NowFn after New returns and
	// the store has to observe the new clock (hoststate.New doc).
	d.State = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return d.Cfg.Seams.NowFn() }, logger)
	d.JournalReads = journalwatch.Tracker{
		Needed: cfg.Journal.UnreadableNeeded,
		Dirs:   cfg.Journal.Dirs,
	}

	d.Cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_cycles_total",
		Help: "Worker-hygiene check cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	d.Actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_actions_total",
		Help: "Worker-hygiene remediation actions by check and action " +
			"(force_delete|pod_delete|sigkill|pause_kill|restart|rm_dir|shim_kill|image_rm|remediate).",
	}, []string{"check", "action"})
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

	h := &Hygiene{Deps: d}
	if reg != nil {
		for _, c := range []prometheus.Collector{
			d.Cycles, d.Actions, d.CiliumAllocated, d.CiliumLeaked,
			d.CtrIngestsCleaned,
		} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register workerhygiene metrics: %w", err)
			}
		}
	}
	h.initChecks()
	return h, nil
}

// Name identifies the subsystem for logging.
func (h *Hygiene) Name() string { return "workerhygiene" }

// Run checks immediately, then every Interval until ctx is cancelled.
// The T15 kubelet watchdog feeder runs on its own faster ticker in
// parallel — the controllerhygiene runFeeder pattern (shell had a
// dedicated systemd unit looping every ~15s).
func (h *Hygiene) Run(ctx context.Context) {
	if !h.Cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		cycle.Idle(ctx)
		return
	}
	// The tick self-gates on KubeletFeederActive() each round, so a
	// node dropped from systemd_watchdog_hosts (unit file pruned) or
	// a WD_SIG_KUBELET_WATCHDOG=off conf rewrite idles without an
	// agent restart. The wait makes Run's return coincide with the
	// feeder's exit — a restarted Run must never stack a second
	// feeder, and callers may tear down cfg paths on return.
	// The feeder gets its OWN cancel: a bare `defer wg.Wait()` also
	// runs during panic unwinding, but the feeder only exits on
	// ctx.Done() — nothing cancels ctx on a Cycle panic, so Run
	// parked forever and the agent's recover never fired (the
	// subsystem died silently). Cancelling first bounds the wait on
	// EVERY exit path — panic included — so the panic reaches the
	// agent recover and a restarted Run finds the old feeder gone.
	fctx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			// A feeder panic must not take the daemon down — the
			// agent's recover only wraps Run itself, not
			// goroutines Run spawned.
			if r := recover(); r != nil {
				logger().Error("workerhygiene: kubelet watchdog feeder "+
					"panicked — feeder dead until Run restart",
					"panic", r)
			}
		}()
		kubelet.RunKubeletFeeder(fctx, h.Deps)
	}()
	// Feeder setup precedes the FIRST Cycle too — a first-Cycle
	// panic must tear down a running feeder, not stack a second
	// one behind it on the agent's restart.
	defer func() {
		stop()
		wg.Wait()
	}()
	cycle.Every("workerhygiene", h.Cfg.Interval, h.Cycle).Run(ctx)
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
	if up, err := h.Proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
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
	pidsOnce := func() []int {
		if pids == nil {
			// ReadDir-order pids, error swallowed like the old
			// procPIDs — a nil result retries the scan on the
			// next pidsOnce call (same as before).
			pids, _ = h.Proc.PIDs()
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
			j, err := h.Cfg.Seams.JournalFn(ctx)
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
	if h.Cfg.WatchdogSrc != nil {
		h.Cfg.Watchdog = h.Cfg.WatchdogSrc.Get()
	}
	if wd := h.Cfg.Watchdog; wd != nil && h.Cfg.WatchdogSrc != nil {
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
	sigOn := func(name string) bool {
		return h.Cfg.Watchdog == nil || h.Cfg.Watchdog.SignalEnabled(name)
	}
	// The checks dispatch through the shared ordered dispatcher —
	// the entries are rebuilt each cycle because checks.Entry.Run
	// takes no env: every entry closes over THIS cycle's env (the
	// pod LIST, the workerActive gate and the lazy once-per-cycle
	// snapshots). One small slice per Interval. A single UNGATED
	// group: the unit-file and uptime gates return early above,
	// and workerActive gates inside each check (per-check
	// cycles{check,"gated"}) — none map onto Group.GateOK, whose
	// skip counts "uptime_gate" and would starve the "disabled"
	// count of a kill-switched check. Entry order IS h.checks
	// order — load-bearing, same as the hand-rolled loop; a
	// WD_SIG_<NAME>=off check counts cycles{check,"disabled"}
	// exactly like the old run gate.
	env := &wdeps.CycleEnv{
		Pods:         pods,
		APIOK:        apiOK,
		WorkerActive: workerActive,
		TasksOnce:    tasksOnce,
		PidsOnce:     pidsOnce,
		JournalOnce:  journalOnce,
	}
	entries := make([]checks.Entry, 0, len(h.checks))
	for _, c := range h.checks {
		entries = append(entries, checks.Entry{
			Name: c.Name(),
			Run:  func(ctx context.Context) { c.Run(ctx, env) },
		})
	}
	checks.Dispatch(ctx, sigOn, h.Cycles, []checks.Group{{Entries: entries}})
	// W10 node_agent_* gauges — one textfile per cycle carrying the
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
