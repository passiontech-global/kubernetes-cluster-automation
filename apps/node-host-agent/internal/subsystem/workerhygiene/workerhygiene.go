// Package workerhygiene ports the worker-only node-watchdog shell
// modules (WD_REQUIRES: uptime k0sworker) into one agent subsystem:
//
//   - 05-kubelet-stall.sh       — sig1/sig2/kubelet-10250: informer
//     zombie journal spam, phantom pods (>=5 pod dirs, zero live
//     tasks), or a dead :10250 healthz → consecutive-gated k0sworker
//     restart + state-kubelet-runtime-stall latch.
//   - 06-kubelet-watch-wedge.sh — sig16: pods assigned to this node in
//     the API for >15m without a kubelet pod dir → kubelet watch
//     stream wedge → state-kubelet-watch-wedge + k0sworker restart
//     (shared last-restart budget; gated when ALL apiserver backends
//     are stale — upstream wedge, restart useless).
//   - 36-pod-teardown.sh   — sig16: pods stuck Terminating with zero
//     live containerd tasks get force-deleted (verified object
//     cleanup, never while a task is alive); pods Terminating >30m
//     whose task dirs still exist = node-side wedge →
//     state-pod-teardown-wedged latch for the NPD→NHC→SNR reboot path.
//   - 30-konnectivity.sh   — sig6: konnectivity-agent's
//     agent-identifiers=host=<IP> is baked into env at POD creation —
//     after a node InternalIP change the pod keeps registering the old
//     IP and konnectivity-server can't route dials (kubectl logs/exec
//     timeout while the node looks fine, incident 2026-09-13). Remedy:
//     recreate the konnectivity-agent pod so a fresh sandbox gets the
//     new baked env.
//   - 33-dns-resolv-drift.sh — sig12: kubelet snapshots host
//     /etc/resolv.conf into dnsPolicy:Default pods at sandbox create;
//     a resolv.conf repoint never reaches running pods (incident
//     2026-09-15: node-local-dns kept nameserver 8.8.8.8 → "." forwarded
//     to public DNS → api.passiontech.internal NXDOMAIN ~29h). Remedy:
//     SIGKILL the pod's PAUSE pid — kubelet recreates the sandbox with
//     the fresh resolv.conf (killing the app container keeps the old
//     sandbox and changes nothing).
//   - 31-ctr-tasks.sh      — sig7: wedged containerd task dirs (init
//     dead/zombie >=5m, half-written dir without init.pid >=5m, or
//     missing log.json >=5m) get their shim killed + dir removed;
//     orphan containerd-shim-runc-v2 processes whose task dir vanished
//     get SIGKILLed.
//   - 32-cilium.sh         — sig9: cilium-agent :9879 healthz down →
//     state-cilium-agent-down + SIGKILL the agent container so
//     kubelet restarts it (shared last-cilium-restart budget).
//   - 35-cilium-init-stuck.sh — sig15: endpoints stuck in
//     reserved:init (informer wedge, healthz still OK) →
//     state-cilium-init-stuck + SIGKILL cilium-agent.
//   - 37-ctr-image-healer.sh — pods stuck Waiting
//     (CreateContainerError/ErrImagePull/ImagePullBackOff) whose
//     message is a corrupted containerd layer/content-store error
//     (missing content digest, failed layer extraction, missing
//     parent snapshot) get their image removed via `ctr images rm
//     --sync` so kubelet's next pull re-fetches the bad layer —
//     the pod recovers without a node reboot. Shared
//     last-ctr-image-rm 15m budget.
//   - 38-cilium-bpf-ipam.sh — cilium IPAM leak detector: reads
//     ipam.ipv4 used/available off the agent unix socket and
//     cross-checks the allocated count against non-hostNetwork
//     Running pods on this node (allocated − in-use = leaked IPs
//     held by dead pods). Gauges are exported every probe;
//     leaked >30 or available <=2 for ConsecNeeded consecutive
//     cycles → state-cilium-ipam-exhausted latch.
//   - T15 (k0s-kubelet-watchdog.sh + k0sworker-remediate.sh) — the
//     Option-D kubelet watchdog feeder, on its own 15s ticker
//     parallel to Cycle: probe :10248/healthz (body must be "ok"),
//     and after 4 consecutive fails (~60s) run the ordered gates
//     (uptime/settle/overload/apiserver/rate-limit) before spending
//     the shared last-restart budget on a k0sworker restart. An
//     exhausted budget latches state-kubelet-healthz-down instead —
//     the NHC→SNR reboot escalation path.
//   - W7 additions — d-state-storm (H1: >=5 total or >=2
//     runtime-critical procs in uninterruptible sleep for
//     ConsecNeeded cycles → state-d-state-storm → KernelHungTasks),
//     systemd-scopes (H2: 30m reset-failed sweep of abandoned
//     cri-containerd-*.scope units), the cilium-envoy xDS NACK guard
//   - cilium-lrp-dns :53 datapath probe (H3), spegel-mirror (H4:
//     Ready=False DaemonSet pod → delete + state latch), and
//     calico-hygiene (H7: orphan cali* veth leak + felix :9099
//     readiness — active only on calico nodes like cicd).
//   - W8 additions — the agent-owned watchdog heartbeat (BUG-H1:
//     Cycle() refreshes last-run + seeds installed, the reporter's
//     self-heartbeat made WatchdogStale permanently blind),
//     k0sworker restarts on the A4 syncloop/containerd-sock latches
//     (BUG-H4, shared overload/settle/last-restart gates), mtime
//     refresh on maintained latches (BUG-H6), 2xx-only probeHTTP
//     verdicts (BUG-H7), pod-log + snapshot attribution in
//     disk-bloat (BUG-H8), felix restart + cali* orphan-veth GC
//     (W8-NM3), cilium BPF map pressure (W8-NM3), and the PSI
//     memory-thrash evictor (W2).
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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checks"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// Defaults mirror the shell modules + the DaemonSet host mounts —
// the domain knobs live next to their checks (kubelet.go,
// pod_teardown.go, ctr_tasks.go, cilium_*.go, disk_bloat.go,
// journald.go, dstate_scopes.go, psi_thrash.go,
// spegel_calico_netns.go, kubelet_feeder.go, kubelet_syncloop.go)
// and the subsystem wiring defaults in config.go.
const (
	// minUptimeSeconds mirrors the shell runner's WD_REQUIRES: uptime
	// gate (MIN_UPTIME_S=1200) — no destructive checks in the first
	// 20 minutes after boot.
	minUptimeSeconds = 1200
)

// Check names — prometheus `check` label + log context.
const (
	checkTeardown    = "pod-teardown"
	checkKonn        = "konnectivity"
	checkDNS         = "dns-resolv"
	checkStall       = "kubelet-stall"
	checkWatch       = "kubelet-watch-wedge"
	checkCtrTasks    = "ctr-tasks"
	checkCilium      = "cilium"
	checkCiliumInit  = "cilium-init-stuck"
	checkCtrImages   = "ctr-image-healer"   // 37
	checkCiliumIPAM  = "cilium-ipam"        // 38
	checkKubeletWd   = "kubelet-watchdog"   // T15 feeder + remediate
	checkSyncloop    = "kubelet-syncloop"   // A4 PLEG probe
	checkCtrSock     = "containerd-sock"    // A4 socket hang probe
	checkIngestGC    = "ctr-ingest-gc"      // 39 (A3)
	checkZombieStorm = "zombie-storm"       // A2
	checkJournald    = "journald-integrity" // A5
	checkCiliumEnvoy = "cilium-envoy"       // B1
	checkCiliumMTU   = "cilium-mtu"         // B4
	checkCiliumWG    = "cilium-wg-peers"    // W5.6
	checkDiskBloat   = "disk-bloat"         // W6.3
	checkDState      = "d-state-storm"      // W7-H1
	checkSysScopes   = "systemd-scopes"     // W7-H2
	checkCiliumLRP   = "cilium-lrp-dns"     // W7-H3
	checkSpegel      = "spegel-mirror"      // W7-H4
	checkCalico      = "calico-hygiene"     // W7-H7
	checkCiliumBPF   = "cilium-bpf-maps"    // W8-NM3 (inside checkCilium)
	checkPSIThrash   = "psi-memory-thrash"  // W2
	checkCNINetns    = "cni-netns-gc"       // W9 orphan /run/netns/cni-* reaper
	checkCtrMeta     = "containerd-meta"    // W10-KR3 meta.db corruption + orphan shims
	checkHostOOM     = "host-oom"           // W10-KR1 SystemOOMVictim event + metric
	checkOrphanHP    = "orphan-hostpath"    // W10-ST2 orphaned pvc-* hostPath dirs
	// Runtime-resource guards (runtime_resource_guards.go).
	checkCgroupDying      = "cgroup-dying-reclaim"        // nr_dying_descendants reclaim
	checkSystemdSessions  = "systemd-session-hygiene"     // logind session janitor
	checkOverlayFSStale   = "overlayfs-stale-mount"       // ESTALE/lowerdir image healer
	checkIOPressure       = "io-pressure-throttler"       // diskstats + PSI io throttler
	checkConntrackLiberal = "conntrack-tcp-liberal-guard" // neb1 be_liberal fixer
	checkClockJump        = "clock-jump-session-healer"   // konn pod recreate after step
)

// Regexes shared by the ctrTask machinery and the snapshot→pod
// attribution — config.json annotation extraction, same pattern
// shape as the shell sed: key, junk up to the quote, 36-char uid
// value. The domain matchers moved next to their checks.
var (
	podUIDRe        = regexp.MustCompile(`"io\.kubernetes\.pod\.uid"[^0-9a-f-]*"([0-9a-f-]{36})"`)
	containerNameRe = regexp.MustCompile(`"io\.kubernetes\.container\.name"[^"]*"([^"]+)"`)
)

// Hygiene runs the worker checks on one ticker. It is the
// orchestrator only: everything the checks consume (config, procfs
// view, state store, journal tracker, metric vecs, cross-check
// shared state) lives on the embedded *deps — see deps.go. The
// embed keeps the pre-Check test contract compiling: h.cfg,
// h.stallFails, h.ciliumAgentKilled etc. promote through it.
type Hygiene struct {
	*deps

	// checks is the ordered per-Cycle dispatch list — initChecks
	// fills it; the order preserves the sequence the checks ran
	// before the table existed. Cycle wraps it into a checks.Group
	// for platform/checks.Dispatch (the Entry.Run closures bind
	// the per-cycle env — see Cycle). The checks are also named
	// fields so tests can reach per-check state and the old
	// Hygiene-method forwarders resolve without a list walk.
	checks      []Check
	stall       *stallCheck
	watch       *watchWedgeCheck
	teardown    *podTeardownCheck
	konn        *konnCheck
	dns         *dnsResolvCheck
	syncloop    *syncloopCheck
	ctrsock     *ctrsockCheck
	ctrTasks    *ctrTasksCheck
	ingestGC    *ingestGCCheck
	cilium      *ciliumCheck
	ciliumInit  *ciliumInitCheck
	ctrImages   *ctrImagesCheck
	ciliumIPAM  *ciliumIPAMCheck
	ciliumEnvoy *ciliumEnvoyCheck
	ciliumMTU   *ciliumMTUCheck
	ciliumWG    *ciliumWGCheck
	diskBloat   *diskBloatCheck
	journald    *journaldCheck
	zombies     *zombieStormCheck
	dstate      *dstateCheck
	scopes      *scopesCheck
	ciliumLRP   *ciliumLRPCheck
	spegel      *spegelCheck
	calico      *calicoCheck
	cniNetns    *cniNetnsCheck
	psiThrash   *psiThrashCheck
	ctrMeta     *ctrMetaCheck
	hostOOM     *hostOOMCheck
	orphanHP    *orphanHPCheck

	// Runtime-resource guards — the checks live in
	// runtime_resource_guards.go.
	cgroupDying      *cgroupDyingCheck
	systemdSessions  *systemdSessionCheck
	overlayFSStale   *overlayFSStaleCheck
	ioPressure       *ioPressureCheck
	conntrackLiberal *conntrackLiberalCheck
	clockJump        *clockJumpCheck
}

// New returns a Hygiene and registers its metrics on reg.
func New(cfg Config, reg prometheus.Registerer) (*Hygiene, error) {
	if cfg.Client == nil {
		// The first Cycle LIST would nil-pointer panic — the check
		// contract is "never panic", so reject at construction.
		return nil, errors.New("workerhygiene: Config.Client is required")
	}
	cfg.applyDefaults()
	d := &deps{cfg: cfg, proc: procfs.New(cfg.ProcRoot)}
	// Now MUST close over the live config field, not the cfg
	// parameter: tests re-stub h.cfg.Seams.nowFn after New returns and
	// the store has to observe the new clock (hoststate.New doc).
	d.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return d.cfg.Seams.nowFn() }, logger)
	d.journalReads = journalwatch.Tracker{
		Needed: cfg.Journal.UnreadableNeeded,
		Dirs:   cfg.Journal.Dirs,
	}

	d.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_cycles_total",
		Help: "Worker-hygiene check cycles by check and result (ok|abort|gated).",
	}, []string{"check", "result"})
	d.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_actions_total",
		Help: "Worker-hygiene remediation actions by check and action " +
			"(force_delete|pod_delete|sigkill|pause_kill|restart|rm_dir|shim_kill|image_rm|remediate).",
	}, []string{"check", "action"})
	d.ciliumAllocated = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_allocated_ips",
		Help: "IPv4 addresses cilium IPAM reports allocated on this node.",
	})
	d.ciliumLeaked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_workerhygiene_cilium_leaked_ips",
		Help: "Allocated cilium IPs not held by a non-hostNetwork Running pod on this node (leaked).",
	})
	d.ctrIngestsCleaned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_host_agent_workerhygiene_ctr_ingests_cleaned_total",
		Help: "Stale containerd content ingest dirs removed by the ingest GC (39).",
	})

	h := &Hygiene{deps: d}
	if reg != nil {
		for _, c := range []prometheus.Collector{
			d.cycles, d.actions, d.ciliumAllocated, d.ciliumLeaked,
			d.ctrIngestsCleaned,
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
	if !h.cfg.Enabled {
		// Constructed but disabled — idle instead of returning: the
		// agent restarts a returned Run in a hot loop.
		cycle.Idle(ctx)
		return
	}
	// The tick self-gates on kubeletFeederActive() each round, so a
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
		h.runKubeletFeeder(fctx)
	}()
	// Feeder setup precedes the FIRST Cycle too — a first-Cycle
	// panic must tear down a running feeder, not stack a second
	// one behind it on the agent's restart.
	defer func() {
		stop()
		wg.Wait()
	}()
	cycle.Every("workerhygiene", h.cfg.Interval, h.Cycle).Run(ctx)
}

// Cycle runs one round of every check in the ordered dispatch
// list. The k0sworker unit file gates everything (WD_REQUIRES:
// k0sworker) — controllers and test envs without the unit are a
// silent no-op. Each check must never panic and degrades to no-op
// on missing files.
func (h *Hygiene) Cycle(ctx context.Context) {
	if _, err := os.Stat(h.cfg.K0sWorkerUnitFile); err != nil {
		h.cycles.WithLabelValues("all", "gated").Inc()
		return
	}
	// uptime gate (WD_REQUIRES: uptime k0sworker — the shell also
	// required uptime >= 1200s): a freshly rebooted node gets grace
	// before any destructive check runs — Terminating ages surviving
	// a reboot must not trigger action inside the first minutes.
	if up, err := h.proc.UptimeSeconds(); err == nil && up < minUptimeSeconds {
		h.cycles.WithLabelValues("all", "uptime_gate").Inc()
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
	var tasks map[string][]ctrTask
	tasksComplete := true
	tasksOnce := func() (map[string][]ctrTask, bool) {
		if tasks == nil {
			tasks, tasksComplete = h.buildTaskMap()
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
			pids, _ = h.proc.PIDs()
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
			j, err := h.cfg.Seams.journalFn(ctx)
			switch {
			case err != nil:
				h.state.AppendLog(fmt.Sprintf("k0sworker journal snapshot failed: %v", err))
				h.noteJournalRead(false,
					fmt.Sprintf("snapshot failed: %v", err))
			case journalwatch.FilesGone(j):
				h.noteJournalRead(false,
					"journalctl reports no journal files")
			case strings.TrimSpace(j) != "":
				h.noteJournalRead(true, "")
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
	if h.cfg.WatchdogSrc != nil {
		h.cfg.Watchdog = h.cfg.WatchdogSrc.Get()
	}
	if wd := h.cfg.Watchdog; wd != nil && h.cfg.WatchdogSrc != nil {
		h.cfg.APIBackends = wd.APIBackendIPs()
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
	if h.cfg.Systemd != nil {
		if active, err := h.cfg.Systemd.Active(ctx, "k0sworker.service"); err != nil {
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
	h.ciliumAgentKilled = false
	sigOn := func(name string) bool {
		return h.cfg.Watchdog == nil || h.cfg.Watchdog.SignalEnabled(name)
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
	env := &cycleEnv{
		pods:         pods,
		apiOK:        apiOK,
		workerActive: workerActive,
		tasksOnce:    tasksOnce,
		pidsOnce:     pidsOnce,
		journalOnce:  journalOnce,
	}
	entries := make([]checks.Entry, 0, len(h.checks))
	for _, c := range h.checks {
		entries = append(entries, checks.Entry{
			Name: c.Name(),
			Run:  func(ctx context.Context) { c.Run(ctx, env) },
		})
	}
	checks.Dispatch(ctx, sigOn, h.cycles, []checks.Group{{Entries: entries}})
	// W10 node_agent_* gauges — one textfile per cycle carrying the
	// OOM/conntrack counters and the orphan-hostpath measurements
	// the checks above just refreshed.
	h.writeNodeAgentPromTextfile()
	// BUG-H1: the periodic watchdog heartbeat lives HERE now —
	// nodereporter used to refresh last-run every Cycle, which made
	// its own WatchdogStale probe permanently blind. The hygiene
	// Cycle owns the refresh (controllerhygiene/nethealth do the
	// same on non-worker nodes); gated early-returns above skip it
	// so a node where the checks never ran does not claim a run.
	h.state.Heartbeat()
}

// listNodePods lists pods scheduled to this node; apiOK=false means
// the LIST failed — checks treat it as "apiserver unreachable"
// (inconclusive: keep counters/latches, never act).
func (h *Hygiene) listNodePods(ctx context.Context) ([]corev1.Pod, bool) {
	list, err := h.cfg.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + h.cfg.NodeName,
	})
	if err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: pod list failed node=%s: %v — pod checks inconclusive this cycle",
			h.cfg.NodeName, err))
		return nil, false
	}
	pods := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NodeName == h.cfg.NodeName {
			pods = append(pods, list.Items[i])
		}
	}
	return pods, true
}

// --- watchdog file helpers (lib.sh parity) ---
// state-<name> latches, last-* rate budgets, the installed/last-run
// heartbeat and watchdog-log appends are the shared hoststate.Store
// contract — h.state (built in New) implements them; see
// internal/platform/hoststate for the file-format docs.

// --- /proc + containerd task helpers ---
// The /proc reads themselves live in platform/procfs (h.proc) —
// pid listing, cmdline/environ/stat parsing, liveness, uptime. What
// remains below is only the part that must read the live config
// seams (killFn/nowFn are re-stubbed by tests after New).

// pidLive is procfs.FS.Live bound to this subsystem's killFn seam —
// h.cfg.Seams.killFn is read at call time because tests re-stub it after
// New returns.
func (d *deps) pidLive(pid int) bool {
	return d.proc.Live(pid, d.cfg.Seams.killFn)
}

// ctrTask is one containerd task dir (runtime-v2 task or sandbox
// controller shim) — the node-side ground truth for "are tasks of
// this pod still around", replacing `ctr tasks ls` so no ctr socket
// is needed inside the agent pod.
type ctrTask struct {
	uid  string // io.kubernetes.pod.uid annotation
	name string // io.kubernetes.container.name annotation ("pause"/"POD" = sandbox infra)
	pid  int    // init.pid contents
	live bool   // kill -0 ok and not zombie
}

// buildTaskMap scans CtrTaskRoot/*/ and SandboxCtlRoot/*/ once per
// cycle and groups task dirs by pod UID — shared by the teardown and
// dns checks. Missing files are skipped, never fatal.
//
// complete=false when a task ROOT itself could not be listed — the
// map then only claims "no live tasks" for pods whose tasks it
// never saw, so force-delete callers must fail closed (checkCtrTasks
// abort parity): the runtime root must exist on a live worker (ANY
// error incl. ENOENT is suspect), while a genuinely-absent sandbox
// root is normal on layouts without a shim dir and stays complete.
// taskMapBuilds counts invocations so tests can assert the lazy
// once-per-cycle behaviour directly.
func (d *deps) buildTaskMap() (map[string][]ctrTask, bool) {
	d.taskMapBuilds++
	m := map[string][]ctrTask{}
	complete := true
	for i, root := range []string{d.cfg.CtrTaskRoot, d.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			if i == 0 || !os.IsNotExist(err) {
				complete = false
			}
			// A permission/IO error silently degrades the task
			// map — surface it so force-delete decisions aren't
			// the only trace of running on incomplete data.
			if !os.IsNotExist(err) {
				d.state.AppendLog(fmt.Sprintf(
					"suspect: ctr task root %s unreadable: %v — task map incomplete",
					root, err))
			}
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(dir, "config.json"))
			if err != nil {
				continue
			}
			um := podUIDRe.FindSubmatch(cfgData)
			if um == nil {
				continue
			}
			t := ctrTask{uid: string(um[1])}
			if nm := containerNameRe.FindSubmatch(cfgData); nm != nil {
				t.name = string(nm[1])
			}
			if pidData, err := os.ReadFile(filepath.Join(dir, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = d.pidLive(pid)
				}
			}
			m[t.uid] = append(m[t.uid], t)
		}
	}
	return m, complete
}

// countLive returns how many tasks of a UID still have a live init
// pid — the force-delete precondition (zero live tasks = verified
// container death, status.containerStatuses is only last-known).
func countLive(tasks []ctrTask) int {
	n := 0
	for _, t := range tasks {
		if t.live {
			n++
		}
	}
	return n
}

// --- Check 1: pod-teardown (36-pod-teardown.sh) ---

// podHasPVC reports whether the pod mounts a persistentVolumeClaim —
// force-deleting a PVC consumer on a wrong "dead" verdict risks a
// dual-mount of an RWO volume.
func podHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// PVC + generic ephemeral volumes share the same dual-mount
		// risk class on a wrong "dead" verdict.
		if v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			return true
		}
	}
	return false
}

// isMirrorPod reports kubelet-static mirror pods — deleting the
// mirror object changes nothing on disk.
func isMirrorPod(p *corev1.Pod) bool {
	_, ok := p.Annotations["kubernetes.io/config.mirror"]
	return ok
}

// forceDeletePod removes the pod object with grace 0 + Background
// propagation — reached only after zero-live-task verification, so it
// is pure object cleanup (no split-brain/dual-mount risk).
func (d *deps) forceDeletePod(ctx context.Context, p *corev1.Pod) error {
	// Log line is an NPD contract: ends in "force-delete pod ..." so
	// the StuckPodForceDeleted filelog pattern still fires.
	d.state.AppendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: force-delete pod %s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(d.cfg.Seams.nowFn().Sub(p.DeletionTimestamp.Time).Seconds())))
	return d.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
		})
}

// procAge is procfs.FS.Age bound to the nowFn seam (tests re-stub
// h.cfg.Seams.nowFn after New — the deps field promotes through
// the Hygiene embed).
func (d *deps) procAge(pid int) time.Duration {
	return d.proc.Age(pid, d.cfg.Seams.nowFn())
}

// pidsWithCmdline returns pids whose joined cmdline contains sub —
// the pkill -f replacement (the agent can't rely on pkill being in
// the container image). The pid list is the caller's per-cycle
// snapshot.
func (d *deps) pidsWithCmdline(sub string, pids []int) []int {
	var out []int
	for _, pid := range pids {
		if strings.Contains(strings.Join(d.proc.Cmdline(pid), " "), sub) {
			out = append(out, pid)
		}
	}
	return out
}

// --- orphan-shim scope helpers ---
//
// The Phase-B shim reaper must only ever reap shims of THE containerd
// instance CtrTaskRoot belongs to. A node can run a second containerd
// (host dockerd serves namespace moby on /run/containerd/containerd.sock,
// concourse workers spawn their own) whose shims read as "orphan" the
// moment their -id doesn't exist under the k0s k8s.io task root —
// SIGKILLing them cold-restarted every docker container per sweep
// (NodeOverloaded incident 2026-11: 10 containers x every ~6min).
// The shim's own cmdline carries the proof: -namespace + -address.

// stateFileExists reports whether a state-dir file exists — unlike
// stateExists it checks RAW filenames (markers like wedged-seen-<id>
// are not state-* latches).
func (d *deps) stateFileExists(name string) bool {
	_, err := os.Stat(filepath.Join(d.cfg.WatchdogStateDir, name))
	return err == nil
}

// --- Check: cilium (32-cilium.sh + 35-cilium-init-stuck.sh) ---

// podReady reports whether the pod's Ready condition is True — the
// API-side verdict the datapath guards contrast against (a pod
// Ready=True whose service listener is dead is exactly the wedge
// these checks heal).
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
