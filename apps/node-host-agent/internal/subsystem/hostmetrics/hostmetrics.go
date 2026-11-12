// Package hostmetrics exposes node-local filesystem state as
// Prometheus metrics, collected at scrape time.
//
// Sources (all paths configurable, host-mounted into the agent pod):
//
//   - Watchdog state latches: node-watchdog writes
//     /var/lib/node-watchdog/state-<name> while a failure signal is
//     active and deletes it on recovery (state_enter/state_exit in
//     watchdog/lib.sh). Each present latch exports
//     node_host_agent_watchdog_state{node,state}=1. States seen by an
//     earlier scrape keep exporting 0 after the latch clears, matching
//     the watchdog's own emit-0 semantics so alerts auto-resolve.
//   - Nebula interface: /sys/class/net/<neb1>/operstate →
//     node_host_agent_nebula_interface_up.
//   - Overlay route: any route via the nebula interface in the host
//     route table (/proc/1/net/route) →
//     node_host_agent_nebula_route_present.
//   - k0s config drift: mirrors the node-config-agent drift check —
//     on nodes where k0scontroller.service exists (control plane),
//     node_k0s_config_drift{reason,key}=1 per finding: a removed flag
//     still present, an unexpected/missing KCM extraArgs key vs
//     ExpectedKCMArgs, or an unreadable k0s.yaml.
//   - Nebula cert expiry: replaces the shell's `nebula-cert print`
//     fork — parses the PEM-wrapped protobuf NebulaCertificate
//     directly and exports node_host_agent_nebula_cert_days_left plus
//     the watchdog-state-style series
//     node_host_agent_watchdog_state{state="nebula-cert-expiring"}.
//   - PSI overload: /proc/pressure/cpu some avg60 →
//     node_watchdog_psi_cpu_some_avg60, and drives the
//     state-node-overloaded latch with hysteresis (>=40% enter,
//     <25% exit) — the runner's node-overloaded signal every restart
//     gate reads.
//   - cpu-delivered probe (lib.sh measure_cpu_delivered): a fixed
//     ~0.3 cpu-s busy loop on a locked thread (RUSAGE_THREAD) vs wall
//     clock → node_cpu_delivered_ratio +
//     node_cpu_delivered_probe_wall_seconds — the ground-truth
//     "how much of 1 vCPU did the hypervisor actually give" steal
//     canary guest accounting can't see.
//   - fail2ban banned counts: fail2ban-banned file ("jail=N ...")
//     written by the nethealth check → node_fail2ban_banned_ips{jail}.
//   - egress relay state: per OVERLAY_EGRESS_RELAYS target,
//     node_overlay_egress_relay_active{target} = 1 while
//     egress-state-<ip> is "relay" (emitted for every configured
//     target — absent vs 0 must stay distinguishable).
//   - clock sync (H1): adjtimex(2) →
//     node_host_agent_clock_unsynchronized (STA_UNSYNC flag) +
//     node_host_agent_clock_estimated_error_seconds (Esterror,
//     exported µs→s) — a silently drifting clock breaks cert
//     validation, etcd and log ordering long before anyone notices.
//   - conntrack table (H2): nf_conntrack_{count,max} →
//     node_host_agent_conntrack_{entries,limit,used_ratio} — a full
//     table drops NEW flows silently (DNS timeouts with zero
//     packet-loss evidence).
//   - filesystem inodes + hung-mount probe (H3/H7): statfs(2) over
//     FilesystemTargets → node_host_agent_filesystem_inodes_* and
//     node_host_agent_filesystem_probe_stalled — inode exhaustion
//     fails every create while df still shows free GB, and a hung
//     mount wedges any process that stats it (the probe runs with a
//     deadline on a spare goroutine — a stuck syscall can't be
//     cancelled, so at most one goroutine per mount is allowed to
//     pile up).
//   - FD + socket pressure (H6): /proc/sys/fs/file-nr +
//     /proc/1/net/sockstat → node_host_agent_filefd_* +
//     node_host_agent_sockstat_* — fd exhaustion and orphan/TIME_WAIT
//     pileups present as accept/connect flakes.
//   - On-disk PKI cert expiry (2.4): *.crt/*.pem under the k0s/kine
//     PKI dirs → node_host_agent_pki_cert_days_left{path} — the
//     apiserver/etcd/kubelet-client certs expire silently; a lapsed
//     cert surfaces as a control-plane outage weeks after the
//     warning should have fired.
//   - inotify pressure (A1/H8): /proc/[0-9]*/fdinfo sweep (cached
//     60s — a full walk per scrape is too heavy) vs
//     /proc/sys/fs/inotify/max_user_{instances,watches} →
//     node_host_agent_inotify_{instances,watches}_used_ratio. An
//     inotify-instance leak presents as `too many open files` while
//     fs.file-nr is nearly empty; over 80% the top 3 holder PIDs are
//     logged once per episode.
//   - zombie + cgroup pids pressure (A2): state Z entries under
//     ProcRoot → node_host_agent_processes_zombie_count, and
//     pids.current/pids.max of the k0s/kubepods slices →
//     node_host_agent_cgroup_pids_used_ratio{slice} — pids.max
//     exhaustion is `fork: resource temporarily unavailable` while
//     CPU looks idle.
//   - MTU drift (B4): cilium_net MTU (sysfs, falling back to
//     agent-runtime-config.json) vs the nebula overlay MTU →
//     node_host_agent_mtu_drift = 1 when the pod datapath MTU
//     exceeds the overlay's — packets then die silently on
//     FRAG_NEEDED (1300-byte neb1 vs 1500 pods).
//
// Emission policy (documented choice): watchdog_state emits for every
// latch ever observed (1 while latched, 0 after clear). The
// nebula_* metrics emit only when the interface exists — on non-nebula
// nodes they are absent rather than 0, so "interface missing" is
// distinguishable from "interface down". The nebula cert days gauge
// emits only when the cert parses. node_k0s_config_drift emits
// only where the k0s controller unit exists — workers carry no series.
// The clock/conntrack/filefd/sockstat gauges emit only when their
// source reads or parses; filesystem_probe_stalled emits for EVERY
// configured mount — a 0 means the probe answered in time, so
// "reachable and boring" stays distinguishable from "never probed".
package hostmetrics

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostmetrics/kernelfail"
)

// Defaults — paths are the host mounts the DaemonSet provides.
// Domain-specific defaults live with their collect_*.go files; the
// ones here are shared across collect domains (or used by the
// latch files).
const (
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	// defaultWatchdogLogFile is the shared appended watchdog log —
	// the same path workerhygiene/nethealth/controllerhygiene
	// write and nodereporter's events.go tails. The latch ticker
	// needs the file half of AppendLog for its STATE-ENTER lines.
	defaultWatchdogLogFile = "/host/var/log/node-watchdog.log"
	defaultSysClassNet     = "/sys/class/net"
	defaultNebulaIface     = "neb1"
	// defaultProcRoot is the host /proc — plain /proc under
	// hostPID:true (the pod's /proc is the host's); the inotify
	// fdinfo and zombie scans walk it.
	defaultProcRoot = "/proc"
	// kernel-keys-pressure: /proc/key-users — kernel keyring quota pressure.
	defaultKeyUsersFile = "/proc/key-users"
	// kernelKeysPressureRatio arms state-kernel-keys-pressure.
	kernelKeysPressureRatio = 0.80
	// inode-pressure inode-pressure hysteresis: any monitored mount at or
	// above inodePressureEnterRatio of its inode table latches
	// state-inode-pressure; the latch clears only once EVERY
	// monitored mount sits at or below inodePressureClearRatio —
	// between the two the latch holds (a 92% mount must not flap
	// the condition on every scrape).
	inodePressureEnterRatio = 0.95
	inodePressureClearRatio = 0.90
	// defaultLatchInterval is the Run() ticker's cadence (BUG-H5) —
	// the watchdog-state file contract must hold even when nothing
	// scrapes this collector (DaemonSet mode).
	defaultLatchInterval = 30 * time.Second
)

// Collector implements prometheus.Collector — all reads happen at
// scrape time, so no goroutine or refresh interval is needed.
type Collector struct {
	cfg Config

	// state is the shared watchdog-state contract handle (hoststate):
	// the last-* rate budgets, the kmsg counter files and the
	// STATE-ENTER log lines go through it so the on-disk format stays
	// the lib.sh parity every subsystem shares. LogFile is the shared
	// watchdog log — nodereporter tails it, so a latch-entry line
	// only counts if it lands there. Now is c.cfg.Clock.Now — the
	// method value binds the shared timex.Cell, so a post-New
	// Clock.Set lands here.
	state *hoststate.Store

	// Hoisted out of the scrape path in New(): drift regexes are
	// compiled once and the expected-KCM set is built once — the
	// per-scrape work left in collectK0sDrift is a stat + map lookups.
	removedFlagRe map[string]*regexp.Regexp
	expectedKCM   map[string]bool

	// Per-domain scrape/probe state — each type is defined next to
	// the collect_*.go file that consumes it and carries its own
	// mutex (the domains are independent, so the old single mu
	// split into one lock per domain). Field docs live on the
	// domain types.
	seen   latchSeenBook     // collect_watchdog.go — emit-0 bookkeeping
	k0s    k0sDriftCache     // collect_k0sdrift.go — mtime+size config cache
	cpu    cpuDeliveredProbe // collect_psi_cpu.go — busy-loop probe
	fs     fsProbeState      // collect_fs.go — hung-mount probes
	ino    inotifyCache      // collect_inotify.go — >80% warn edge flags
	lpv    localpvCache      // collect_localpv.go — du walk cache
	fdscan fdLinkCache       // collect_fdlinks.go — shared inotify+ebpf /proc fd sweep (singleflight)
	proc   procScanCache     // collect_procs_scan.go — shared /proc walk (daemon-fd + zombies)
	scopes scopesCache       // collect_procs_cgroup.go — systemd scope-count TTL cache
	certs  certNotAfterCache // certcache.go — stat-key memoized X.509 notAfter (pki + nebula)
	// wr is the host-sysctl write bookkeeping (host_writes.go) —
	// clocksource restore + aio-max-nr bump run on the latch tick,
	// never on the scrape path.
	wr writeState
	// snapMu/snapAt/snapMetrics are the 10s Collect snapshot cache:
	// Prometheus scrapes can arrive faster than the probe work
	// inside a pass (psi avg60, the cpu-delivered busy loop, the
	// TTL-cached but still costly fdinfo/inotify walks), so a
	// fresh-enough snapshot is replayed instead of re-measuring
	// the host. snapMu serializes Collect — concurrent scrapes
	// must not run duplicate passes nor race the snapshot swap.
	snapMu      sync.Mutex
	snapAt      time.Time
	snapMetrics []prometheus.Metric
	// kf is the kernel deep-failure engine (kernelfail
	// subpackage) — the kmsg tail session + the steal jiffie
	// baseline live inside it. Owned by the Collector directly:
	// the Latches wrapper is recreated per call, so a keyed
	// side-map would pin the session (and its /dev/kmsg fd) for
	// the process lifetime — Latches.Run closes it on exit. Only
	// the latch ticker touches it.
	kf *kernelfail.Runner
}

// New returns the Collector. Call Register to add it to the agent's
// registry, and wire its Latches() half in as the latch-ticker
// subsystem.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg}
	c.wr.tried = map[string]time.Time{}
	c.seen.m = map[string]time.Time{}
	c.fs.inflight = map[string]*fsFlight{}
	c.fs.stalledLogged = map[string]bool{}
	c.state = cfg.Store(logger)
	c.removedFlagRe = make(map[string]*regexp.Regexp, len(cfg.RemovedFlags))
	for _, flag := range cfg.RemovedFlags {
		// Anchored key match (same shape as the canonical
		// grep "^[[:space:]]*flag[[:space:]]*:") over the raw file —
		// a removed flag may hide in ANY extraArgs block
		// (api/controllerManager/scheduler), and a substring match
		// would fire on comments or values.
		c.removedFlagRe[flag] = regexp.MustCompile(
			`(?m)^\s*` + regexp.QuoteMeta(flag) + `\s*:`)
	}
	c.expectedKCM = make(map[string]bool, len(cfg.ExpectedKCMArgs))
	for _, k := range cfg.ExpectedKCMArgs {
		c.expectedKCM[k] = true
	}
	// Built last — the Deps close over cfg + the Store, so both
	// must be resolved first.
	c.kf = kernelfail.New(c.kernelFailDeps())
	return c
}

// Register adds the collector to reg — the error-returning form of
// the registration every other subsystem performs inside
// New(cfg, reg) (workerhygiene parity). hostmetrics keeps a
// registry-free New(cfg) because its test suite builds bare
// collectors directly; production wiring (cmd/agent's hostmetrics
// descriptor) goes through this step so a registration failure
// surfaces as a Build error — "hostmetrics setup failed" — instead
// of a MustRegister panic taking the process down.
func (c *Collector) Register(reg prometheus.Registerer) error {
	if reg == nil {
		return nil
	}
	return reg.Register(c)
}

// The scrape-domain registry — domainTable, descMetaTable and
// Describe() — lives in domains.go (workerhygiene check.go parity):
// one ordered table the scrape, the descriptor set and the textfile
// writer all derive from. Adding a domain is a collect_<domain>.go
// file plus ONE row there — the old split (a row in collectors()
// AND a row per family in descTable) is gone.

// collectSnapshotTTL bounds how long one measured metric set is
// replayed to repeat scrapes — 10s keeps staleness far under any
// alerting window while collapsing scrape bursts (and the
// textfile writer's extra passes) to a single host measurement.
const collectSnapshotTTL = 10 * time.Second

// Collect implements prometheus.Collector — a snapshot younger
// than collectSnapshotTTL is replayed verbatim; anything older
// (or the first call) runs the full measurement pass and becomes
// the new snapshot. The pass itself is READ-ONLY by contract:
// latch transitions live on the Latches ticker (refreshLatches)
// and host sysctl writes on reconcileHostWrites — a scrape must
// never stamp watchdog-state files or sysctls as a side effect.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	now := c.cfg.Clock.Now()
	if c.cfg.collectCacheTTL > 0 && c.snapMetrics != nil &&
		now.Sub(c.snapAt) < c.cfg.collectCacheTTL {
		for _, m := range c.snapMetrics {
			ch <- m
		}
		return
	}
	ms := c.collectFresh()
	c.snapAt = now
	c.snapMetrics = ms
	for _, m := range ms {
		ch <- m
	}
}

// collect is the real measurement pass — the side-effect probes
// feed scrapeCtx into the domains (watchdog, nebula-cert, psi,
// filesystem, fs-bytes). One statfs per mount per pass: the
// filesystem and fs-bytes domains share overlapping targets (the
// k0s data dir, the OpenEBS local root), and each used to probe
// them separately; probeFS's singleflight still bounds in-flight
// goroutines at one per mount. NO latch updaters run here —
// updateOverloadLatch/updateCertLatch/updateFSReadonlyLatch/
// updateInodePressureLatch all belong to refreshLatches.
func (c *Collector) collect(ch chan<- prometheus.Metric) {
	var sc scrapeCtx
	sc.avg60, sc.psiOK = c.psiAvg60()
	c.maybeMeasureCPU()
	// The cert is parsed once per pass and shared between the
	// watchdog-state latch bookkeeping and the days-left gauge.
	sc.certDays, sc.certOK = c.nebulaCertDaysLeft()
	sc.fs = c.scrapeFSProbes()
	for _, d := range domainTable {
		d.run(c, ch, sc)
	}
}

// collectFresh drains one full collect() pass into a slice — the
// uncached half Collect caches and WriteTextfile renders. The
// drain runs on a goroutine because the domains push into ch.
func (c *Collector) collectFresh() []prometheus.Metric {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.collect(ch)
		close(ch)
	}()
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

// --- node-exporter textfile rendering (standalone prom_emit port) ---

// TextfileName is the prom file the standalone writer renders —
// node-watchdog.prom, the same name prom_emit used.
const TextfileName = "node-watchdog.prom"

// collectAll drains a full fresh collect into a slice — the
// textfile writer's scrape (collect pushes; a reader must consume
// concurrently or the collector blocks on the channel). It
// deliberately bypasses the 10s snapshot cache: the textfile
// render is already interval-driven and must reflect the latest
// host state, not a scrape-side cache entry.
func (c *Collector) collectAll() []prometheus.Metric {
	return c.collectFresh()
}

// WriteTextfile renders the full metric set in node-exporter
// textfile format and atomically installs it as
// <dir>/node-watchdog.prom (tmp + rename — node_exporter only reads
// complete files). This is the standalone equivalent of prom_emit:
// on out-of-cluster hosts (api-lb VMs, kine DB VM, hubs) there is no
// Prometheus scrape, so the same series the /metrics endpoint
// exports are dropped into the textfile dir instead.
func (c *Collector) WriteTextfile(dir string) error {
	series := map[string][]string{}
	metaByName := map[string]descMeta{}
	counterSeries := map[string]bool{}
	var names []string
	for _, m := range c.collectAll() {
		meta, ok := descMetaTable[m.Desc()]
		if !ok {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			continue
		}
		// Counters land on dm.Counter, gauges on dm.Gauge — the
		// vmstat swap-thrash series (psi-swap-thrash) are the first counters in
		// the set; skipping non-gauges would silently drop them from
		// node-watchdog.prom on standalone VMs.
		val, isCounter := float64(0), false
		switch {
		case dm.Gauge != nil && dm.Gauge.Value != nil:
			val = dm.Gauge.GetValue()
		case dm.Counter != nil && dm.Counter.Value != nil:
			val, isCounter = dm.Counter.GetValue(), true
		default:
			continue
		}
		var sb strings.Builder
		sb.WriteString(meta.name)
		if len(dm.Label) > 0 {
			sb.WriteByte('{')
			for i, l := range dm.Label {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(l.GetName())
				sb.WriteString(`="`)
				sb.WriteString(promfile.EscapeLabelValue(l.GetValue()))
				sb.WriteByte('"')
			}
			sb.WriteByte('}')
		}
		sb.WriteByte(' ')
		sb.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
		if _, seen := series[meta.name]; !seen {
			names = append(names, meta.name)
			metaByName[meta.name] = meta
		}
		if isCounter {
			counterSeries[meta.name] = true
		}
		series[meta.name] = append(series[meta.name], sb.String())
	}
	sort.Strings(names)

	var b promfile.Builder
	for _, name := range names {
		typ := "gauge"
		if counterSeries[name] {
			typ = "counter"
		}
		b.HeaderType(name, metaByName[name].help, typ)
		samples := series[name]
		sort.Strings(samples)
		// Dedupe identical sample lines — a duplicated series makes
		// the textfile collector reject the WHOLE file (the same
		// constraint prom_emit's `emitted` bookkeeping guarded).
		last := ""
		for _, s := range samples {
			if s == last {
				continue
			}
			last = s
			b.Line(s)
		}
	}

	return promfile.Write(dir, TextfileName, []byte(b.String()))
}
