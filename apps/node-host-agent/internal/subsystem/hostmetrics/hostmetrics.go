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
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
	// W8-KR3: /proc/key-users — kernel keyring quota pressure.
	defaultKeyUsersFile = "/proc/key-users"
	// kernelKeysPressureRatio arms state-kernel-keys-pressure.
	kernelKeysPressureRatio = 0.80
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
	// only counts if it lands there. Now is a closure over
	// c.cfg.nowFn — tests re-stub the clock after New() and the
	// store must observe the new one.
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
	seen  latchSeenBook     // collect_watchdog.go — emit-0 bookkeeping
	k0s   k0sDriftCache     // collect_k0sdrift.go — mtime+size config cache
	cpu   cpuDeliveredProbe // collect_psi_cpu.go — busy-loop probe
	steal stealDelta        // collect_steal_entropy.go — jiffie baseline
	fs    fsProbeState      // collect_fs.go — hung-mount probes
	ino   inotifyCache      // collect_inotify.go — fdinfo sweep cache
	lpv   localpvCache      // collect_localpv.go — du walk cache
}

// New returns the Collector. Register it on the agent's registry,
// and wire its Latches() half in as the latch-ticker subsystem.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg}
	c.seen.m = map[string]time.Time{}
	c.fs.inflight = map[string]time.Time{}
	c.fs.stalledLogged = map[string]bool{}
	c.state = hoststate.New(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		func() time.Time { return c.cfg.nowFn() }, logger)
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
	return c
}

// descMeta carries the fqName + help text of one descriptor — the
// textfile writer's header lines (a Metric's Desc does not expose the
// name programmatically).
type descMeta struct {
	name string
	help string
}

// descTable is the ordered descriptor registry — one row per
// exported series family, in Describe() order. The descs themselves
// are package vars next to the collect_*.go file that emits them;
// the name/help here are the textfile writer's short form (the full
// help sentence lives on the desc's NewDesc call). Adding a family
// means one row here AND one row in the collectors() table.
var descTable = []struct {
	desc *prometheus.Desc
	name string
	help string
}{
	{descWatchdog, "node_host_agent_watchdog_state",
		"node-watchdog state-* latch present (1) or previously seen and cleared (0)."},
	{descWatchdogLegacy, "node_watchdog_state",
		"Signal currently active on node-watchdog (1 = state file exists)."},
	{descNebUp, "node_host_agent_nebula_interface_up",
		"Nebula interface operstate is up (emitted only when the interface exists)."},
	{descNebRoute, "node_host_agent_nebula_route_present",
		"A host route via the Nebula interface exists (emitted only when the interface exists)."},
	{descNebCertDays, "node_host_agent_nebula_cert_days_left",
		"Days until the nebula host certificate notAfter (emitted only when the cert parses)."},
	{descK0sDrift, "node_k0s_config_drift",
		"/etc/k0s/k0s.yaml drifted vs expected config (1=drift)."},
	{descPSI, "node_watchdog_psi_cpu_some_avg60",
		"PSI cpu some avg60 — share of time runnable tasks stalled (runner's overload signal)."},
	{descCPURatio, "node_cpu_delivered_ratio",
		"Share of 1 vCPU actually delivered by the hypervisor — busy-loop probe (~0.3 cpu-s, 1.0 = no steal)."},
	{descCPUWall, "node_cpu_delivered_probe_wall_seconds",
		"Wall-clock the cpu-delivered probe ran — abnormal growth = the probe itself stalled."},
	{descF2B, "node_fail2ban_banned_ips",
		"Currently banned IPs per fail2ban jail (emitted only when the banned file exists)."},
	{descEgressRelay, "node_overlay_egress_relay_active",
		"Egress target currently routed via the overlay relay (1) or direct underlay (0)."},
	{descEgressRelayLegacy, "node_watchdog_egress_relay",
		"Egress target currently routed via overlay relay (1) or direct (0)."},
	{descClockUnsync, "node_host_agent_clock_unsynchronized",
		"Kernel clock reports STA_UNSYNC via adjtimex (1 = not synchronized)."},
	{descClockEstErr, "node_host_agent_clock_estimated_error_seconds",
		"adjtimex Timex.Esterror exported as seconds."},
	{descCtEntries, "node_host_agent_conntrack_entries",
		"nf_conntrack_count — conntrack table entries currently tracked."},
	{descCtLimit, "node_host_agent_conntrack_limit",
		"nf_conntrack_max — conntrack table capacity."},
	{descCtRatio, "node_host_agent_conntrack_used_ratio",
		"Conntrack table fill ratio (entries/limit)."},
	{descFSInodesTotal, "node_host_agent_filesystem_inodes_total",
		"Total inodes on the probed mount (statfs Files)."},
	{descFSInodesFree, "node_host_agent_filesystem_inodes_free",
		"Free inodes on the probed mount (statfs Ffree)."},
	{descFSInodesRatio, "node_host_agent_filesystem_inodes_used_ratio",
		"Used-inode share of the probed mount."},
	{descFSProbeStalled, "node_host_agent_filesystem_probe_stalled",
		"statfs probe of this mount exceeded the deadline (1 = hung mount)."},
	{descFileFDAlloc, "node_host_agent_filefd_allocated",
		"file-nr field 0 — file handles currently allocated."},
	{descFileFDMax, "node_host_agent_filefd_maximum",
		"file-nr field 2 — file handle limit."},
	{descFileFDRatio, "node_host_agent_filefd_used_ratio",
		"file-nr allocated/maximum."},
	{descSockTCPInuse, "node_host_agent_sockstat_tcp_inuse",
		"sockstat TCP inuse — TCP sockets in use."},
	{descSockTCPOrphan, "node_host_agent_sockstat_tcp_orphan",
		"sockstat TCP orphan — orphaned TCP connections."},
	{descSockTCPTW, "node_host_agent_sockstat_tcp_tw",
		"sockstat TCP tw — TCP sockets in TIME_WAIT."},
	{descSockUsed, "node_host_agent_sockstat_sockets_used",
		"sockstat 'sockets: used' — total sockets in use."},
	{descPKIDays, "node_host_agent_pki_cert_days_left",
		"Days until the earliest notAfter of the on-disk PKI cert at this path."},
	{descInotifyInst, "node_host_agent_inotify_instances_used_ratio",
		"inotify fds in use / max_user_instances."},
	{descInotifyWatches, "node_host_agent_inotify_watches_used_ratio",
		"inotify watches in use / max_user_watches."},
	{descZombies, "node_host_agent_processes_zombie_count",
		"Processes in state Z under the host proc root."},
	{descCgroupPids, "node_host_agent_cgroup_pids_used_ratio",
		"pids.current / pids.max of the slice."},
	{descMTUDrift, "node_host_agent_mtu_drift",
		"cilium datapath MTU exceeds the nebula overlay MTU (1 = drift)."},
	{descFSReadonly, "node_host_agent_filesystem_readonly",
		"Probed mount reports ST_RDONLY via statfs (1 = filesystem remounted read-only)."},
	{descPSIMemSome, "node_host_agent_psi_memory_some_avg60",
		"PSI memory some avg60 — share of time any task stalled on memory reclaim."},
	{descPSIMemFull, "node_host_agent_psi_memory_full_avg60",
		"PSI memory full avg60 — share of time all tasks stalled on memory reclaim."},
	{descPSIIOSome, "node_host_agent_psi_io_some_avg60",
		"PSI io some avg60 — share of time any task stalled on block IO."},
	{descPSIIOFull, "node_host_agent_psi_io_full_avg60",
		"PSI io full avg60 — share of time all tasks stalled on block IO."},
	{descPSWPIn, "node_host_agent_vmstat_pswpin_total",
		"/proc/vmstat pswpin — cumulative pages swapped in."},
	{descPSWPOut, "node_host_agent_vmstat_pswpout_total",
		"/proc/vmstat pswpout — cumulative pages swapped out."},
	{descDState, "node_host_agent_dstate_processes",
		"Processes in state D (uninterruptible sleep) under the host proc root."},
	{descSystemdScopes, "node_host_agent_systemd_scopes_count",
		"cri-containerd-*.scope dirs under the kubepods cgroup slice."},
	{descCtInsertFail, "node_host_agent_conntrack_insert_failed_total",
		"insert_failed column sum over all CPU rows of nf_conntrack stats."},
	{descCtDrops, "node_host_agent_conntrack_drops_total",
		"drop column sum over all CPU rows of nf_conntrack stats."},
	{descARPEntries, "node_host_agent_arp_entries",
		"Entries in the ARP neighbour table."},
	{descCgMemHigh, "node_host_agent_cgroup_memory_high_events_total",
		"memory.events high of the unit — direct-reclaim throttling."},
	{descCgMemOOMKill, "node_host_agent_cgroup_memory_oom_kill_events_total",
		"memory.events oom_kill of the unit."},
	{descKernelKeys, "node_host_agent_kernel_keys_used_ratio",
		"Highest per-UID keyring fill ratio from /proc/key-users."},
	{descSockTCPCW, "node_host_agent_sockstat_tcp_close_wait",
		"sockstat TCP close_wait."},
	{descLocalPVDirBytes, "node_host_agent_localpv_dir_bytes",
		"Bytes under the OpenEBS LocalPV pvc-* volume dir."},
}

// descMetaTable maps each desc to its textfile fqName/help — a
// prometheus.Metric carries the Desc but the fqName is only
// reachable through Desc.String(), so the writer keeps its own
// table keyed off the same descTable Describe() serves.
var descMetaTable = func() map[*prometheus.Desc]descMeta {
	m := make(map[*prometheus.Desc]descMeta, len(descTable))
	for _, e := range descTable {
		m[e.desc] = descMeta{name: e.name, help: e.help}
	}
	return m
}()

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, e := range descTable {
		ch <- e.desc
	}
}

// collectEntry is one row of the scrape-time dispatch table — the
// domain name plus the emit function. Rows run in declaration order
// inside collectors().
type collectEntry struct {
	name string
	emit func(chan<- prometheus.Metric)
}

// collectors returns the scrape-time dispatch table — one row per
// metric domain, in emission order. Adding a domain means a
// collect_<domain>.go file (with its desc vars), one row here and
// one row in descTable. Domains that share a per-scrape probe
// result (the PSI avg60, the parsed nebula cert days) close over
// the values Collect computed once.
func (c *Collector) collectors(avg60 float64, psiOK bool,
	certDays int64, certOK bool) []collectEntry {
	return []collectEntry{
		{"watchdog", func(ch chan<- prometheus.Metric) {
			c.collectWatchdog(ch, certDays, certOK)
		}},
		{"nebula", c.collectNebula},
		{"nebula-cert", func(ch chan<- prometheus.Metric) {
			c.collectNebulaCert(ch, certDays, certOK)
		}},
		{"k0s-drift", c.collectK0sDrift},
		{"psi", func(ch chan<- prometheus.Metric) {
			c.collectPSI(ch, avg60, psiOK)
		}},
		{"cpu-delivered", c.collectCPUDelivered},
		{"fail2ban", c.collectFail2ban},
		{"egress-relay", c.collectEgressRelay},
		{"clock", c.collectClock},
		{"conntrack", c.collectConntrack},
		{"filesystem", c.collectFilesystem},
		{"filefd", c.collectFileFD},
		{"sockstat", c.collectSockstat},
		{"pki-certs", c.collectPKICerts},
		{"inotify", c.collectInotify},
		{"zombies", c.collectZombies},
		{"cgroup-pids", c.collectCgroupPids},
		{"mtu-drift", c.collectMTUDrift},
		{"memory-io", c.collectMemoryIO},
		{"systemd-scopes", c.collectSystemdScopes},
		{"arp", c.collectARP},
		{"cgroup-mem-events", c.collectCgroupMemEvents},
		{"kernel-keys", c.collectKernelKeys},
		{"localpv", c.collectLocalPVUsage},
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Side-effect probes run BEFORE the state-dir scan so a latch
	// they transition shows up in this scrape's watchdog_state.
	avg60, psiOK := c.psiAvg60()
	if psiOK {
		c.updateOverloadLatch(avg60)
	}
	c.maybeMeasureCPU()
	// The cert is parsed once per scrape and shared between the
	// watchdog-state latch bookkeeping and the days-left gauge.
	certDays, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(certDays, certOK)
	for _, e := range c.collectors(avg60, psiOK, certDays, certOK) {
		e.emit(ch)
	}
}

// --- node-exporter textfile rendering (standalone prom_emit port) ---

// TextfileName is the prom file the standalone writer renders —
// node-watchdog.prom, the same name prom_emit used.
const TextfileName = "node-watchdog.prom"

// collectAll drains a full Collect into a slice — the textfile
// writer's scrape (Collect pushes; a reader must consume
// concurrently or the collector blocks on the channel).
func (c *Collector) collectAll() []prometheus.Metric {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
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
		// vmstat swap-thrash series (W5.7) are the first counters in
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
