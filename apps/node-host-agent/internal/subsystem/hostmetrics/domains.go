// domains.go — the ordered scrape-domain registry (workerhygiene
// check.go parity): ONE table that Describe(), Collect() and the
// node-watchdog.prom textfile writer all derive from. Table order is
// the scrape emission order — load-bearing like the check order over
// there (prometheus sorts families at Gather time, but collectAll's
// slice order and any in-process channel consumer observe this
// sequence, so preserve the historical domain order when adding rows).
//
// Adding a domain used to mean a collect_<domain>.go file PLUS one
// row in collectors() AND one row in descTable — two parallel lists
// that could silently drift apart (a described family with no
// emitter, or an emitted series the textfile writer couldn't name).
// Now a domain is ONE row here: the emit entry point plus every
// series family it can produce.
//
// The W10 textfile-only channels (node_agent_*_utilization_ratio in
// pidfd.go, the steal/entropy gauges in collect_steal_entropy.go)
// are deliberately NOT rows: they ride promfile.Builder on the
// latch ticker, not the prometheus.Collector path, so they never
// had a desc to register.
package hostmetrics

import "github.com/prometheus/client_golang/prometheus"

// scrapeCtx carries the probe results Collect computes once per
// scrape and shares across domains — psiAvg60 (the same value the
// node-overloaded latch hysteresis just acted on) and the parsed
// nebula cert days (folded into BOTH the watchdog-state latch
// bookkeeping and the days-left gauge). Passing them through the
// entry point keeps the values per-scrape — a Collector field would
// race under concurrent Collect.
type scrapeCtx struct {
	avg60    float64
	psiOK    bool
	certDays int64
	certOK   bool
}

// descMeta carries one exported series family — the desc Describe()
// serves plus the textfile writer's fqName/HELP short form (a
// Metric's Desc does not expose the name programmatically; the full
// help sentence lives on the desc's NewDesc call).
type descMeta struct {
	desc *prometheus.Desc
	name string
	help string
}

// domainEntry is one row of the scrape-domain table — a metric
// domain: the emit entry point plus the series families it can
// emit, in Describe order.
//
// emit is the common shape (the domain reads its sources and pushes
// metrics). emitCtx is for the three domains that fold in the shared
// per-scrape probe results — exactly one of the two is set.
type domainEntry struct {
	name     string
	emit     func(*Collector, chan<- prometheus.Metric)
	emitCtx  func(*Collector, chan<- prometheus.Metric, scrapeCtx)
	families []descMeta
}

// run dispatches the domain — emitCtx rows get the scrape-shared
// probe results, plain emit rows read everything themselves.
func (d domainEntry) run(c *Collector, ch chan<- prometheus.Metric,
	sc scrapeCtx) {
	if d.emitCtx != nil {
		d.emitCtx(c, ch, sc)
		return
	}
	d.emit(c, ch)
}

// domainTable is THE scrape-domain registry — one row per metric
// domain, in emission order. Describe() flattens the families, the
// textfile writer names series through descMetaTable, Collect()
// walks run(). Domains with a scrape-side cache close over it via
// the Collector receiver — the cache stays a Collector field next
// to the collect_<domain>.go file that owns it.
var domainTable = []domainEntry{
	{name: "watchdog",
		emitCtx: (*Collector).collectWatchdog,
		families: []descMeta{
			{descWatchdog, "node_host_agent_watchdog_state",
				"node-watchdog state-* latch present (1) or previously seen and cleared (0)."},
			{descWatchdogLegacy, "node_watchdog_state",
				"Signal currently active on node-watchdog (1 = state file exists)."},
		}},
	{name: "nebula",
		emit: (*Collector).collectNebula,
		families: []descMeta{
			{descNebUp, "node_host_agent_nebula_interface_up",
				"Nebula interface operstate is up (emitted only when the interface exists)."},
			{descNebRoute, "node_host_agent_nebula_route_present",
				"A host route via the Nebula interface exists (emitted only when the interface exists)."},
		}},
	{name: "nebula-cert",
		emitCtx: (*Collector).collectNebulaCert,
		families: []descMeta{
			{descNebCertDays, "node_host_agent_nebula_cert_days_left",
				"Days until the nebula host certificate notAfter (emitted only when the cert parses)."},
		}},
	{name: "k0s-drift",
		emit: (*Collector).collectK0sDrift,
		families: []descMeta{
			{descK0sDrift, "node_k0s_config_drift",
				"/etc/k0s/k0s.yaml drifted vs expected config (1=drift)."},
		}},
	{name: "psi",
		emitCtx: (*Collector).collectPSI,
		families: []descMeta{
			{descPSI, "node_watchdog_psi_cpu_some_avg60",
				"PSI cpu some avg60 — share of time runnable tasks stalled (runner's overload signal)."},
		}},
	{name: "cpu-delivered",
		emit: (*Collector).collectCPUDelivered,
		families: []descMeta{
			{descCPURatio, "node_cpu_delivered_ratio",
				"Share of 1 vCPU actually delivered by the hypervisor — busy-loop probe (~0.3 cpu-s, 1.0 = no steal)."},
			{descCPUWall, "node_cpu_delivered_probe_wall_seconds",
				"Wall-clock the cpu-delivered probe ran — abnormal growth = the probe itself stalled."},
		}},
	{name: "fail2ban",
		emit: (*Collector).collectFail2ban,
		families: []descMeta{
			{descF2B, "node_fail2ban_banned_ips",
				"Currently banned IPs per fail2ban jail (emitted only when the banned file exists)."},
		}},
	{name: "egress-relay",
		emit: (*Collector).collectEgressRelay,
		families: []descMeta{
			{descEgressRelay, "node_overlay_egress_relay_active",
				"Egress target currently routed via the overlay relay (1) or direct underlay (0)."},
			{descEgressRelayLegacy, "node_watchdog_egress_relay",
				"Egress target currently routed via overlay relay (1) or direct (0)."},
		}},
	{name: "clock",
		emit: (*Collector).collectClock,
		families: []descMeta{
			{descClockUnsync, "node_host_agent_clock_unsynchronized",
				"Kernel clock reports STA_UNSYNC via adjtimex (1 = not synchronized)."},
			{descClockEstErr, "node_host_agent_clock_estimated_error_seconds",
				"adjtimex Timex.Esterror exported as seconds."},
		}},
	{name: "conntrack",
		emit: (*Collector).collectConntrack,
		families: []descMeta{
			{descCtEntries, "node_host_agent_conntrack_entries",
				"nf_conntrack_count — conntrack table entries currently tracked."},
			{descCtLimit, "node_host_agent_conntrack_limit",
				"nf_conntrack_max — conntrack table capacity."},
			{descCtRatio, "node_host_agent_conntrack_used_ratio",
				"Conntrack table fill ratio (entries/limit)."},
			{descCtInsertFail, "node_host_agent_conntrack_insert_failed_total",
				"insert_failed column sum over all CPU rows of nf_conntrack stats."},
			{descCtDrops, "node_host_agent_conntrack_drops_total",
				"drop column sum over all CPU rows of nf_conntrack stats."},
		}},
	{name: "filesystem",
		emit: (*Collector).collectFilesystem,
		families: []descMeta{
			{descFSInodesTotal, "node_host_agent_filesystem_inodes_total",
				"Total inodes on the probed mount (statfs Files)."},
			{descFSInodesFree, "node_host_agent_filesystem_inodes_free",
				"Free inodes on the probed mount (statfs Ffree)."},
			{descFSInodesRatio, "node_host_agent_filesystem_inodes_used_ratio",
				"Used-inode share of the probed mount."},
			{descFSProbeStalled, "node_host_agent_filesystem_probe_stalled",
				"statfs probe of this mount exceeded the deadline (1 = hung mount)."},
			{descFSReadonly, "node_host_agent_filesystem_readonly",
				"Probed mount reports ST_RDONLY via statfs (1 = filesystem remounted read-only)."},
		}},
	{name: "filefd",
		emit: (*Collector).collectFileFD,
		families: []descMeta{
			{descFileFDAlloc, "node_host_agent_filefd_allocated",
				"file-nr field 0 — file handles currently allocated."},
			{descFileFDMax, "node_host_agent_filefd_maximum",
				"file-nr field 2 — file handle limit."},
			{descFileFDRatio, "node_host_agent_filefd_used_ratio",
				"file-nr allocated/maximum."},
		}},
	{name: "sockstat",
		emit: (*Collector).collectSockstat,
		families: []descMeta{
			{descSockTCPInuse, "node_host_agent_sockstat_tcp_inuse",
				"sockstat TCP inuse — TCP sockets in use."},
			{descSockTCPOrphan, "node_host_agent_sockstat_tcp_orphan",
				"sockstat TCP orphan — orphaned TCP connections."},
			{descSockTCPTW, "node_host_agent_sockstat_tcp_tw",
				"sockstat TCP tw — TCP sockets in TIME_WAIT."},
			{descSockUsed, "node_host_agent_sockstat_sockets_used",
				"sockstat 'sockets: used' — total sockets in use."},
			{descSockTCPCW, "node_host_agent_sockstat_tcp_close_wait",
				"sockstat TCP close_wait."},
		}},
	{name: "pki-certs",
		emit: (*Collector).collectPKICerts,
		families: []descMeta{
			{descPKIDays, "node_host_agent_pki_cert_days_left",
				"Days until the earliest notAfter of the on-disk PKI cert at this path."},
		}},
	{name: "inotify",
		emit: (*Collector).collectInotify,
		families: []descMeta{
			{descInotifyInst, "node_host_agent_inotify_instances_used_ratio",
				"inotify fds in use / max_user_instances."},
			{descInotifyWatches, "node_host_agent_inotify_watches_used_ratio",
				"inotify watches in use / max_user_watches."},
		}},
	{name: "zombies",
		emit: (*Collector).collectZombies,
		families: []descMeta{
			{descZombies, "node_host_agent_processes_zombie_count",
				"Processes in state Z under the host proc root."},
			{descDState, "node_host_agent_dstate_processes",
				"Processes in state D (uninterruptible sleep) under the host proc root."},
		}},
	{name: "cgroup-pids",
		emit: (*Collector).collectCgroupPids,
		families: []descMeta{
			{descCgroupPids, "node_host_agent_cgroup_pids_used_ratio",
				"pids.current / pids.max of the slice."},
		}},
	{name: "mtu-drift",
		emit: (*Collector).collectMTUDrift,
		families: []descMeta{
			{descMTUDrift, "node_host_agent_mtu_drift",
				"cilium datapath MTU exceeds the nebula overlay MTU (1 = drift)."},
		}},
	{name: "memory-io",
		emit: (*Collector).collectMemoryIO,
		families: []descMeta{
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
		}},
	{name: "systemd-scopes",
		emit: (*Collector).collectSystemdScopes,
		families: []descMeta{
			{descSystemdScopes, "node_host_agent_systemd_scopes_count",
				"cri-containerd-*.scope dirs under the kubepods cgroup slice."},
		}},
	{name: "arp",
		emit: (*Collector).collectARP,
		families: []descMeta{
			{descARPEntries, "node_host_agent_arp_entries",
				"Entries in the ARP neighbour table."},
		}},
	{name: "cgroup-mem-events",
		emit: (*Collector).collectCgroupMemEvents,
		families: []descMeta{
			{descCgMemHigh, "node_host_agent_cgroup_memory_high_events_total",
				"memory.events high of the unit — direct-reclaim throttling."},
			{descCgMemOOMKill, "node_host_agent_cgroup_memory_oom_kill_events_total",
				"memory.events oom_kill of the unit."},
		}},
	{name: "kernel-keys",
		emit: (*Collector).collectKernelKeys,
		families: []descMeta{
			{descKernelKeys, "node_host_agent_kernel_keys_used_ratio",
				"Highest per-UID keyring fill ratio from /proc/key-users."},
		}},
	{name: "localpv",
		emit: (*Collector).collectLocalPVUsage,
		families: []descMeta{
			{descLocalPVDirBytes, "node_host_agent_localpv_dir_bytes",
				"Bytes under the OpenEBS LocalPV pvc-* volume dir."},
		}},
	{name: "netstat-snmp",
		emit: (*Collector).collectNetstatSNMP,
		families: []descMeta{
			{descNetstatListenOverflows, "node_host_agent_netstat_tcp_listen_overflows_total",
				"TcpExt ListenOverflows — SYNs dropped on a full accept queue."},
			{descNetstatListenDrops, "node_host_agent_netstat_tcp_listen_drops_total",
				"TcpExt ListenDrops — connections dropped from a full listen backlog."},
			{descNetstatSynRetrans, "node_host_agent_netstat_tcp_syn_retrans_total",
				"TcpExt TCPSynRetrans — retransmitted SYNs."},
			{descNetstatTCPTimeouts, "node_host_agent_netstat_tcp_timeouts_total",
				"TcpExt TCPTimeouts — connections that timed out."},
			{descSNMPReasmFails, "node_host_agent_snmp_ip_reasm_fails_total",
				"Ip ReasmFails — IP fragment reassembly failures."},
			{descSNMPRcvbufErrors, "node_host_agent_snmp_udp_rcvbuf_errors_total",
				"Udp RcvbufErrors — UDP datagrams dropped on a full receive buffer."},
		}},
}

// descMetaTable maps each desc to its textfile fqName/help — a
// prometheus.Metric carries the Desc but the fqName is only
// reachable through Desc.String(), so the writer keeps its own
// lookup keyed off the same domainTable Describe() serves.
var descMetaTable = func() map[*prometheus.Desc]descMeta {
	n := 0
	for _, d := range domainTable {
		n += len(d.families)
	}
	m := make(map[*prometheus.Desc]descMeta, n)
	for _, d := range domainTable {
		for _, f := range d.families {
			m[f.desc] = f
		}
	}
	return m
}()

// Describe implements prometheus.Collector — every family every
// domain can emit, in table order.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range domainTable {
		for _, f := range d.families {
			ch <- f.desc
		}
	}
}
