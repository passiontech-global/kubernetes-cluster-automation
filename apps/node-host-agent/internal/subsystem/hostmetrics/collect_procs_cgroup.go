// collect_procs_cgroup.go — A2 zombie/d-state counts, cgroup
// pids/memory.events pressure (systemd-scopes/memory-events-reclaim), the kubepods
// cri-containerd scope footprint, and B4/overlay-MTU drift. Split out
// of hostmetrics.go.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

const (
	defaultCgroupRoot     = "/sys/fs/cgroup"
	defaultCiliumIface    = "cilium_net"
	defaultCiliumWG0Iface = "cilium_wg0"
)

// defaultCgroupPidsSlices are the cgroup-v2 dirs whose
// pids.current/pids.max feed the pids-used-ratio gauge (A2) — the
// k0s units plus the whole pod workload slice.
var defaultCgroupPidsSlices = []string{
	"system.slice/k0sworker.service",
	"system.slice/k0scontroller.service",
	"kubepods.slice",
}

// defaultCgroupMemUnits are the system.slice units whose
// memory.events feed the memory-events-reclaim reclaim-throttling counters — the
// k0s daemons whose freeze-under-high is the classic gray failure.
var defaultCgroupMemUnits = []string{
	"k0scontroller.service",
	"k0sworker.service",
}

// --- A2: zombie count + cgroup pids pressure ---

var (
	descZombies = prometheus.NewDesc(
		"node_host_agent_processes_zombie_count",
		"Processes in state Z under the host proc root (emitted only when the scan succeeds).",
		[]string{"node"}, nil)
	// d-state-storm: uninterruptible-sleep count — the same /proc walk.
	descDState = prometheus.NewDesc(
		"node_host_agent_dstate_processes",
		"Processes in state D (uninterruptible sleep) under the host proc root (emitted only when the scan succeeds).",
		[]string{"node"}, nil)
)

// collectZombies counts state Z processes under ProcRoot — off the
// shared procSnapshot (collect_procs_scan.go), so the daemon-fd
// collector and this one cost ONE /proc walk per scan interval.
// Emits only when the proc root scans.
func (c *Collector) collectZombies(ch chan<- prometheus.Metric) {
	procs, ok := c.procSnapshot()
	if !ok {
		return
	}
	var n, dstate float64
	for _, ps := range procs {
		switch ps.state {
		case 'Z':
			n++
		case 'D': // d-state-storm: uninterruptible-sleep count, same scan
			dstate++
		}
	}
	ch <- prometheus.MustNewConstMetric(descZombies,
		prometheus.GaugeValue, n, c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(descDState,
		prometheus.GaugeValue, dstate, c.cfg.NodeName)
}

var descCgroupPids = prometheus.NewDesc(
	"node_host_agent_cgroup_pids_used_ratio",
	"pids.current / pids.max of the slice (emitted only when both files parse and max > 0).",
	[]string{"node", "slice"}, nil)

// collectCgroupPids emits pids.current/pids.max per slice — a
// missing or non-numeric ("max") limit yields no ratio (never a
// fake 0). The pids.current/pids.max filenames are cgroup-v2
// unified-hierarchy only — k0s hosts are v2; on a v1 host the
// files simply don't exist and no series emits.
func (c *Collector) collectCgroupPids(ch chan<- prometheus.Metric) {
	for _, slice := range c.cfg.CgroupPidsSlices {
		cur, ok := hostutil.ReadUintFile(filepath.Join(
			c.cfg.CgroupRoot, slice, "pids.current"))
		if !ok {
			continue
		}
		mx, ok := hostutil.ReadUintFile(filepath.Join(
			c.cfg.CgroupRoot, slice, "pids.max"))
		if !ok || mx == 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(descCgroupPids,
			prometheus.GaugeValue, float64(cur)/float64(mx),
			c.cfg.NodeName, slice)
	}
}

// --- B4: MTU drift (cilium datapath vs nebula overlay) ---
//
// mtuOfIface/jsonFindInts/runtimeConfigMTU live in
// internal/platform/hostutil now — the same helpers workerhygiene's
// checkCiliumMTU uses (hostutil.MTUOfIface / JSONFindInts /
// RuntimeConfigMTU).

var descMTUDrift = prometheus.NewDesc(
	"node_host_agent_mtu_drift",
	"cilium datapath MTU exceeds the nebula overlay MTU (1 = drift; emitted only when both MTUs resolve).",
	[]string{"node"}, nil)

// wgEncapOverheadBytes is the WireGuard encapsulation overhead the
// cilium_wg0 MTU must leave under the nebula overlay MTU (double-encap
// guard — same constant as workerhygiene).
const wgEncapOverheadBytes = 60

// collectMTUDrift emits 1 when a pod-datapath MTU exceeds what the
// overlay path can carry — a pod holding MTU 1500 dies silently on
// FRAG_NEEDED through neb1 (1300). Two datapaths are checked:
// cilium_net (sysfs, falling back to agent-runtime-config.json)
// must stay <= neb, and cilium_wg0 must stay <= neb-60 to leave
// room for the WG header inside the double-encapsulated path, and
// (lxc-mtu-drift) the MAX pod lxc* veth MTU must stay <= neb — a stale
// pod veth dies on FRAG_NEEDED even with aligned datapath ifaces.
// The series emits when the overlay MTU resolves AND at least one
// datapath or pod-veth MTU resolves; absent interfaces simply don't
// vote.
func (c *Collector) collectMTUDrift(ch chan<- prometheus.Metric) {
	neb, ok := hostutil.MTUOfIface(c.cfg.SysClassNet, c.cfg.NebulaIface)
	if !ok {
		return
	}
	cil, cilOK := hostutil.MTUOfIface(c.cfg.SysClassNet, c.cfg.CiliumIface)
	if !cilOK {
		cil, cilOK = hostutil.RuntimeConfigMTU(c.cfg.CiliumRuntimeConfig)
	}
	wg, wgOK := hostutil.MTUOfIface(c.cfg.SysClassNet, c.cfg.CiliumWG0Iface)
	lxcMax, lxcOK := hostutil.MaxPodLxcMTU(c.cfg.SysClassNet)
	if !cilOK && !wgOK && !lxcOK {
		return
	}
	drift := 0.0
	if (cilOK && cil > neb) || (wgOK && wg > neb-wgEncapOverheadBytes) ||
		(lxcOK && lxcMax > neb) {
		drift = 1
	}
	ch <- prometheus.MustNewConstMetric(descMTUDrift,
		prometheus.GaugeValue, drift, c.cfg.NodeName)
}

// --- systemd scope footprint, ARP entries, cgroup memory.events ---

var (
	// systemd-scopes: the abandoned cri-containerd scope footprint.
	descSystemdScopes = prometheus.NewDesc(
		"node_host_agent_systemd_scopes_count",
		"cri-containerd-*.scope dirs under the kubepods cgroup slice — the abandoned-scope footprint slowing PID 1 D-Bus.",
		[]string{"node"}, nil)
	// memory-events-reclaim: memory.events reclaim-throttling counters.
	descCgMemHigh = prometheus.NewDesc(
		"node_host_agent_cgroup_memory_high_events_total",
		"memory.events `high` of the unit — direct-reclaim throttling episodes (freeze, not OOMKill).",
		[]string{"node", "unit"}, nil)
	descCgMemOOMKill = prometheus.NewDesc(
		"node_host_agent_cgroup_memory_oom_kill_events_total",
		"memory.events `oom_kill` of the unit — actual OOM kills counted by the cgroup.",
		[]string{"node", "unit"}, nil)
	descCgMemOOMGroupKill = prometheus.NewDesc(
		"node_host_agent_cgroup_memory_oom_group_kill_events_total",
		"memory.events `oom_group_kill` of the unit — whole-cgroup OOM kills (every task terminated at once).",
		[]string{"node", "unit"}, nil)
)

// collectSystemdScopes counts cri-containerd-*.scope dirs under the
// kubepods cgroup slice (systemd-scopes): a leaking abandoned-scope
// footprint is what slows every PID 1 D-Bus call down before
// systemctl-level symptoms appear. Counted directly in the cgroup
// fs — no systemctl fork per scrape. Emits only when the slice
// root exists.
func (c *Collector) collectSystemdScopes(ch chan<- prometheus.Metric) {
	root := filepath.Join(c.cfg.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(root); err != nil {
		return
	}
	var n float64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger().Debug("hostmetrics: kubepods scope walk entry skipped — unreadable",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), "cri-containerd-") &&
			strings.HasSuffix(d.Name(), ".scope") {
			n++
		}
		return nil
	})
	ch <- prometheus.MustNewConstMetric(descSystemdScopes,
		prometheus.GaugeValue, n, c.cfg.NodeName)
}

// collectCgroupMemEvents reads memory.events of the configured
// system.slice units (memory-events-reclaim): a climbing `high` count is
// direct-reclaim throttling evidence — the unit freezes without an
// OOMKill, the classic healthcheck-timeout-with-no-logs gray
// failure; `oom_kill` counts the kills that do happen and
// `oom_group_kill` the whole-cgroup ones. Each series emits only
// when its own field parses. pod-cgroup-oomkill-metrics adds the whole pod-workload
// slice alongside the k0s daemons — pod-level high/oom_kill/
// oom_group_kill counts were invisible while only system.slice
// units were watched; the unit label spells it "kubepods.slice".
func (c *Collector) collectCgroupMemEvents(ch chan<- prometheus.Metric) {
	emit := func(unit, dir string) {
		ev := vmstatCounters(filepath.Join(c.cfg.CgroupRoot, dir,
			"memory.events"), "high", "oom_kill", "oom_group_kill")
		if v, ok := ev["high"]; ok {
			ch <- prometheus.MustNewConstMetric(descCgMemHigh,
				prometheus.CounterValue, float64(v), c.cfg.NodeName, unit)
		}
		if v, ok := ev["oom_kill"]; ok {
			ch <- prometheus.MustNewConstMetric(descCgMemOOMKill,
				prometheus.CounterValue, float64(v), c.cfg.NodeName, unit)
		}
		if v, ok := ev["oom_group_kill"]; ok {
			ch <- prometheus.MustNewConstMetric(descCgMemOOMGroupKill,
				prometheus.CounterValue, float64(v), c.cfg.NodeName, unit)
		}
	}
	for _, unit := range c.cfg.CgroupMemUnits {
		emit(unit, filepath.Join("system.slice", unit))
	}
	emit("kubepods.slice", "kubepods.slice")
}
