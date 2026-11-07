// collect_k0schildren.go — gomemlimit-sum per-child RSS inside the
// k0scontroller.service cgroup. GOMEMLIMIT is a PER-PROCESS soft cap
// for every Go child in the unit, so the cgroup-OOM risk is the SUM
// of children RSS vs MemoryMax — this series is the evidence the
// sizing rule (and the K0sControllerChildrenMemoryHigh alert) needs.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// k0sControllerSlice is the cgroup-v2 dir (relative to CgroupRoot)
// whose cgroup.procs lists the control-plane children.
const k0sControllerSlice = "system.slice/k0scontroller.service"

// k0sChildLabels maps a child's argv0 basename (comm fallback) to
// its {child} label. "k0s" is the supervisor itself — it carries the
// k0scontroller label rather than the binary name so the series set
// reads like the unit's process roster.
var k0sChildLabels = map[string]string{
	"kube-apiserver":          "kube-apiserver",
	"kine":                    "kine",
	"etcd":                    "etcd",
	"kube-controller-manager": "kube-controller-manager",
	"kube-scheduler":          "kube-scheduler",
	"konnectivity-server":     "konnectivity-server",
	"k0s":                     "k0scontroller",
}

var descK0sChildrenRSS = prometheus.NewDesc(
	"node_host_agent_k0scontroller_children_rss_bytes",
	"RSS bytes per child process of k0scontroller.service (summed when several pids share a label).",
	[]string{"node", "child"}, nil)

// k0sChildLabel resolves a pid's {child} label from argv0's
// basename, falling back to comm — comm is TASK_COMM_LEN-truncated
// ("kube-controller-manager" reads "kube-controller"), so argv0 is
// the precise source.
func k0sChildLabel(procDir string) string {
	if b, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		if i := strings.IndexByte(string(b), 0); i > 0 {
			return k0sChildLabels[filepath.Base(string(b[:i]))]
		}
	}
	if b, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		return k0sChildLabels[strings.TrimSpace(string(b))]
	}
	return ""
}

// procVMRSS returns VmRSS bytes from /proc/<pid>/status ("VmRSS:
// <n> kB"), ok=false when absent/unparseable.
func procVMRSS(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line) // "VmRSS:" "<n>" "kB"
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb << 10, true
	}
	return 0, false
}

// collectK0sChildrenRSS sums VmRSS per child label over
// k0scontroller.service's cgroup.procs — emits nothing on workers
// (no controller unit, no cgroup.procs file).
func (c *Collector) collectK0sChildrenRSS(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(filepath.Join(c.cfg.CgroupRoot,
		k0sControllerSlice, "cgroup.procs"))
	if err != nil {
		return
	}
	rss := map[string]uint64{}
	for _, pid := range strings.Fields(string(data)) {
		dir := filepath.Join(c.cfg.ProcRoot, pid)
		label := k0sChildLabel(dir)
		if label == "" {
			continue
		}
		if v, ok := procVMRSS(filepath.Join(dir, "status")); ok {
			rss[label] += v
		}
	}
	for child, v := range rss {
		ch <- prometheus.MustNewConstMetric(descK0sChildrenRSS,
			prometheus.GaugeValue, float64(v), c.cfg.NodeName, child)
	}
}
