// collect_daemon_fd.go — daemon-fd per-daemon fd exhaustion plus the
// containerd bbolt metadata size. fs.file-nr can read 1% while one
// daemon sits at ITS RLIMIT_NOFILE — the first symptom of a
// socket/pipe leak is per-process, not per-host.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// daemonFDTargets are the daemons whose /proc/<pid>/fd count is
// divided by their RLIMIT_NOFILE soft limit (daemon-fd). comm is the
// 15-char TASK_COMM match; cmdlineArg disambiguates procs sharing a
// comm — k0sworker and k0scontroller both run with comm "k0s", only
// argv[1] tells them apart.
var daemonFDTargets = []struct {
	daemon     string // {daemon} label
	comm       string // /proc/<pid>/comm exact match
	cmdlineArg string // argv[1] discriminator, "" = none needed
}{
	{"k0sworker", "k0s", "worker"},
	{"k0scontroller", "k0s", "controller"},
	{"containerd", "containerd", ""},
	{"kubelet", "kubelet", ""},
	{"cilium-agent", "cilium-agent", ""},
	{"nebula", "nebula", ""},
	{"haproxy", "haproxy", ""},
	{"postgres", "postgres", ""},
	{"pgbouncer", "pgbouncer", ""},
}

// defaultContainerdMetaDB is the bbolt metadata file path relative
// to HostRoot (applyDefaults joins it) — postmortem containerd#4604:
// meta.db bloat after tens of thousands of image pulls slows every
// CRI call.
const defaultContainerdMetaDB = "var/lib/k0s/containerd/io.containerd.metadata.v1.bolt/meta.db"

var (
	descDaemonFDRatio = prometheus.NewDesc(
		"node_host_agent_daemon_fd_used_ratio",
		"Open fds / RLIMIT_NOFILE(soft) of the worst-off matching process per daemon (emitted only when a watched process's limit parses).",
		[]string{"node", "daemon"}, nil)
	descContainerdMetaDB = prometheus.NewDesc(
		"node_host_agent_containerd_metadb_bytes",
		"Size of the containerd bbolt metadata db (io.containerd.metadata.v1.bolt/meta.db).",
		[]string{"node"}, nil)
)

// matchDaemon returns the {daemon} label for a pid's comm, "" when
// the process is not a watched daemon. k0s procs share comm "k0s" —
// the mode token in argv[1] decides worker vs controller.
func matchDaemon(comm, cmdline string) string {
	for _, d := range daemonFDTargets {
		if comm != d.comm {
			continue
		}
		if d.cmdlineArg == "" {
			return d.daemon
		}
		argv := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
		if len(argv) > 1 && argv[1] == d.cmdlineArg {
			return d.daemon
		}
	}
	return ""
}

// procLimitsSoftFD parses the "Max open files" SOFT limit column of
// /proc/<pid>/limits — "unlimited" (and any malformed line) is not a
// bound, so ok=false.
func procLimitsSoftFD(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		// "Max open files <soft> <hard> files"
		f := strings.Fields(line)
		if len(f) < 5 {
			return 0, false
		}
		soft, err := strconv.ParseUint(f[3], 10, 64)
		if err != nil || soft == 0 {
			return 0, false
		}
		return soft, true
	}
	return 0, false
}

// collectDaemonFD emits the worst (highest) open-fd/soft-limit ratio
// per watched daemon in one ProcRoot pass. Several procs share a
// comm (postgres workers, pgbouncer) — the max ratio is the
// exhaustion signal, so per-daemon series report it rather than an
// arbitrary pid's value.
func (c *Collector) collectDaemonFD(ch chan<- prometheus.Metric) {
	entries, err := os.ReadDir(c.cfg.ProcRoot)
	if err != nil {
		return
	}
	worst := map[string]float64{}
	for _, e := range entries {
		if !e.IsDir() || !pidDirRe.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(c.cfg.ProcRoot, e.Name())
		commB, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commB))
		var cmdline string
		if comm == "k0s" {
			if b, rerr := os.ReadFile(filepath.Join(dir, "cmdline")); rerr == nil {
				cmdline = string(b)
			}
		}
		daemon := matchDaemon(comm, cmdline)
		if daemon == "" {
			continue
		}
		soft, ok := procLimitsSoftFD(filepath.Join(dir, "limits"))
		if !ok {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		if r := float64(len(fds)) / float64(soft); r > worst[daemon] {
			worst[daemon] = r
		}
	}
	for daemon, r := range worst {
		ch <- prometheus.MustNewConstMetric(descDaemonFDRatio,
			prometheus.GaugeValue, r, c.cfg.NodeName, daemon)
	}
}

// collectContainerdMetaDB emits the bbolt meta.db size — absent
// when the file is missing (containerd not under k0s on this host).
func (c *Collector) collectContainerdMetaDB(ch chan<- prometheus.Metric) {
	fi, err := os.Stat(c.cfg.ContainerdMetaDBFile)
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(descContainerdMetaDB,
		prometheus.GaugeValue, float64(fi.Size()), c.cfg.NodeName)
}
