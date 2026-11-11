package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// counterValue mirrors metricValue for Counter-typed series.
func counterValue(t *testing.T, c *Collector, name string,
	labels map[string]string) (float64, bool) {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			if matchLabels(m, labels) {
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// --- conntrack-arp-pressure: conntrack stat + ARP ---

const conntrackStatBody = "  entries  searched found insert insert_failed drop early_drop\n" +
	"00000ed4  00000000 00000000 00000000 0000000a 00000004 00000000\n" +
	"00000ed5  00000000 00000000 00000000 00000014 00000002 00000000\n"

func TestConntrackStatParse(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "nf_conntrack")
	testutil.WriteFile(t, f, conntrackStatBody)
	st, ok := procfs.ReadConntrackStat(f)
	if !ok {
		t.Fatal("ReadConntrackStat reported unparsed")
	}
	// hex sums: 0xa+0x14=30 insert_failed, 0x4+0x2=6 drop.
	if st.InsertFailed != 30 || st.Drop != 6 {
		t.Fatalf("conntrack stat = %+v, want insert_failed=30 drop=6", st)
	}
	if _, ok := procfs.ReadConntrackStat(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing file must report unparsed")
	}
}

func TestCollectConntrackStat(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, cfg.ConntrackStatFile, conntrackStatBody)
	c := New(cfg)
	v, ok := counterValue(t, c, "node_host_agent_conntrack_insert_failed_total",
		map[string]string{"node": "node-a"})
	if !ok || v != 30 {
		t.Fatalf("insert_failed = %v ok=%v, want 30", v, ok)
	}
	v, ok = counterValue(t, c, "node_host_agent_conntrack_drops_total",
		map[string]string{"node": "node-a"})
	if !ok || v != 6 {
		t.Fatalf("drops = %v ok=%v, want 6", v, ok)
	}
}

func TestCollectARP(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.ARPTableFile = filepath.Join(t.TempDir(), "arp")
	testutil.WriteFile(t, cfg.ARPTableFile,
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"+
			"10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0\n"+
			"10.0.0.3         0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n")
	c := New(cfg)
	v, ok := metricValue(t, c, "node_host_agent_arp_entries",
		map[string]string{"node": "node-a"})
	if !ok || v != 3 {
		t.Fatalf("arp_entries = %v ok=%v, want 3", v, ok)
	}
}

// --- d-state-storm + systemd-scopes: dstate + scope footprint ---

func TestCollectDStateProcesses(t *testing.T) {
	cfg, dirs := fixture(t)
	for pid, state := range map[int]string{101: "S", 102: "D", 103: "D", 104: "Z"} {
		pd := filepath.Join(dirs["proc"], strconv.Itoa(pid))
		if err := os.MkdirAll(pd, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(pd, "stat"),
			"1 (fakeproc) "+state+" 0 0 0\n")
	}
	c := New(cfg)
	v, ok := metricValue(t, c, "node_host_agent_dstate_processes",
		map[string]string{"node": "node-a"})
	if !ok || v != 2 {
		t.Fatalf("dstate_processes = %v ok=%v, want 2", v, ok)
	}
	v, ok = metricValue(t, c, "node_host_agent_processes_zombie_count",
		map[string]string{"node": "node-a"})
	if !ok || v != 1 {
		t.Fatalf("zombie_count = %v ok=%v, want 1", v, ok)
	}
}

func TestCollectSystemdScopes(t *testing.T) {
	cfg, _ := fixture(t)
	kube := filepath.Join(cfg.CgroupRoot, "kubepods.slice")
	for _, d := range []string{
		"kubepods-burstable.slice/pod_abc.slice/cri-containerd-aa11.scope",
		"kubepods-burstable.slice/pod_def.slice/cri-containerd-bb22.scope",
		"kubepods-besteffort.slice/pod_xyz.slice/cri-containerd-cc33.scope",
		"kubepods-besteffort.slice/pod_xyz.slice/other.slice",
	} {
		if err := os.MkdirAll(filepath.Join(kube, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := New(cfg)
	v, ok := metricValue(t, c, "node_host_agent_systemd_scopes_count",
		map[string]string{"node": "node-a"})
	if !ok || v != 3 {
		t.Fatalf("systemd_scopes_count = %v ok=%v, want 3", v, ok)
	}
}

// --- memory-events-reclaim: cgroup memory.events ---

func TestCollectCgroupMemEvents(t *testing.T) {
	cfg, _ := fixture(t)
	for unit, body := range map[string]string{
		"k0sworker.service":     "low 0\nhigh 17\nmax 0\noom 0\noom_kill 2\noom_group_kill 1\n",
		"k0scontroller.service": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
	} {
		d := filepath.Join(cfg.CgroupRoot, "system.slice", unit)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		testutil.WriteFile(t, filepath.Join(d, "memory.events"), body)
	}
	// pod-cgroup-oomkill-metrics — the whole pod-workload slice joins the per-unit set.
	pods := filepath.Join(cfg.CgroupRoot, "kubepods.slice")
	if err := os.MkdirAll(pods, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(pods, "memory.events"),
		"low 0\nhigh 9\nmax 0\noom 0\noom_kill 4\noom_group_kill 3\n")
	c := New(cfg)
	v, ok := counterValue(t, c, "node_host_agent_cgroup_memory_high_events_total",
		map[string]string{"node": "node-a", "unit": "k0sworker.service"})
	if !ok || v != 17 {
		t.Fatalf("memory_high{worker} = %v ok=%v, want 17", v, ok)
	}
	v, ok = counterValue(t, c, "node_host_agent_cgroup_memory_oom_kill_events_total",
		map[string]string{"node": "node-a", "unit": "k0sworker.service"})
	if !ok || v != 2 {
		t.Fatalf("oom_kill{worker} = %v ok=%v, want 2", v, ok)
	}
	v, ok = counterValue(t, c, "node_host_agent_cgroup_memory_oom_group_kill_events_total",
		map[string]string{"node": "node-a", "unit": "k0sworker.service"})
	if !ok || v != 1 {
		t.Fatalf("oom_group_kill{worker} = %v ok=%v, want 1", v, ok)
	}
	// kubepods.slice series — pod-workload memory.events now visible.
	v, ok = counterValue(t, c, "node_host_agent_cgroup_memory_high_events_total",
		map[string]string{"node": "node-a", "unit": "kubepods.slice"})
	if !ok || v != 9 {
		t.Fatalf("memory_high{kubepods.slice} = %v ok=%v, want 9", v, ok)
	}
	v, ok = counterValue(t, c, "node_host_agent_cgroup_memory_oom_kill_events_total",
		map[string]string{"node": "node-a", "unit": "kubepods.slice"})
	if !ok || v != 4 {
		t.Fatalf("oom_kill{kubepods.slice} = %v ok=%v, want 4", v, ok)
	}
	v, ok = counterValue(t, c, "node_host_agent_cgroup_memory_oom_group_kill_events_total",
		map[string]string{"node": "node-a", "unit": "kubepods.slice"})
	if !ok || v != 3 {
		t.Fatalf("oom_group_kill{kubepods.slice} = %v ok=%v, want 3", v, ok)
	}
	// A unit without the oom_group_kill key emits no group-kill series.
	if _, ok = counterValue(t, c,
		"node_host_agent_cgroup_memory_oom_group_kill_events_total",
		map[string]string{"node": "node-a", "unit": "k0scontroller.service"}); ok {
		t.Fatal("oom_group_kill emitted for a unit lacking the key")
	}
}
