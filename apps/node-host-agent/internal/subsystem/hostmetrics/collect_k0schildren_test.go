// collect_k0schildren_test.go — gomemlimit-sum per-child RSS of
// k0scontroller.service.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// childProcFixture seeds a pid dir with argv0/status for the RSS
// mapping.
func childProcFixture(t *testing.T, cfg Config, pid, argv0, comm string, rssKB int) {
	t.Helper()
	dir := filepath.Join(cfg.ProcRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "cmdline"), argv0+"\x00")
	testutil.WriteFile(t, filepath.Join(dir, "comm"), comm+"\n")
	testutil.WriteFile(t, filepath.Join(dir, "status"),
		"Name:   "+comm+"\nState:  S (sleeping)\nVmRSS:\t    "+
			strconv.Itoa(rssKB)+" kB\n")
}

func TestCollectK0sChildrenRSS(t *testing.T) {
	cfg, _ := fixture(t)
	slice := filepath.Join(cfg.CgroupRoot, "system.slice", "k0scontroller.service")
	if err := os.MkdirAll(slice, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(slice, "cgroup.procs"), "10\n11\n12\n13\n14\n15\n99\n")

	childProcFixture(t, cfg, "10", "/usr/local/bin/k0s", "k0s", 50*1024)
	childProcFixture(t, cfg, "11", "/var/lib/k0s/bin/kube-apiserver", "kube-apiserver", 2400*1024)
	childProcFixture(t, cfg, "12", "/var/lib/k0s/bin/etcd", "etcd", 900*1024)
	childProcFixture(t, cfg, "13", "/var/lib/k0s/bin/kube-controller-manager", "kube-controller", 300*1024)
	childProcFixture(t, cfg, "14", "/var/lib/k0s/bin/kube-scheduler", "kube-scheduler", 200*1024)
	childProcFixture(t, cfg, "15", "/var/lib/k0s/bin/konnectivity-server", "konnectivity-se", 100*1024)
	// pid 99: a foreign proc outside the label set — skipped.
	childProcFixture(t, cfg, "99", "/usr/bin/sshd", "sshd", 10*1024)

	c := New(cfg)
	for child, wantKB := range map[string]int{
		"k0scontroller":           50 * 1024,
		"kube-apiserver":          2400 * 1024,
		"etcd":                    900 * 1024,
		"kube-controller-manager": 300 * 1024,
		"kube-scheduler":          200 * 1024,
		"konnectivity-server":     100 * 1024,
	} {
		got, ok := metricValue(t, c,
			"node_host_agent_k0scontroller_children_rss_bytes",
			map[string]string{"node": "node-a", "child": child})
		if !ok || got != float64(wantKB)*1024 {
			t.Fatalf("children_rss{%s}=%v ok=%v want %v bytes", child, got, ok, float64(wantKB)*1024)
		}
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_k0scontroller_children_rss_bytes",
		map[string]string{"node": "node-a", "child": "sshd"}); ok {
		t.Fatal("foreign proc emitted a child series")
	}
}

func TestCollectK0sChildrenNoSlice(t *testing.T) {
	cfg, _ := fixture(t) // no cgroup.procs — worker node shape
	c := New(cfg)
	if _, ok := metricValue(t, c,
		"node_host_agent_k0scontroller_children_rss_bytes",
		map[string]string{"node": "node-a", "child": "kube-apiserver"}); ok {
		t.Fatal("children RSS emitted without the controller slice")
	}
}

// TestK0sChildLabelFallbacks: a proc with no cmdline (or one
// without a NUL-terminated argv0) falls back to comm; neither file
// resolving yields no label.
func TestK0sChildLabelFallbacks(t *testing.T) {
	dir := t.TempDir()
	commOnly := filepath.Join(dir, "comm-only")
	if err := os.MkdirAll(commOnly, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(commOnly, "comm"), "etcd\n")
	if got := k0sChildLabel(commOnly); got != "etcd" {
		t.Fatalf("comm-only label=%q want etcd", got)
	}

	// A cmdline without a single NUL byte (kernel-clamped or raced
	// read) cannot yield an argv0 — comm still answers.
	testutil.WriteFile(t, filepath.Join(commOnly, "cmdline"), "/usr/bin/kine-no-nul")
	if got := k0sChildLabel(commOnly); got != "etcd" {
		t.Fatalf("no-NUL cmdline label=%q want the comm fallback etcd", got)
	}

	// Neither file readable → no label, the pid is skipped.
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := k0sChildLabel(empty); got != "" {
		t.Fatalf("unresolvable label=%q want empty", got)
	}
}

// TestProcVMRSSMalformed: a status without a VmRSS line, a bare
// "VmRSS:" header and a non-numeric size are all unparseable —
// never a silent 0.
func TestProcVMRSSMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "status")
	testutil.WriteFile(t, p, "Name:\tx\nState:\tS (sleeping)\n")
	if _, ok := procVMRSS(p); ok {
		t.Fatal("status without a VmRSS line parsed")
	}
	testutil.WriteFile(t, p, "VmRSS:\n")
	if _, ok := procVMRSS(p); ok {
		t.Fatal("bare VmRSS header parsed")
	}
	testutil.WriteFile(t, p, "VmRSS:\tnotanumber kB\n")
	if _, ok := procVMRSS(p); ok {
		t.Fatal("non-numeric VmRSS parsed")
	}
	if _, ok := procVMRSS(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing status file parsed")
	}
	testutil.WriteFile(t, p, "VmRSS:\t12 kB\n")
	if v, ok := procVMRSS(p); !ok || v != 12<<10 {
		t.Fatalf("VmRSS=%v ok=%v want %v bytes", v, ok, 12<<10)
	}
}
