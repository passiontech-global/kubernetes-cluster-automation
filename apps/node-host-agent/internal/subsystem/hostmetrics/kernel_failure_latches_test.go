package hostmetrics

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- W10-KR1: kmsg classification ---

// kmsgFixture seeds a resumable kmsg session: boot_id under ProcRoot,
// a kmsg cursor at seq 0, and records in the fixture file.
func kmsgFixture(t *testing.T, cfg Config, records ...string) {
	t.Helper()
	bootDir := filepath.Join(cfg.ProcRoot, "sys", "kernel", "random")
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(bootDir, "boot_id"), "testboot\n")
	testutil.WriteFile(t, filepath.Join(cfg.WatchdogStateDir, kmsgCursorFile),
		"kmsg testboot 0 0\n")
	var b strings.Builder
	for i, m := range records {
		fmt.Fprintf(&b, "6,%d,%d,0;%s\n", i+1, (i+1)*1000, m)
	}
	devDir := filepath.Dir(kmsgDevicePaths(cfg.HostRoot)[0])
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, kmsgDevicePaths(cfg.HostRoot)[0], b.String())
}

func TestKmsgFSAndConntrack(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	kmsgFixture(t, cfg,
		"EXT4-fs error (device sda1): ext4_journal_check_start: "+
			"detected aborted journal",
		"nf_conntrack: table full, dropping packet",
		"nf_conntrack: table full, dropping packet",
		"random unrelated kernel line")
	// Conntrack max file for the sysctl-bump path.
	testutil.WriteFile(t, cfg.ConntrackMaxFile, "262144\n")
	// Sysctl write target — point the bump at a writable file by
	// faking the path through ConntrackMaxFile's sibling? The bump
	// writes /proc/sys/... via a fixed path — check maybeBumpConntrackMax.
	c.Latches().checkKernelDmesg()
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		kmsgFsErrorFile)); err != nil {
		t.Fatal("kmsg-fs-error marker missing")
	}
	got := strings.TrimSpace(testutil.ReadFile(t,
		filepath.Join(cfg.WatchdogStateDir, kmsgConntrackDropsFile)))
	if got != "2" {
		t.Fatalf("conntrack drops=%q want 2", got)
	}
	// Second drain must not double-count — the fd sits at EOF.
	c.Latches().checkKernelDmesg()
	got = strings.TrimSpace(testutil.ReadFile(t,
		filepath.Join(cfg.WatchdogStateDir, kmsgConntrackDropsFile)))
	if got != "2" {
		t.Fatalf("conntrack drops after re-drain=%q want 2", got)
	}
}

func TestKmsgOOMClassification(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	kmsgFixture(t, cfg,
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),"+
			"cpuset=cri-containerd-abc.scope,mems_allowed=0,"+
			"oom_memcg=/kubepods.slice/pod123,task_memcg=/kubepods.slice/pod123,"+
			"task=web-server,pid=1234,uid=0",
		"Out of memory: Killed process 1234 (web-server) total-vm:1kB",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),"+
			"cpuset=/,oom_memcg=/system.slice,task=containerd-shim,pid=99",
		"Out of memory: Killed process 99 (containerd-shim) total-vm:2kB",
		"oom-kill:constraint=CONSTRAINT_NONE,task=somepod,pid=55",
		"Out of memory: Killed process 55 (somepod) total-vm:3kB",
		// Memcg OOM variant — the kernel's COMMON cgroup form must
		// classify identically to the global "Out of memory:" line.
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),"+
			"oom_memcg=/system.slice,task_memcg=/system.slice,"+
			"task=kubelet,pid=88",
		"Memory cgroup out of memory: Killed process 88 (kubelet) total-vm:5kB")
	c.Latches().checkKernelDmesg()
	victim := strings.TrimSpace(testutil.ReadFile(t, filepath.Join(
		cfg.WatchdogStateDir, kmsgOOMVictimFile)))
	if !strings.Contains(victim, "kubelet") {
		t.Fatalf("host OOM victim=%q want kubelet (last host kill)", victim)
	}
	count := strings.TrimSpace(testutil.ReadFile(t, filepath.Join(
		cfg.WatchdogStateDir, kmsgOOMCountFile)))
	if count != "2" {
		t.Fatalf("host oom count=%q want 2 (pod kills excluded)", count)
	}
}

func TestKmsgFirstOpenPrimesBacklog(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// NO cursor — first open must discard the retained backlog.
	bootDir := filepath.Join(cfg.ProcRoot, "sys", "kernel", "random")
	_ = os.MkdirAll(bootDir, 0o755)
	testutil.WriteFile(t, filepath.Join(bootDir, "boot_id"), "testboot\n")
	devDir := filepath.Dir(kmsgDevicePaths(cfg.HostRoot)[0])
	_ = os.MkdirAll(devDir, 0o755)
	testutil.WriteFile(t, kmsgDevicePaths(cfg.HostRoot)[0],
		"6,1,1000,0;EXT4-fs error old history\n")
	c.Latches().checkKernelDmesg()
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatal("backlog record classified on first open")
	}
}

// --- W10-KR2: pid/thread/fd pressure ---

func TestKernelProcRatios(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// Inconclusive when nothing parses.
	if _, _, _, _, _, _, ok := c.Latches().kernelProcRatios(); ok {
		t.Fatal("empty proc reported ok")
	}
	// file-nr only → fd ratio.
	testutil.WriteFile(t, cfg.FileNRFile, "900 100 1000\n")
	_, _, fd, _, _, fdOK, ok := c.Latches().kernelProcRatios()
	if !ok || !fdOK || fd != 0.9 {
		t.Fatalf("fd ratio=%v ok=%v fdOK=%v want 0.9", fd, ok, fdOK)
	}
	// pids: 5 pid dirs / pid_max 10.
	for _, p := range []string{"1", "2", "3", "4", "5"} {
		if err := os.MkdirAll(filepath.Join(cfg.ProcRoot, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		"sys/kernel/pid_max", "sys/kernel/threads-max", "loadavg"} {
		if err := os.MkdirAll(filepath.Join(cfg.ProcRoot,
			filepath.Dir(f)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot, "sys/kernel/pid_max"), "10\n")
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot, "sys/kernel/threads-max"), "100\n")
	testutil.WriteFile(t, filepath.Join(cfg.ProcRoot, "loadavg"),
		"0.5 0.4 0.3 95/200 1234\n")
	pids, threads, _, pOK, tOK, _, ok := c.Latches().kernelProcRatios()
	if !ok || !pOK || !tOK {
		t.Fatalf("ratios not ok: pids=%v threads=%v", pids, threads)
	}
	if pids != 0.5 {
		t.Fatalf("pids ratio=%v want 0.5", pids)
	}
	if threads != 2.0 {
		t.Fatalf("threads ratio=%v want 2.0 (loadavg total 200 / threads-max 100)", threads)
	}
}

func TestPidFDPressureLatch(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	testutil.WriteFile(t, cfg.FileNRFile, "950 50 1000\n") // 0.95 > 0.90
	for i := 0; i < kernelProcPressureNeeded-1; i++ {
		c.Latches().updatePidFDPressure()
		if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
			"state-pid-fd-pressure")); !os.IsNotExist(err) {
			t.Fatalf("latch set early at tick %d", i+1)
		}
	}
	c.Latches().updatePidFDPressure()
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-pid-fd-pressure")); err != nil {
		t.Fatal("pid-fd-pressure latch missing after 3 ticks")
	}
	// Below threshold clears.
	testutil.WriteFile(t, cfg.FileNRFile, "100 900 1000\n")
	c.Latches().updatePidFDPressure()
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-pid-fd-pressure")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared below threshold")
	}
	// Textfile gauge emitted.
	textfileDirOverride = t.TempDir()
	c.Latches().updatePidFDPressure()
	b, err := os.ReadFile(filepath.Join(textfileDirOverride,
		"node-agent-kernel.prom"))
	if err != nil {
		t.Fatalf("kernel prom missing: %v", err)
	}
	if !strings.Contains(string(b),
		"node_agent_file_nr_utilization_ratio 0.1") {
		t.Fatalf("file-nr gauge missing/wrong:\n%s", b)
	}
}

// --- W10-KR5: clock skew ---

func TestParseChronycTracking(t *testing.T) {
	off, synced, ok := parseChronycTracking(
		"Reference ID    : A29FC87B (time.cloudflare.com)\n" +
			"System time     : 0.0012 seconds fast of NTP time\n" +
			"Leap status     : Normal\n")
	if !ok || !synced || off != 0.0012 {
		t.Fatalf("off=%v synced=%v ok=%v", off, synced, ok)
	}
	off, synced, ok = parseChronycTracking(
		"System time     : 3.5 seconds slow of NTP time\n" +
			"Leap status     : Not synchronised\n")
	if !ok || synced || off != -3.5 {
		t.Fatalf("off=%v synced=%v ok=%v", off, synced, ok)
	}
	if _, _, ok := parseChronycTracking("garbage\n"); ok {
		t.Fatal("garbage parsed ok")
	}
}

func TestClockSkew(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	// chronyc stub: 3s fast + unsynchronised → step + latch path.
	orig := runHostCmd
	defer func() { runHostCmd = orig }()
	var stepped bool
	runHostCmd = func(ctx context.Context, argv ...string) (string, error) {
		if len(argv) > 1 && argv[1] == "makestep" {
			stepped = true
			return "", nil
		}
		return "System time     : 3.0 seconds fast of NTP time\n" +
			"Leap status     : Not synchronised\n", nil
	}
	for i := 0; i < clockSkewLatchNeeded; i++ {
		c.Latches().checkClockSkew()
	}
	if !stepped {
		t.Fatal("chronyc makestep not attempted")
	}
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-clock-skew")); err != nil {
		t.Fatal("clock-skew latch missing")
	}
}

// --- W10-ST1: ro mounts ---

func TestParseProcMounts(t *testing.T) {
	ms := parseProcMounts([]byte(
		"/dev/sda1 /var/openebs/local/pvc-abc ext4 rw,relatime 0 0\n" +
			"/dev/sdb1 /var/openebs/local/pvc-def xfs ro,relatime 0 0\n" +
			"tmpfs /var/openebs/local/pvc-ghi tmpfs ro 0 0\n" +
			"bad line\n"))
	if len(ms) != 3 {
		t.Fatalf("parsed %d mounts want 3", len(ms))
	}
	if !ms[1].ro || ms[0].ro {
		t.Fatal("ro flag wrong")
	}
}

func TestROPVCMounts(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	proc1 := filepath.Join(cfg.ProcRoot, "1")
	if err := os.MkdirAll(proc1, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(proc1, "mounts"),
		"/dev/sda1 /var/openebs/local/pvc-abc ext4 rw,relatime 0 0\n"+
			"/dev/sdb1 /var/openebs/local/pvc-def xfs ro,relatime 0 0\n"+
			"/dev/sdc1 /opt/local-path-provisioner/pvc-ghi ext4 ro 0 0\n"+
			"/dev/sdd1 /var/lib/k0s/kubelet/pods/pod1/volumes/"+
			"kubernetes.io~secret-token ext4 ro 0 0\n"+
			"/dev/sde1 /etc/other xfs ro 0 0\n")
	ros := c.Latches().roPVCMounts()
	if len(ros) != 2 {
		t.Fatalf("roPVCMounts=%v want 2 (secret excluded, /etc excluded)", ros)
	}
	c.Latches().updateFSReadonlyEvidence()
	if _, err := os.Stat(filepath.Join(cfg.WatchdogStateDir,
		"state-fs-readonly")); err != nil {
		t.Fatal("fs-readonly latch missing")
	}
	// Fresh kmsg fs-error marker alone also latches.
	cfg2, _ := fixture(t)
	c2 := New(cfg2)
	testutil.WriteFile(t, filepath.Join(cfg2.WatchdogStateDir, kmsgFsErrorFile),
		strconv.FormatInt(time.Now().Unix(), 10)+" ext4 died\n")
	c2.Latches().updateFSReadonlyEvidence()
	if _, err := os.Stat(filepath.Join(cfg2.WatchdogStateDir,
		"state-fs-readonly")); err != nil {
		t.Fatal("fs-readonly latch missing from kmsg marker")
	}
}
