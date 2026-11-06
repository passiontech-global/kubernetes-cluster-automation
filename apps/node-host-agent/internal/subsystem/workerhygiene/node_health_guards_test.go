package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// mkStatProc writes a /proc entry with a custom comm + state and an
// optional wchan — mkProc only ever writes comm "fakeproc", but the
// d-state check classifies by comm (runc/jbd2/...).
func (e *env) mkStatProc(t *testing.T, pid int, comm, state, wchan string) {
	t.Helper()
	writeFile(t, filepath.Join(e.proc, strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (%s) %s 1 0 0", pid, comm, state))
	e.live[pid] = state != "Z"
	if wchan != "" {
		writeFile(t, filepath.Join(e.proc, strconv.Itoa(pid), "wchan"), wchan+"\n")
	}
}

func pidsOf(pids ...int) func() []int {
	return func() []int { return pids }
}

// --- W7-H1: d-state-storm ---

func TestDStateRuntimeComm(t *testing.T) {
	for comm, want := range map[string]bool{
		"runc": true, "containerd": true, "containerd-shim": true,
		"containerd-shim-runc-v2": true, "k0s": true, "k0sworker": true,
		"kubelet": true, "btrfs-worker": true, "jbd2/vda1-8": true,
		"postgres": false, "nginx": false, "bash": false, "pause": false,
	} {
		if got := guards.DstateRuntimeComm(comm); got != want {
			t.Errorf("guards.DstateRuntimeComm(%q) = %v, want %v", comm, got, want)
		}
	}
}

func TestCheckDStateStormLatch(t *testing.T) {
	e := fixture(t)
	// 5 generic D-state procs — the total-count trigger.
	pids := []int{7001, 7002, 7003, 7004, 7005}
	for i, pid := range pids {
		e.mkStatProc(t, pid, "postgres", "D", "blk_mq_get_tag")
		_ = i
	}
	e.h.checkDStateTasks(pidsOf(pids...), true)
	if e.h.State.Exists("d-state-storm") {
		t.Fatal("latch fired before ConsecNeeded cycles")
	}
	e.h.checkDStateTasks(pidsOf(pids...), true)
	if !e.h.State.Exists("d-state-storm") {
		t.Fatal("state-d-state-storm not latched after ConsecNeeded cycles")
	}
	log := logLines(t, e)
	if !strings.Contains(log, "ACTION d-state-storm: count=5 runtime=0 wchan=postgres=blk_mq_get_tag") {
		t.Fatalf("missing ACTION d-state-storm line:\n%s", log)
	}
	// Recovery clears the latch.
	for _, pid := range pids {
		e.mkStatProc(t, pid, "postgres", "S", "")
	}
	e.h.checkDStateTasks(pidsOf(pids...), true)
	if e.h.State.Exists("d-state-storm") {
		t.Fatal("latch not cleared after D procs recovered")
	}
}

func TestCheckDStateRuntimeMinTrigger(t *testing.T) {
	e := fixture(t)
	// Only 2 D procs but both runtime-critical (runc + jbd2) — the
	// runtime >= 2 branch fires below the total threshold of 5.
	pids := []int{7101, 7102}
	e.mkStatProc(t, 7101, "runc", "D", "umount_tree")
	e.mkStatProc(t, 7102, "jbd2/vda1-8", "D", "wait_transaction_locked")
	e.h.checkDStateTasks(pidsOf(pids...), true)
	e.h.checkDStateTasks(pidsOf(pids...), true)
	if !e.h.State.Exists("d-state-storm") {
		t.Fatal("runtime-critical D-state storm not latched")
	}
	if !strings.Contains(logLines(t, e), "ACTION d-state-storm: count=2 runtime=2") {
		t.Fatalf("missing runtime=2 ACTION line:\n%s", logLines(t, e))
	}
}

// --- W7-H2: systemd-scopes ---

func TestCheckSystemdScopesResetFailed(t *testing.T) {
	e := fixture(t)
	e.sdReply["list-units --type=scope --state=failed"] =
		"cri-containerd-aa11.scope loaded failed failed abandoned\n" +
			"cri-containerd-bb22.scope loaded failed failed abandoned\n"
	e.sdReply["reset-failed cri-containerd-*.scope"] = ""
	e.h.checkSystemdScopes(context.Background(), true)
	if !e.sdRan("reset-failed cri-containerd-*.scope") {
		t.Fatal("systemctl reset-failed not invoked for failed scopes")
	}
	if !strings.Contains(logLines(t, e), "ACTION: systemd-scopes reset-failed count=2") {
		t.Fatalf("missing reset-failed ACTION line:\n%s", logLines(t, e))
	}
	// Inside the 30m scan interval — no further exec.
	before := len(e.sdcmds)
	e.h.checkSystemdScopes(context.Background(), true)
	if len(e.sdcmds) != before {
		t.Fatal("scan re-ran inside SystemdScopeScanInterval")
	}
	// Past the interval the sweep runs again.
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkSystemdScopes(context.Background(), true)
	if len(e.sdcmds) != before+2 { // list + reset again
		t.Fatalf("scan did not re-run past interval: sdcmds=%d want %d", len(e.sdcmds), before+2)
	}
}

func TestCheckSystemdScopesClean(t *testing.T) {
	e := fixture(t)
	e.sdReply["list-units --type=scope --state=failed"] = ""
	e.h.checkSystemdScopes(context.Background(), true)
	if e.sdRan("reset-failed cri-containerd-") {
		t.Fatal("reset-failed ran with zero failed scopes")
	}
}

// --- W7-H3: envoy xDS NACK + node-local-dns LRP ---

func TestParseEnvoyXDSRejected(t *testing.T) {
	body := []byte(
		"cluster_manager.cds.update_rejected: 3\n" +
			"listener_manager.lds.update_rejected: 1\n" +
			"http.ingress.rds.route_config.update_rejected: 2\n" +
			"cluster_manager.cds.update_success: 9\n" +
			"server.watchdog_miss: 4\n")
	if got := cilium.ParseEnvoyXDSRejected(body); got != 6 {
		t.Fatalf("cilium.ParseEnvoyXDSRejected = %d, want 6", got)
	}
	if got := cilium.ParseEnvoyXDSRejected([]byte("cds.update_rejected: notanumber\n")); got != 0 {
		t.Fatalf("malformed value counted: %d", got)
	}
}

func TestCheckCiliumEnvoyXDSReject(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 4242, "S", "", "")
	e.mkTask(t, uidA, "cilium-envoy", 4242)
	stats := []string{
		"cluster_manager.cds.update_rejected: 5\n",
		"cluster_manager.cds.update_rejected: 6\n",
		"cluster_manager.cds.update_rejected: 9\n",
	}
	call := 0
	e.h.Cfg.Seams.HTTPGetBody = func(context.Context, string, time.Duration) ([]byte, error) {
		defer func() { call++ }()
		if call < len(stats) {
			return []byte(stats[call]), nil
		}
		return []byte(stats[len(stats)-1]), nil
	}
	e.h.checkCiliumEnvoy(context.Background(), true) // baseline read — no delta
	e.h.checkCiliumEnvoy(context.Background(), true) // delta +1 → streak 1
	if e.h.State.Exists("cilium-envoy-xds-reject") {
		t.Fatal("xds latch fired before ConsecNeeded deltas")
	}
	e.h.checkCiliumEnvoy(context.Background(), true) // delta +1 → streak 2
	if !e.h.State.Exists("cilium-envoy-xds-reject") {
		t.Fatal("state-cilium-envoy-xds-reject not latched")
	}
	found := false
	for _, k := range e.kills {
		if k.pid == 4242 && k.sig == syscall.SIGKILL {
			found = true
		}
	}
	if !found {
		t.Fatalf("envoy task not killed on xDS reject: kills=%v", e.kills)
	}
}

func TestCheckCiliumLRPDNS(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-local-dns-a1b2c", Namespace: "kube-system",
			UID: types.UID(uidA), CreationTimestamp: metav1.Now(),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	})
	if err := os.MkdirAll(filepath.Join(e.sysnet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The LRP gate requires a live cilium-agent task.
	e.mkProc(t, 4343, "S", "", "")
	e.mkTask(t, uidB, "cilium-agent", 4343)
	pod, _ := e.cs.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-a1b2c", metav1.GetOptions{})
	e.h.Cfg.Seams.DNSProbe = func(string, string, time.Duration) bool { return false }
	e.h.checkCiliumLRPDNS(context.Background(), []corev1.Pod{*pod}, true, true)
	e.h.checkCiliumLRPDNS(context.Background(), []corev1.Pod{*pod}, true, true)
	if _, err := e.cs.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-a1b2c", metav1.GetOptions{}); err == nil {
		t.Fatal("node-local-dns pod not deleted after confirmed :53 probe failures")
	}
	if !strings.Contains(logLines(t, e), "ACTION: cilium-lrp-dns deleted pod kube-system/node-local-dns-a1b2c") {
		t.Fatalf("missing LRP delete ACTION line:\n%s", logLines(t, e))
	}
}

func TestCheckCiliumLRPDNSGates(t *testing.T) {
	e := fixture(t)
	// No cilium_host → dormant (calico node) — the probe must not run.
	e.h.Cfg.Seams.DNSProbe = func(string, string, time.Duration) bool {
		t.Fatal("dnsProbe ran without cilium datapath")
		return false
	}
	e.h.checkCiliumLRPDNS(context.Background(), nil, true, true)
	if e.h.ciliumLRP.Fails != 0 {
		t.Fatalf("nldFails = %d, want 0 on non-cilium node", e.h.ciliumLRP.Fails)
	}

	// cilium_host present but no cilium-agent task → gated (agent
	// down — checkCilium owns that verdict), probe must not run.
	if err := os.MkdirAll(filepath.Join(e.sysnet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.h.checkCiliumLRPDNS(context.Background(), nil, true, true)
	if e.h.ciliumLRP.Fails != 0 {
		t.Fatalf("nldFails = %d, want 0 with cilium-agent absent", e.h.ciliumLRP.Fails)
	}
}

// --- W7-H4: spegel-mirror ---

func TestCheckSpegelMirror(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spegel-x9y8z", Namespace: "spegel",
			UID: types.UID(uidB), CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
	})
	pod, _ := e.cs.CoreV1().Pods("spegel").Get(
		context.Background(), "spegel-x9y8z", metav1.GetOptions{})
	e.h.checkSpegelMirror(context.Background(), []corev1.Pod{*pod}, true, true)
	if e.h.State.Exists("spegel-mirror-degraded") {
		t.Fatal("spegel latch fired before ConsecNeeded cycles")
	}
	e.h.checkSpegelMirror(context.Background(), []corev1.Pod{*pod}, true, true)
	if !e.h.State.Exists("spegel-mirror-degraded") {
		t.Fatal("state-spegel-mirror-degraded not latched")
	}
	if _, err := e.cs.CoreV1().Pods("spegel").Get(
		context.Background(), "spegel-x9y8z", metav1.GetOptions{}); err == nil {
		t.Fatal("NotReady spegel pod not deleted")
	}
}

func TestCheckSpegelMirrorTooYoung(t *testing.T) {
	e := fixture(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spegel-new00", Namespace: "kube-system",
			UID: types.UID(uidB), CreationTimestamp: metav1.NewTime(e.now.Add(-time.Minute)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
	}
	e.h.checkSpegelMirror(context.Background(), []corev1.Pod{*pod}, true, true)
	e.h.checkSpegelMirror(context.Background(), []corev1.Pod{*pod}, true, true)
	if e.h.spegel.Fails != 0 || e.h.State.Exists("spegel-mirror-degraded") {
		t.Fatal("3m-old spegel pod counted toward the streak — startup grace violated")
	}
}

// --- W7-H7: calico-hygiene ---

func TestCheckCalicoHygieneVethLeak(t *testing.T) {
	e := fixture(t)
	for i := 0; i < 55; i++ {
		if err := os.MkdirAll(filepath.Join(
			e.sysnet, fmt.Sprintf("cali%02x", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.h.checkCalicoHygiene(context.Background(), nil, true, true)
	if e.h.State.Exists("calico-veth-leak") {
		t.Fatal("veth-leak latch fired before ConsecNeeded cycles")
	}
	e.h.checkCalicoHygiene(context.Background(), nil, true, true)
	if !e.h.State.Exists("calico-veth-leak") {
		t.Fatal("state-calico-veth-leak not latched (55 cali vs 0 pods)")
	}
}

func TestCheckCalicoHygieneFelixDown(t *testing.T) {
	e := fixture(t)
	for i := 0; i < 3; i++ {
		if err := os.MkdirAll(filepath.Join(
			e.sysnet, fmt.Sprintf("cali%02x", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.probes[wdeps.DefaultCalicoFelixReadyURL] = os.ErrNotExist
	pods := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-node-q9w8e", Namespace: "kube-system",
			UID: types.UID(uidC), CreationTimestamp: metav1.Now()},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}}
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	e.h.checkCalicoHygiene(context.Background(), pods, true, true)
	if !e.h.State.Exists("calico-felix-down") {
		t.Fatal("state-calico-felix-down not latched on failing readiness")
	}
}

func TestCheckCalicoHygieneCiliumGate(t *testing.T) {
	e := fixture(t)
	// cilium_host wins over cali* ifaces — a cilium node never runs
	// the calico verdicts.
	if err := os.MkdirAll(filepath.Join(e.sysnet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.sysnet, "cali00"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.h.calico.VethFails = 1
	writeFile(t, filepath.Join(e.state, "state-calico-veth-leak"), "1\n")
	e.h.checkCalicoHygiene(context.Background(), nil, true, true)
	if e.h.calico.VethFails != 0 || e.h.State.Exists("calico-veth-leak") {
		t.Fatal("calico checks ran/cleared nothing on a cilium node")
	}
}
