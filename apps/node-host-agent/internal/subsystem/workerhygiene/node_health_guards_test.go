package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

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
		e.MkStatProc(t, pid, "postgres", "D", "blk_mq_get_tag")
		_ = i
	}
	wdepstest.Check[*guards.DstateCheck](e.H, wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: wdepstest.PidsOf(pids...), WorkerActive: true})
	if e.H.State.Exists("d-state-storm") {
		t.Fatal("latch fired before ConsecNeeded cycles")
	}
	wdepstest.Check[*guards.DstateCheck](e.H, wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: wdepstest.PidsOf(pids...), WorkerActive: true})
	if !e.H.State.Exists("d-state-storm") {
		t.Fatal("state-d-state-storm not latched after ConsecNeeded cycles")
	}
	log := e.LogLines(t)
	if !strings.Contains(log, "ACTION d-state-storm: count=5 runtime=0 wchan=postgres=blk_mq_get_tag") {
		t.Fatalf("missing ACTION d-state-storm line:\n%s", log)
	}
	// Recovery clears the latch.
	for _, pid := range pids {
		e.MkStatProc(t, pid, "postgres", "S", "")
	}
	wdepstest.Check[*guards.DstateCheck](e.H, wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: wdepstest.PidsOf(pids...), WorkerActive: true})
	if e.H.State.Exists("d-state-storm") {
		t.Fatal("latch not cleared after D procs recovered")
	}
}

func TestCheckDStateRuntimeMinTrigger(t *testing.T) {
	e := fixture(t)
	// Only 2 D procs but both runtime-critical (runc + jbd2) — the
	// runtime >= 2 branch fires below the total threshold of 5.
	pids := []int{7101, 7102}
	e.MkStatProc(t, 7101, "runc", "D", "umount_tree")
	e.MkStatProc(t, 7102, "jbd2/vda1-8", "D", "wait_transaction_locked")
	wdepstest.Check[*guards.DstateCheck](e.H, wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: wdepstest.PidsOf(pids...), WorkerActive: true})
	wdepstest.Check[*guards.DstateCheck](e.H, wdeps.CheckDState).Run(context.Background(), &wdeps.CycleEnv{
		PidsOnce: wdepstest.PidsOf(pids...), WorkerActive: true})
	if !e.H.State.Exists("d-state-storm") {
		t.Fatal("runtime-critical D-state storm not latched")
	}
	if !strings.Contains(e.LogLines(t), "ACTION d-state-storm: count=2 runtime=2") {
		t.Fatalf("missing runtime=2 ACTION line:\n%s", e.LogLines(t))
	}
}

// --- W7-H2: systemd-scopes ---

func TestCheckSystemdScopesResetFailed(t *testing.T) {
	e := fixture(t)
	e.SDReply["list-units --type=scope --state=failed"] =
		"cri-containerd-aa11.scope loaded failed failed abandoned\n" +
			"cri-containerd-bb22.scope loaded failed failed abandoned\n"
	e.SDReply["reset-failed cri-containerd-*.scope"] = ""
	wdepstest.Check[*guards.ScopesCheck](e.H, wdeps.CheckSysScopes).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if !e.SDRan("reset-failed cri-containerd-*.scope") {
		t.Fatal("systemctl reset-failed not invoked for failed scopes")
	}
	if !strings.Contains(e.LogLines(t), "ACTION: systemd-scopes reset-failed count=2") {
		t.Fatalf("missing reset-failed ACTION line:\n%s", e.LogLines(t))
	}
	// Inside the 30m scan interval — no further exec.
	before := len(e.SDCmds)
	wdepstest.Check[*guards.ScopesCheck](e.H, wdeps.CheckSysScopes).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if len(e.SDCmds) != before {
		t.Fatal("scan re-ran inside SystemdScopeScanInterval")
	}
	// Past the interval the sweep runs again.
	e.Now = e.Now.Add(31 * time.Minute)
	wdepstest.Check[*guards.ScopesCheck](e.H, wdeps.CheckSysScopes).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if len(e.SDCmds) != before+2 { // list + reset again
		t.Fatalf("scan did not re-run past interval: sdcmds=%d want %d", len(e.SDCmds), before+2)
	}
}

func TestCheckSystemdScopesClean(t *testing.T) {
	e := fixture(t)
	e.SDReply["list-units --type=scope --state=failed"] = ""
	wdepstest.Check[*guards.ScopesCheck](e.H, wdeps.CheckSysScopes).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if e.SDRan("reset-failed cri-containerd-") {
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
	e.MkProc(t, 4242, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "cilium-envoy", 4242)
	stats := []string{
		"cluster_manager.cds.update_rejected: 5\n",
		"cluster_manager.cds.update_rejected: 6\n",
		"cluster_manager.cds.update_rejected: 9\n",
	}
	call := 0
	e.H.Cfg.Seams.Probe.HTTPGetBody = func(context.Context, string, time.Duration) ([]byte, error) {
		defer func() { call++ }()
		if call < len(stats) {
			return []byte(stats[call]), nil
		}
		return []byte(stats[len(stats)-1]), nil
	}
	wdepstest.Check[*cilium.CiliumEnvoyCheck](e.H, wdeps.CheckCiliumEnvoy).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true}) // baseline read — no delta
	wdepstest.Check[*cilium.CiliumEnvoyCheck](e.H, wdeps.CheckCiliumEnvoy).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true}) // delta +1 → streak 1
	if e.H.State.Exists("cilium-envoy-xds-reject") {
		t.Fatal("xds latch fired before ConsecNeeded deltas")
	}
	wdepstest.Check[*cilium.CiliumEnvoyCheck](e.H, wdeps.CheckCiliumEnvoy).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true}) // delta +1 → streak 2
	if !e.H.State.Exists("cilium-envoy-xds-reject") {
		t.Fatal("state-cilium-envoy-xds-reject not latched")
	}
	found := false
	for _, k := range e.Kills {
		if k.PID == 4242 && k.Sig == syscall.SIGKILL {
			found = true
		}
	}
	if !found {
		t.Fatalf("envoy task not killed on xDS reject: kills=%v", e.Kills)
	}
}

func TestCheckCiliumLRPDNS(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-local-dns-a1b2c", Namespace: "kube-system",
			UID: types.UID(wdepstest.UIDA), CreationTimestamp: metav1.Now(),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	})
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The LRP gate requires a live cilium-agent task.
	e.MkProc(t, 4343, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	pod, _ := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-a1b2c", metav1.GetOptions{})
	e.H.Cfg.Seams.Probe.DNSProbe = func(string, string, time.Duration) bool { return false }
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-a1b2c", metav1.GetOptions{}); err == nil {
		t.Fatal("node-local-dns pod not deleted after confirmed :53 probe failures")
	}
	if !strings.Contains(e.LogLines(t), "ACTION: cilium-lrp-dns deleted pod kube-system/node-local-dns-a1b2c") {
		t.Fatalf("missing LRP delete ACTION line:\n%s", e.LogLines(t))
	}
}

func TestCheckCiliumLRPDNSGates(t *testing.T) {
	e := fixture(t)
	// No cilium_host → dormant (calico node) — the probe must not run.
	e.H.Cfg.Seams.Probe.DNSProbe = func(string, string, time.Duration) bool {
		t.Fatal("dnsProbe ran without cilium datapath")
		return false
	}
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Fails != 0 {
		t.Fatalf("nldFails = %d, want 0 on non-cilium node", wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Fails)
	}

	// cilium_host present but no cilium-agent task → gated (agent
	// down — checkCilium owns that verdict), probe must not run.
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Fails != 0 {
		t.Fatalf("nldFails = %d, want 0 with cilium-agent absent", wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Fails)
	}
}

// TCP-failing-only :53 datapath is still a wedge — UDP alone must
// not mark the listener healthy.
func TestCheckCiliumLRPDNSTCPHalfWedge(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-local-dns-b2c3d", Namespace: "kube-system",
			UID: types.UID(wdepstest.UIDA), CreationTimestamp: metav1.Now(),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	})
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 4343, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	pod, _ := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-b2c3d", metav1.GetOptions{})
	// UDP answers, TCP silent — a one-sided wedge still counts.
	e.H.Cfg.Seams.Probe.DNSProbe = func(string, string, time.Duration) bool { return true }
	e.DNSTCP = false
	e.SvcErr = errors.New("map unreadable") // desync probe inconclusive
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-b2c3d", metav1.GetOptions{}); err == nil {
		t.Fatal("nld pod not deleted on TCP-only :53 wedge")
	}
}

// --- local BPF service-map desync ---

// TestCheckCiliumLRPServiceDesync: apiserver-side kube-dns has Ready
// endpoints but the local BPF map has 0 backends → restart
// cilium-agent through last-cilium-restart after ConsecNeeded
// cycles; the nld pod delete is suppressed meanwhile.
func TestCheckCiliumLRPServiceDesync(t *testing.T) {
	e := fixture(t, &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: "10.244.1.7"}},
		}},
	})
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 4343, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	e.SvcBackends = map[string]int{
		"kube-system/kube-dns": 0, // desynced — ready endpoints, no backends
		"default/kubernetes":   1,
	}
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	killed := false
	for _, k := range e.Kills {
		if k.PID == 4343 && k.Sig == syscall.SIGKILL {
			killed = true
		}
	}
	if killed {
		t.Fatal("agent killed before ConsecNeeded desync cycles")
	}
	wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	killed = false
	for _, k := range e.Kills {
		if k.PID == 4343 && k.Sig == syscall.SIGKILL {
			killed = true
		}
	}
	if !killed {
		t.Fatal("cilium-agent not killed on confirmed BPF service-map desync")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-cilium-restart")); err != nil {
		t.Fatal("last-cilium-restart budget not spent")
	}
}

// TestCheckCiliumLRPDesyncSuppressesPodDelete: while the map is
// desynced the :53 datapath verdict is explained by the agent —
// the nld pod must not be deleted for it.
func TestCheckCiliumLRPDesyncSuppressesPodDelete(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-local-dns-c4d5e", Namespace: "kube-system",
			UID: types.UID(wdepstest.UIDA), CreationTimestamp: metav1.Now(),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}, &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: "10.244.1.7"}},
		}},
	})
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 4343, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4343)
	e.SvcBackends = map[string]int{"kube-system/kube-dns": 0, "default/kubernetes": 1}
	// :53 is dead on both transports — the desync explains it.
	e.H.Cfg.Seams.Probe.DNSProbe = func(string, string, time.Duration) bool { return false }
	e.DNSTCP = false
	for i := 0; i < 3; i++ {
		wdepstest.Check[*cilium.CiliumLRPCheck](e.H, wdeps.CheckCiliumLRP).Run(context.Background(), &wdeps.CycleEnv{
			APIOK: true, WorkerActive: true})
	}
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "node-local-dns-c4d5e", metav1.GetOptions{}); err != nil {
		t.Fatal("nld pod deleted while the desync explained the :53 failures")
	}
}

func TestParseCiliumServiceBackends(t *testing.T) {
	body := []byte(`[
		{"spec":{"id":1,"name":"kube-dns","namespace":"kube-system",
			"frontend-address":{"ip":"10.96.0.10","port":53},
			"backend-addresses":[{"ip":"10.244.1.7"},{"ip":"10.244.2.3"}]}},
		{"spec":{"id":2,"name":"kube-dns","namespace":"kube-system",
			"frontend-address":{"ip":"10.96.0.10","port":53},
			"backend-addresses":[{"ip":"10.244.1.7"}]}},
		{"spec":{"id":3,"flags":{"name":"kubernetes","namespace":"default"},
			"backend-addresses":[]}},
		{"spec":{"id":4,"frontend-address":{"ip":"0.0.0.0","port":0},
			"backend-addresses":[{"ip":"x"}]}}
	]`)
	got, err := wdeps.ParseCiliumServiceBackends(body)
	if err != nil {
		t.Fatal(err)
	}
	if got["kube-system/kube-dns"] != 3 {
		t.Fatalf("kube-dns backends=%d want 3 (sum across transports)",
			got["kube-system/kube-dns"])
	}
	if got["default/kubernetes"] != 0 {
		t.Fatalf("kubernetes backends=%d want 0", got["default/kubernetes"])
	}
	if _, ok := got["/"]; ok {
		t.Fatal("nameless entry mapped")
	}
}

// --- W7-H4: spegel-mirror ---

func TestCheckSpegelMirror(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spegel-x9y8z", Namespace: "spegel",
			UID: types.UID(wdepstest.UIDB), CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
	})
	pod, _ := e.CS.CoreV1().Pods("spegel").Get(
		context.Background(), "spegel-x9y8z", metav1.GetOptions{})
	wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if e.H.State.Exists("spegel-mirror-degraded") {
		t.Fatal("spegel latch fired before ConsecNeeded cycles")
	}
	wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if !e.H.State.Exists("spegel-mirror-degraded") {
		t.Fatal("state-spegel-mirror-degraded not latched")
	}
	if _, err := e.CS.CoreV1().Pods("spegel").Get(
		context.Background(), "spegel-x9y8z", metav1.GetOptions{}); err == nil {
		t.Fatal("NotReady spegel pod not deleted")
	}
}

func TestCheckSpegelMirrorTooYoung(t *testing.T) {
	e := fixture(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "spegel-new00", Namespace: "kube-system",
			UID: types.UID(wdepstest.UIDB), CreationTimestamp: metav1.NewTime(e.Now.Add(-time.Minute)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
	}
	wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{*pod}, APIOK: true, WorkerActive: true})
	if wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel).Fails != 0 || e.H.State.Exists("spegel-mirror-degraded") {
		t.Fatal("3m-old spegel pod counted toward the streak — startup grace violated")
	}
}

// --- W7-H7: calico-hygiene ---

func TestCheckCalicoHygieneVethLeak(t *testing.T) {
	e := fixture(t)
	for i := 0; i < 55; i++ {
		if err := os.MkdirAll(filepath.Join(
			e.SysNet, fmt.Sprintf("cali%02x", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if e.H.State.Exists("calico-veth-leak") {
		t.Fatal("veth-leak latch fired before ConsecNeeded cycles")
	}
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if !e.H.State.Exists("calico-veth-leak") {
		t.Fatal("state-calico-veth-leak not latched (55 cali vs 0 pods)")
	}
}

func TestCheckCalicoHygieneFelixDown(t *testing.T) {
	e := fixture(t)
	for i := 0; i < 3; i++ {
		if err := os.MkdirAll(filepath.Join(
			e.SysNet, fmt.Sprintf("cali%02x", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.Probes[wdeps.DefaultCalicoFelixReadyURL] = os.ErrNotExist
	pods := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-node-q9w8e", Namespace: "kube-system",
			UID: types.UID(wdepstest.UIDC), CreationTimestamp: metav1.Now()},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}}
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).Run(context.Background(), &wdeps.CycleEnv{
		Pods: pods, APIOK: true, WorkerActive: true})
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).Run(context.Background(), &wdeps.CycleEnv{
		Pods: pods, APIOK: true, WorkerActive: true})
	if !e.H.State.Exists("calico-felix-down") {
		t.Fatal("state-calico-felix-down not latched on failing readiness")
	}
}

func TestCheckCalicoHygieneCiliumGate(t *testing.T) {
	e := fixture(t)
	// cilium_host wins over cali* ifaces — a cilium node never runs
	// the calico verdicts.
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cali00"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).VethFails = 1
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-calico-veth-leak"), "1\n")
	wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico).VethFails != 0 || e.H.State.Exists("calico-veth-leak") {
		t.Fatal("calico checks ran/cleared nothing on a cilium node")
	}
}
