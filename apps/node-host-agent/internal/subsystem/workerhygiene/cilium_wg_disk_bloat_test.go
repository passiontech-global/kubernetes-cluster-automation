package workerhygiene

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- W5.6 pure parsers ---

func TestParseWGAllowedIPs(t *testing.T) {
	out := "peer1key=\t10.0.0.1/32\n" +
		"peer2key=\t(none)\n" +
		"peer3key=\t10.0.0.3/32,fd00::3/128\n"
	if got := wdeps.ParseWGAllowedIPs(out); got != 2 {
		t.Fatalf("wdeps.ParseWGAllowedIPs = %d, want 2", got)
	}
	if got := wdeps.ParseWGAllowedIPs(""); got != 0 {
		t.Fatalf("empty: wdeps.ParseWGAllowedIPs = %d, want 0", got)
	}
	allWiped := "peer1key=\t(none)\npeer2key=\t(none)\n"
	if got := wdeps.ParseWGAllowedIPs(allWiped); got != 0 {
		t.Fatalf("all-wiped: wdeps.ParseWGAllowedIPs = %d, want 0", got)
	}
}

func TestParseCiliumEncryptPeers(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
		ok   bool
	}{
		{"json num-peers", `{"encryption":"wireguard","wireguard":{"num-peers":5}}`, 5, true},
		{"json nested", `{"wireguard":{"interfaces":[{"name":"cilium_wg0"}],"num-peers":3}}`, 3, true},
		{"json camel", `{"Wireguard":{"numPeers":7}}`, 7, true},
		{"json none", `{"encryption":"ipsec"}`, 0, false},
		{"text", "Wireguard\tNumPeers: 4\n", 4, true},
		{"text snake", "num_peers=9\n", 9, true},
		{"garbage", "not json no numbers", 0, false},
	}
	for _, tc := range cases {
		got, ok := cilium.ParseCiliumEncryptPeers(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: cilium.ParseCiliumEncryptPeers = (%d,%v), want (%d,%v)",
				tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// --- W5.6 check ---

func TestCheckCiliumWGPeers(t *testing.T) {
	e := fixture(t)
	// WireGuard datapath present + a live cilium-agent task.
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.Live[4242] = true
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4242", "stat"), "1 (agent) S 0 4242 4242 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000\n")
	e.MkTask(t, "aabbccdd-1111-2222-3333-444455556666", "cilium-agent", 4242)
	e.H.Cfg.Seams.Cilium.WGAllowedIPsFn = func(context.Context) (int, error) { return 0, nil }
	e.H.Cfg.Seams.Cilium.CiliumEncryptPeersFn = func(context.Context) (int, error) { return 3, nil }
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("first cycle: kills = %v, want none (streak 1/2)", e.Kills)
	}
	e.H.Cycle(context.Background())
	found := false
	for _, k := range e.Kills {
		if k.PID == 4242 && k.Sig == syscall.SIGKILL {
			found = true
		}
	}
	if !found {
		t.Fatalf("second cycle: kills = %v, want SIGKILL on 4242", e.Kills)
	}
	if !e.H.State.Exists("cilium-wg-peer-wipe") {
		t.Fatal("state-cilium-wg-peer-wipe not latched")
	}
	logData, _ := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if !strings.Contains(string(logData),
		"ACTION: killed cilium-agent container - cilium_wg0 has 0 allowed-ip peers while expected 3") {
		t.Fatalf("missing WG kill ACTION line:\n%s", logData)
	}
}

func TestCheckCiliumWGPeersGates(t *testing.T) {
	e := fixture(t)
	// No cilium_wg0 in sysfs → the check is a silent no-op.
	e.H.Cfg.Seams.Cilium.WGAllowedIPsFn = func(context.Context) (int, error) {
		return 0, errors.New("must not be called")
	}
	wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails != 0 {
		t.Fatalf("no-iface: ciliumWGFails = %d, want 0", wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails)
	}
	// apiOK=false → abort, counters kept.
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails = 1
	wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true})
	if wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails != 1 {
		t.Fatalf("api-down: ciliumWGFails = %d, want kept 1", wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails)
	}
	// Healthy peers → streak resets, latch clears.
	e.H.Cfg.Seams.Cilium.WGAllowedIPsFn = func(context.Context) (int, error) { return 5, nil }
	e.H.Cfg.Seams.Cilium.CiliumEncryptPeersFn = func(context.Context) (int, error) { return 5, nil }
	e.Live[4242] = true
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4242", "stat"), "1 (agent) S 0 4242 4242 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000\n")
	e.MkTask(t, "aabbccdd-1111-2222-3333-444455556666", "cilium-agent", 4242)
	wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Run(context.Background(), &wdeps.CycleEnv{
		APIOK: true, WorkerActive: true})
	if wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails != 0 {
		t.Fatalf("healthy: ciliumWGFails = %d, want 0", wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG).Fails)
	}
}

// --- W6.3 walk + check ---

func TestWalkBytesBoundsAndSizes(t *testing.T) {
	root := t.TempDir()
	wdepstest.WriteFile(t, filepath.Join(root, "a", "f1"), "12345")
	wdepstest.WriteFile(t, filepath.Join(root, "a", "sub", "f2"), "1234567890")
	h := &Hygiene{}
	total, truncated := h.WalkBytes(root)
	if total != 15 || truncated {
		t.Fatalf("walkBytes = (%d,%v), want (15,false)", total, truncated)
	}
}

func TestCheckDiskBloatEvicts(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hog", Namespace: "app",
			UID: types.UID("uid-1"), CreationTimestamp: metav1.Now(),
		},
	})
	e.H.Cfg.Disk.BloatPodThresholdBytes = 64
	e.DiskUsed = 0.95 // above the 0.92 critical watermark
	vol := filepath.Join(e.KubepodsDir, "uid-1", "volumes",
		"kubernetes.io~empty-dir", "data")
	big := make([]byte, 128)
	wdepstest.WriteFile(t, filepath.Join(vol, "blob"), string(big))
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hog", Namespace: "app", UID: types.UID("uid-1"),
		},
	}
	wdepstest.Check[*runtime.DiskBloatCheck](e.H, wdeps.CheckDiskBloat).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{pod}, APIOK: true, WorkerActive: true})
	if !e.H.State.Exists("disk-bloat") {
		t.Fatal("state-disk-bloat not latched")
	}
	if _, err := e.CS.CoreV1().Pods("app").Get(
		context.Background(), "hog", metav1.GetOptions{}); err == nil {
		t.Fatal("bloated pod still exists — expected eviction")
	}
	logData, _ := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if !strings.Contains(string(logData), "ACTION disk-bloat: target=") {
		t.Fatalf("missing disk-bloat ACTION line:\n%s", logData)
	}
}

func TestCheckDiskBloatSystemPodSafe(t *testing.T) {
	e := fixture(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sys-hog", Namespace: "kube-system",
			UID: types.UID("uid-sys"), CreationTimestamp: metav1.Now(),
		},
	})
	e.H.Cfg.Disk.BloatPodThresholdBytes = 64
	e.DiskUsed = 0.95
	vol := filepath.Join(e.KubepodsDir, "uid-sys", "volumes",
		"kubernetes.io~empty-dir", "data")
	wdepstest.WriteFile(t, filepath.Join(vol, "blob"), string(make([]byte, 128)))
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "sys-hog", Namespace: "kube-system", UID: types.UID("uid-sys"),
	}}
	wdepstest.Check[*runtime.DiskBloatCheck](e.H, wdeps.CheckDiskBloat).Run(context.Background(), &wdeps.CycleEnv{
		Pods: []corev1.Pod{pod}, APIOK: true, WorkerActive: true})
	if !e.H.State.Exists("disk-bloat") {
		t.Fatal("state-disk-bloat not latched")
	}
	if _, err := e.CS.CoreV1().Pods("kube-system").Get(
		context.Background(), "sys-hog", metav1.GetOptions{}); err != nil {
		t.Fatal("kube-system pod deleted — system pods are never evicted")
	}
}
