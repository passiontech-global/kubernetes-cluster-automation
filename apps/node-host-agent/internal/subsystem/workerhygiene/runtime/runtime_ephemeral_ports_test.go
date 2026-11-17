// runtime_ephemeral_ports_test.go — Wave 1.3 regression tests:
// per-netns threshold evaluation (no cross-pod summation) and
// CLOSE_WAIT minimum eviction floor.
package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestEphemeralPortsPerNetnsNotSummedAcrossPods(t *testing.T) {
	e := fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "net", "ipv4", "ip_local_port_range"),
		"32768 60999\n")
	var pids []int
	for i := 1; i <= 20; i++ {
		pid := 100 + i
		pids = append(pids, pid)
		nsDir := filepath.Join(e.ProcDir, strconv.Itoa(pid), "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("net:["+strconv.Itoa(1000+i)+"]", filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cfg.Seams.Host.TCPTablesFn = func(pid int) (netlinkx.TCPCensus, error) {
		return netlinkx.TCPCensus{States: map[uint8]int{
			1: 500, // ESTABLISHED
			8: 500, // CLOSE_WAIT — 20 * 500 = 10000 across pods, but 500 per netns
		}}, nil
	}
	for range 3 {
		e.H.Check(wdeps.CheckEphemeralPorts).Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true, APIOK: true, PidsOnce: func() []int { return pids },
		})
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-"+latchdefs.LatchEphemeralPortPressure)); err == nil {
		t.Fatal("per-netns healthy sockets were summed across pods to falsely arm latch")
	}
}

func TestEphemeralPortsCloseWaitEvictRespectsFloor(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Wave2.PortEvictRunawayPod = true
	e.H.Cfg.Wave2.PortCloseWaitMax = 1 // low warn threshold, but eviction requires minCloseWaitFloor
	e.H.Cfg.Wave2.PortLeakMinPct = 50
	e.H.Cfg.Wave2.PortLeakWindowSec = 1
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "net", "ipv4", "ip_local_port_range"),
		"32768 60999\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "1", "net", "tcp"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0100007F:1F90 0100007F:C350 08 00000000:00000000 00:00000000 00000000     0        0 99001 1 00000000 0\n")
	nsDir := filepath.Join(e.ProcDir, "1", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("net:[1001]", filepath.Join(nsDir, "net"))

	uid := "123e4567-e89b-12d3-a456-426614174099"
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "200", "cgroup"),
		"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
			"123e4567_e89b_12d3_a456_426614174099.slice/cri-containerd-abc.scope\n")
	fdDir := filepath.Join(e.ProcDir, "200", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("socket:[99001]", filepath.Join(fdDir, "0"))

	isCtrl := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "one-socket", UID: types.UID(uid),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-1", Controller: &isCtrl,
		}},
	}}
	if _, err := e.CS.CoreV1().Pods("app").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Seams.Host.TCPTablesFn = func(pid int) (netlinkx.TCPCensus, error) {
		return netlinkx.TCPCensus{States: map[uint8]int{8: 1}}, nil
	}
	for range 3 {
		e.H.Check(wdeps.CheckEphemeralPorts).Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true, APIOK: true,
			Pods:     []corev1.Pod{*pod},
			PidsOnce: func() []int { return []int{1, 200} },
		})
		e.Now = e.Now.Add(5 * time.Second)
	}
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("healthy pod with 1 CLOSE_WAIT evicted (floor ignored): %d deletes", n)
	}
}
