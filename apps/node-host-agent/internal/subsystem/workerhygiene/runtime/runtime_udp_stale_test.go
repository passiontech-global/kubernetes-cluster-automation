package runtime_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func setupPodNetnsProc(t *testing.T, f *wdepstest.Fixture, pid int, nsIno string) {
	t.Helper()
	var nsDir string
	if pid == 1 {
		nsDir = filepath.Join(f.ProcDir, "1", "ns")
	} else {
		nsDir = filepath.Join(f.ProcDir, string(rune('0'+pid/100))+string(rune('0'+(pid/10)%10))+string(rune('0'+pid%10)), "ns")
	}
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:["+nsIno+"]", filepath.Join(nsDir, "net")); err != nil {
		t.Fatal(err)
	}
}

func TestUDPStaleCheckMultiCycleStreakAndFailClosed(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	livePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "live-pod"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.1.10"},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "dns-svc"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
	}
	epSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "dns-svc-abc"},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.2.50"}},
		},
	}

	e := fixture(t, node, livePod, svc, epSlice)
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockIDDead [48]byte
	sockIDDead[0] = 0xAA
	var sockIDLive [48]byte
	sockIDLive[0] = 0xBB

	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			// Dead backend Pod IP in PodCIDR -> candidate.
			{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockIDDead},
			// Live EndpointSlice IP -> must NOT be killed.
			{Family: 2, SrcPort: 50001, DstIP: net.ParseIP("10.244.2.50"), DstPort: 53, ID: sockIDLive},
			// External IP outside PodCIDR -> must NOT be candidate.
			{Family: 2, SrcPort: 50002, DstIP: net.ParseIP("8.8.8.8"), DstPort: 53},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) error {
		destroyed = append(destroyed, id)
		return nil
	}

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{1, 200} },
		Pods:         []corev1.Pod{*livePod},
	}

	chk := e.H.Check(wdeps.CheckUDPStale)

	// Cycle 1: streak = 1 -> not destroyed yet.
	chk.Run(context.Background(), ce)
	if len(destroyed) != 0 {
		t.Fatalf("destroyed on cycle 1, want streak >= 2: %v", destroyed)
	}

	// Simulate API failure between cycles -> fail closed, streak stays 1 (not reset, not destroyed).
	e.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	chk.Run(context.Background(), ce)
	if len(destroyed) != 0 {
		t.Fatalf("destroyed while API list failed: %v", destroyed)
	}

	// Restore API -> next cycle reaches streak 2 and destroys only sockIDDead.
	e.CS.ReactionChain = e.CS.ReactionChain[1:]
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockIDDead {
		t.Fatalf("destroyed = %v, want [%x]", destroyed, sockIDDead)
	}
	if e.H.Series.UDPStaleDestroyed != 1 {
		t.Fatalf("UDPStaleDestroyed = %d, want 1", e.H.Series.UDPStaleDestroyed)
	}
	if !strings.Contains(e.LogLines(t), "ACTION: udp-stale-socket SOCK_DESTROY") {
		t.Fatalf("missing ACTION log:\n%s", e.LogLines(t))
	}
}

func TestUDPStaleCheckNoCandidatesZeroLazyListCalls(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node)
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	listCalls := 0
	e.CS.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		listCalls++
		return false, nil, nil
	})
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(int) ([]netlinkx.ConnectedUDPSocket, error) {
		return nil, nil
	}

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{1, 200} },
	}
	e.H.Check(wdeps.CheckUDPStale).Run(context.Background(), ce)
	if listCalls != 0 {
		t.Fatalf("expected 0 lazy list calls when no candidates, got %d", listCalls)
	}
}

func TestUDPStaleCheckCollectsAllNodePodCIDRs(t *testing.T) {
	nodeA := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.10.0/24"},
	}
	nodeB := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
		Spec:       corev1.NodeSpec{PodCIDRs: []string{"10.244.20.0/24"}},
	}
	e := fixture(t, nodeA, nodeB)
	e.H.Cfg.NodeName = "node-a"
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockRemoteDead [48]byte
	sockRemoteDead[0] = 0xCC
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		// Dead backend Pod IP that lived on node-b (10.244.20.42), outside node-a's /24.
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.20.42"), DstPort: 53, ID: sockRemoteDead},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) error {
		destroyed = append(destroyed, id)
		return nil
	}

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{1, 200} },
	}
	chk := e.H.Check(wdeps.CheckUDPStale)
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockRemoteDead {
		t.Fatalf("expected cross-node PodCIDR dead backend socket destroyed, got %v", destroyed)
	}
}
