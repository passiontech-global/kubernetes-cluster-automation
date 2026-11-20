package runtime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

func TestUDPStaleEverSeenPrunedAfterVanished(t *testing.T) {
	d, f := rtDeps(t)
	ctx := context.Background()
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	if _, err := f.CS.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	proto := corev1.ProtocolUDP
	port := int32(53)
	sl := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: "dns"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.9.99"}},
			{Addresses: []string{"10.244.9.100"}},
		},
	}
	if _, err := f.CS.DiscoveryV1().EndpointSlices("default").Create(ctx, sl, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for pid, ino := range map[int]string{1: "40001", 200: "40002"} {
		nsDir := filepath.Join(f.ProcDir, strconv.Itoa(pid), "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("net:["+ino+"]", filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
	}

	var sock [48]byte
	sock[0] = 0x55
	d.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 40002, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sock},
		}, nil
	}

	chk := NewUDPStale(d)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				"uid-a": {{Name: "pause", PID: 200, Live: true}},
			}, true
		},
	}
	// Cycle 1: both 9.99:53 and 9.100:53 enter everSeenUDP.
	chk.Run(ctx, ce)
	if !chk.everSeenUDP.Has("10.244.9.99:53") || !chk.everSeenUDP.Has("10.244.9.100:53") {
		t.Fatal("expected both endpoints in everSeenUDP after cycle 1")
	}

	// Both endpoints leave the EndpointSlice; only 9.99:53 still has a candidate socket.
	sl.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"10.244.9.1"}}}
	if _, err := f.CS.DiscoveryV1().EndpointSlices("default").Update(ctx, sl, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	chk.Run(ctx, ce)
	if !chk.everSeenUDP.Has("10.244.9.99:53") {
		t.Fatal("active candidate backend 10.244.9.99:53 was prematurely pruned")
	}
	if chk.everSeenUDP.Has("10.244.9.100:53") {
		t.Fatal("vanished unreferenced endpoint 10.244.9.100:53 was not pruned from everSeenUDP")
	}
}
