package runtime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

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
	f.Now = f.Now.Add(3 * time.Minute)
	chk.Run(ctx, ce)
	if !chk.everSeenUDP.Has("10.244.9.99:53") {
		t.Fatal("active candidate backend 10.244.9.99:53 was prematurely pruned")
	}
	if chk.everSeenUDP.Has("10.244.9.100:53") {
		t.Fatal("vanished unreferenced endpoint 10.244.9.100:53 was not pruned from everSeenUDP")
	}
}

func TestUDPStaleCombinedDumpAndBatchedDestroy(t *testing.T) {
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
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.244.9.99"}}},
	}
	if _, err := f.CS.DiscoveryV1().EndpointSlices("default").Create(ctx, sl, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for pid, ino := range map[int]string{1: "40001", 200: "40002", 201: "40003"} {
		nsDir := filepath.Join(f.ProcDir, strconv.Itoa(pid), "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("net:["+ino+"]", filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
	}

	// Keep wdeps production netlinkx function pointers so UDPStaleCheck uses the
	// combined dump and batched destroy dispatch paths.
	d.Cfg.Seams.Host.DumpConnectedUDPFn = netlinkx.DumpConnectedUDP
	d.Cfg.Seams.Host.UDPBoundPortsFn = netlinkx.UDPBoundPorts
	d.Cfg.Seams.Host.DestroyUDPSocketFn = netlinkx.DestroyUDPSocket
	d.Cfg.Wave3.UDPStaleDestroyEnabled = true
	d.Cfg.Wave3.UDPStaleMaxKills = 2

	var idA, idB, idC, idD [48]byte
	idA[0], idB[0], idC[0], idD[0] = 1, 2, 3, 4
	dstIP := net.ParseIP("10.244.9.99")

	dumpCalls := map[int]int{}
	type destroyBatchCall struct {
		pid int
		ids [][48]byte
	}
	var batchCalls []destroyBatchCall

	chk := NewUDPStale(d)
	chk.dumpCombinedFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, map[uint16]bool, error) {
		dumpCalls[pid]++
		switch pid {
		case 200:
			return []netlinkx.ConnectedUDPSocket{
				{Family: 2, SrcPort: 40001, DstIP: dstIP, DstPort: 53, ID: idA},
				{Family: 2, SrcPort: 40002, DstIP: dstIP, DstPort: 53, ID: idB},
			}, map[uint16]bool{}, nil
		case 201:
			return []netlinkx.ConnectedUDPSocket{
				{Family: 2, SrcPort: 40003, DstIP: dstIP, DstPort: 53, ID: idC},
				{Family: 2, SrcPort: 40004, DstIP: dstIP, DstPort: 53, ID: idD},
			}, map[uint16]bool{}, nil
		default:
			return nil, nil, nil
		}
	}
	chk.destroyBatchFn = func(pid int, targets []netlinkx.UDPSocketTarget) ([]netlinkx.UDPDestroyResult, error) {
		var ids [][48]byte
		res := make([]netlinkx.UDPDestroyResult, len(targets))
		for i, tgt := range targets {
			ids = append(ids, tgt.ID)
			// idA returns ENOENT (Destroyed: false), idB/idC/idD succeed.
			res[i] = netlinkx.UDPDestroyResult{Destroyed: tgt.ID[0] != 1}
		}
		batchCalls = append(batchCalls, destroyBatchCall{pid: pid, ids: ids})
		return res, nil
	}

	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				"uid-a": {
					{Name: "pause", PID: 200, Live: true},
					{Name: "pause", PID: 201, Live: true},
				},
			}, true
		},
	}

	// Cycle 1: seed everSeenUDP while 10.244.9.99:53 is live.
	chk.Run(ctx, ce)

	// Remove endpoint so 10.244.9.99:53 becomes dead.
	sl.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"10.244.9.1"}}}
	if _, err := f.CS.DiscoveryV1().EndpointSlices("default").Update(ctx, sl, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.Now = f.Now.Add(3 * time.Minute)
	dumpCalls = map[int]int{}

	// Cycle 2 & 3: build 2-cycle streak, then batched destroy triggers on cycle 3.
	chk.Run(ctx, ce)
	chk.Run(ctx, ce)

	if dumpCalls[200] != 2 || dumpCalls[201] != 2 {
		t.Fatalf("expected 1 combined dump per pid per cycle, got %v", dumpCalls)
	}
	// Batch 1 for pid 200 gets [idA, idB] (idA=false, idB=true -> killed=1).
	// Batch 2 for pid 201 gets [idC] (rem=1 -> idC=true -> killed=2, maxKills reached!).
	if len(batchCalls) != 2 {
		t.Fatalf("expected 2 batched destroy calls (1 per repPID), got %+v", batchCalls)
	}
	if batchCalls[0].pid != 200 || len(batchCalls[0].ids) != 2 ||
		batchCalls[0].ids[0] != idA || batchCalls[0].ids[1] != idB {
		t.Fatalf("unexpected batch 0: %+v", batchCalls[0])
	}
	if batchCalls[1].pid != 201 || len(batchCalls[1].ids) != 1 ||
		batchCalls[1].ids[0] != idC {
		t.Fatalf("unexpected batch 1 (maxKills=2 after 1 ENOENT in batch 0): %+v", batchCalls[1])
	}
	if d.Series.UDPStaleDestroyed != 2 {
		t.Fatalf("UDPStaleDestroyed=%d want 2", d.Series.UDPStaleDestroyed)
	}
}

func TestUDPStaleEndpointSliceListTTLCache(t *testing.T) {
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
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.244.9.99"}}},
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
	listCalls := 0
	f.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, kruntime.Object, error) {
		listCalls++
		return false, nil, nil
	})
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
	chk.Run(ctx, ce)
	if listCalls != 1 {
		t.Fatalf("cycle 1 listCalls=%d, want 1", listCalls)
	}
	// Inside TTL -> cache hit, 0 additional EndpointSlice List calls.
	f.Now = f.Now.Add(time.Minute)
	chk.Run(ctx, ce)
	if listCalls != 1 {
		t.Fatalf("within TTL listCalls=%d, want 1", listCalls)
	}
	// Past TTL -> refreshes.
	f.Now = f.Now.Add(2 * time.Minute)
	chk.Run(ctx, ce)
	if listCalls != 2 {
		t.Fatalf("past TTL listCalls=%d, want 2", listCalls)
	}
}
