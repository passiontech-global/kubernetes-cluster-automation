package runtime_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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

// udpCycleEnv feeds the check ONLY a K8s pause task (Wave-5: no more
// host-wide PidsOnce scan). pid is the pause task PID.
func udpCycleEnv(pid int, pods ...corev1.Pod) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         pods,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				wdepstest.UIDA: {{Name: "pause", PID: pid, Live: true}},
			}, true
		},
	}
}

// udpEndpointSlice builds an EndpointSlice that manages one UDP port
// and lists the currently-active backend IPs for it. A socket is only
// a dead-Service backend when its DstPort is managed by at least one
// such slice.
func udpEndpointSlice(name string, port int32, ips ...string) *discoveryv1.EndpointSlice {
	proto := corev1.ProtocolUDP
	eps := make([]discoveryv1.Endpoint, 0, len(ips))
	for _, ip := range ips {
		eps = append(eps, discoveryv1.Endpoint{Addresses: []string{ip}})
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: name},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}},
		Endpoints:   eps,
	}
}

// seedDeadUDPBackend runs one cycle while ip:port is a live UDP
// EndpointSlice endpoint — the check's RAM ledger learns the exact
// ip:port — then strips the endpoint out so the same ip:port reads as
// a vanished Service backend. Without this seed a socket to an
// unobserved ip:port is direct Pod-to-Pod UDP and never a kill
// candidate, even when its port is managed by a Service.
func seedDeadUDPBackend(t *testing.T, e *env, ce *wdeps.CycleEnv, name, ip string) {
	t.Helper()
	sl, err := e.CS.DiscoveryV1().EndpointSlices("default").Get(
		context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.H.Check(wdeps.CheckUDPStale).Run(context.Background(), ce)
	if err := e.CS.DiscoveryV1().EndpointSlices("default").Delete(
		context.Background(), sl.Name, metav1.DeleteOptions{}); err != nil {
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
	epSlice := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
	deadSeed := udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99")

	e := fixture(t, node, livePod, epSlice, deadSeed)
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
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	ce := udpCycleEnv(200, *livePod)
	chk := e.H.Check(wdeps.CheckUDPStale)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")

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
	// The Node snapshot LIST is expected; the lazy EndpointSlices
	// list is the one that must not fire when there are no sockets.
	e.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		listCalls++
		return false, nil, nil
	})
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(int) ([]netlinkx.ConnectedUDPSocket, error) {
		return nil, nil
	}

	e.H.Check(wdeps.CheckUDPStale).Run(context.Background(), udpCycleEnv(200))
	if listCalls != 0 {
		t.Fatalf("expected 0 lazy list calls when no candidates, got %d", listCalls)
	}
}

// TestUDPStaleCheckNoClusterWidePodsOrServices pins the RBAC/OOM fix:
// a list of pods or services at cluster scope must NEVER be issued.
// The fake client fails both on purpose; EndpointSlices stays healthy.
func TestUDPStaleCheckNoClusterWidePodsOrServices(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.1.1"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 200, "40002")
	for _, res := range []string{"pods", "services"} {
		e.CS.PrependReactor("list", res, func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("forbidden: NHA has no cluster-wide " + res + " RBAC")
		})
	}
	var sockID [48]byte
	sockID[0] = 0xDD
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockID},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if e.H.Series.UDPStaleDestroyed != 1 {
		t.Fatalf("UDPStaleDestroyed=%d, want 1 — a 403 on services/pods must not abort",
			e.H.Series.UDPStaleDestroyed)
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
	e := fixture(t, nodeA, nodeB,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.1.1"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.20.42"))
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
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.20.42")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockRemoteDead {
		t.Fatalf("expected cross-node PodCIDR dead backend socket destroyed, got %v", destroyed)
	}
}

// TestUDPStaleSkipsCiliumHealthIP: an IP advertised on a node's
// cilium-health annotation is inside the pod CIDR but is NOT a dead
// backend — never destroy a socket pointing at it.
func TestUDPStaleSkipsCiliumHealthIP(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			Annotations: map[string]string{
				"io.cilium.network.ipv4-health-ip": "10.244.30.7",
			},
		},
		Spec: corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node)
	setupPodNetnsProc(t, e.Fixture, 200, "40002")
	var sockHealth [48]byte
	sockHealth[0] = 0xEE
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.30.7"), DstPort: 4244, ID: sockHealth},
		}, nil
	}
	var destroyed int
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		destroyed++
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if destroyed != 0 {
		t.Fatalf("destroyed %d cilium-health socket(s), want 0", destroyed)
	}
}

// TestUDPStaleENOENTIsNotAKill: the kernel's ENOENT answer means the
// socket had already vanished. It is idempotent success, but must not
// be counted as a SOCK_DESTROY (no metric, no ACTION log).
func TestUDPStaleENOENTIsNotAKill(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.1.1"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 200, "40002")
	var sockID [48]byte
	sockID[0] = 0x11
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockID},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		return false, nil // ENOENT — socket already gone
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if e.H.Series.UDPStaleDestroyed != 0 {
		t.Fatalf("UDPStaleDestroyed=%d, want 0 for ENOENT", e.H.Series.UDPStaleDestroyed)
	}
	if strings.Contains(e.LogLines(t), "ACTION: udp-stale-socket SOCK_DESTROY") {
		t.Fatalf("ENOENT emitted an ACTION kill log:\n%s", e.LogLines(t))
	}
}

// TestUDPStaleHeldUsesOkLabel: the held path used to emit the illegal
// cycles{check="udp-stale-socket",result="held"} label. The contract
// only allows "ok"; a gated cycle must bump "ok" and never "held".
func TestUDPStaleHeldUsesOkLabel(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.1.1"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	e.H.Deps.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: now.Add(10 * time.Minute).Format(time.RFC3339),
			}, nil
		},
	}

	var sockID [48]byte
	sockID[0] = 0x22
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockID},
		}, nil
	}
	var destroyed int
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		destroyed++
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUDPStale, "held")); got != 0 {
		t.Fatalf("illegal cycles{result=held} = %v, want 0", got)
	}
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUDPStale, "ok")); got < 2 {
		t.Fatalf("cycles{result=ok} = %v, want >= 2", got)
	}
	if destroyed != 0 {
		t.Fatalf("destroyed %d socket(s) while maintenance held", destroyed)
	}
}

// TestUDPStaleDirectPodToPodUDPNeverDestroyed pins the Wave-5 P0: a
// connected UDP flow to a Pod IP inside podCIDRs on a port that NO UDP
// EndpointSlice manages is a direct Pod-to-Pod conversation (gossip,
// headless StatefulSet peers, a reply socket to the client Pod IP),
// not a dead Service backend. It must never be SOCK_DESTROY'd.
func TestUDPStaleDirectPodToPodUDPNeverDestroyed(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	// A managed UDP Service (53) still exists so the EndpointSlice
	// verification path runs — the P2P port itself is unmanaged.
	e := fixture(t, node, udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockP2P, sockLive [48]byte
	sockP2P[0], sockLive[0] = 0x31, 0x32
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.4.4"), DstPort: 7777, ID: sockP2P},
			{Family: 2, DstIP: net.ParseIP("10.244.2.50"), DstPort: 53, ID: sockLive},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	for range 4 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) != 0 {
		t.Fatalf("destroyed direct P2P / live-backend sockets: %x", destroyed)
	}
}

// TestUDPStaleDeadEndpointAbsentFromEverySliceDestroyed: the active
// set for a UDP port is the UNION over every slice managing it — an
// IP present in even one slice is live, one absent from all is dead.
func TestUDPStaleDeadEndpointAbsentFromEverySliceDestroyed(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("svc-a", 53, "10.244.2.50"),
		udpEndpointSlice("svc-a-extra", 53, "10.244.2.51"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockDead, sockSecondSlice [48]byte
	sockDead[0], sockSecondSlice[0] = 0x41, 0x42
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockDead},
			{Family: 2, DstIP: net.ParseIP("10.244.2.51"), DstPort: 53, ID: sockSecondSlice},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockDead {
		t.Fatalf("destroyed=%x, want only the dead endpoint %x", destroyed, sockDead)
	}
}

// TestUDPStalePodCIDROverrideKeepsCiliumExemptIPs: a
// NHA_UDP_STALE_POD_CIDRS override replaces the CIDR list but must
// NOT wipe the node-annotation exempt set — both cilium-health and
// cilium-host stay protected, even on a managed UDP port.
func TestUDPStalePodCIDROverrideKeepsCiliumExemptIPs(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			Annotations: map[string]string{
				"io.cilium.network.ipv4-health-ip":   "10.99.0.7",
				"io.cilium.network.ipv4-cilium-host": "10.99.0.8",
			},
		},
		// Override CIDRs deliberately differ from the Node's own.
		Spec: corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.99.0.50"),
		udpEndpointSlice("dead-backend-seed", 53, "10.99.0.99"))
	e.H.Cfg.Wave3.UDPStalePodCIDRs = "10.99.0.0/16"
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockHealth, sockHost, sockDead [48]byte
	sockHealth[0], sockHost[0], sockDead[0] = 0x51, 0x52, 0x53
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.99.0.7"), DstPort: 53, ID: sockHealth},
			{Family: 2, DstIP: net.ParseIP("10.99.0.8"), DstPort: 53, ID: sockHost},
			{Family: 2, DstIP: net.ParseIP("10.99.0.99"), DstPort: 53, ID: sockDead},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.99.0.99")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockDead {
		t.Fatalf("destroyed=%x, want only the dead endpoint %x (health/cilium-host must be exempt)",
			destroyed, sockDead)
	}
}

// TestUDPStaleTerminalLocalPodIPNotExempt: a Succeeded/Failed pod on
// this node must not be treated as a live local endpoint — its IP is
// a genuine dead-backend candidate on a managed UDP port.
func TestUDPStaleTerminalLocalPodIPNotExempt(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	terminal := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "done-pod"},
		Status: corev1.PodStatus{
			Phase: corev1.PodSucceeded, PodIP: "10.244.7.7",
		},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.7.7"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockDead [48]byte
	sockDead[0] = 0x61
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.7.7"), DstPort: 53, ID: sockDead},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200, terminal)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.7.7")
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if len(destroyed) != 1 || destroyed[0] != sockDead {
		t.Fatalf("destroyed=%x, want terminal local pod IP destroyed %x", destroyed, sockDead)
	}
}

// TestUDPStaleNilProtocolIsNotUDP pins the port-eligibility fix: a nil
// EndpointPort.Protocol is Kubernetes' TCP default, never UDP. Even
// after the ledger learned the ip:port from a real UDP slice, a port
// whose only current slice has a nil protocol is unmanaged for this
// check and cannot be destroyed.
func TestUDPStaleNilProtocolIsNotUDP(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	tcpDefault := udpEndpointSlice("nil-proto-svc", 53, "10.244.2.50")
	tcpDefault.Ports[0].Protocol = nil // Kubernetes defaults to TCP
	e := fixture(t, node, tcpDefault,
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockDead [48]byte
	sockDead[0] = 0x71
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockDead},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	for range 4 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) != 0 {
		t.Fatalf("destroyed %x through a nil-protocol (TCP-default) port", destroyed)
	}
}

// TestUDPStaleAPIOKFalseNeverSweeps: a cycle whose API verdict is
// unhealthy must abort before any dump/list/destroy — e.Pods may be
// stale, so no verdict drawn from it is trustworthy.
func TestUDPStaleAPIOKFalseNeverSweeps(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockDead [48]byte
	sockDead[0] = 0x72
	var dumps, sliceLists, destroyed int
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		dumps++
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockDead},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		destroyed++
		return true, nil
	}
	e.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		sliceLists++
		return false, nil, nil
	})

	chk := e.H.Check(wdeps.CheckUDPStale)
	good := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, good, "dead-backend-seed", "10.244.9.99")
	dumps, sliceLists = 0, 0

	bad := udpCycleEnv(200)
	bad.APIOK = false
	for range 3 {
		chk.Run(context.Background(), bad)
	}
	if dumps != 0 || sliceLists != 0 || destroyed != 0 {
		t.Fatalf("unhealthy API cycle: dumps=%d sliceLists=%d destroyed=%d, want all 0",
			dumps, sliceLists, destroyed)
	}
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(
		wdeps.CheckUDPStale, "abort")); got < 3 {
		t.Fatalf("abort=%v want >= 3", got)
	}
}

// TestUDPStaleNoHealthyNodeSnapshotNeverSweeps: before the Node
// snapshot has ever been read successfully (healthCachedAt zero), no
// socket may be swept or destroyed — not even under a CIDR override.
func TestUDPStaleNoHealthyNodeSnapshotNeverSweeps(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"))
	e.H.Cfg.Wave3.UDPStalePodCIDRs = "10.244.0.0/16" // override must NOT bypass the guard
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")
	// Force the snapshot LIST to fail so healthCachedAt stays zero.
	e.CS.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nodes list unavailable")
	})

	var dumps, sliceLists, destroyed int
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		dumps++
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(int, uint8, [48]byte) (bool, error) {
		destroyed++
		return true, nil
	}
	e.CS.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		sliceLists++
		return false, nil, nil
	})

	for range 3 {
		e.H.Check(wdeps.CheckUDPStale).Run(context.Background(), udpCycleEnv(200))
	}
	if dumps != 0 || sliceLists != 0 || destroyed != 0 {
		t.Fatalf("no healthy-node snapshot: dumps=%d sliceLists=%d destroyed=%d, want all 0",
			dumps, sliceLists, destroyed)
	}
	if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(
		wdeps.CheckUDPStale, "abort")); got < 3 {
		t.Fatalf("abort=%v want >= 3", got)
	}
}

// TestUDPStaleDirectP2PSameManagedPortNeverDestroyed pins the
// ever-seen-endpoint ledger: a direct Pod-to-Pod UDP flow to a Pod IP
// that was never an EndpointSlice endpoint is NOT a dead Service
// backend even though its destination port is managed by a UDP
// Service. The old "port managed + IP absent" rule destroyed it.
func TestUDPStaleDirectP2PSameManagedPortNeverDestroyed(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node, udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sockP2P [48]byte
	sockP2P[0] = 0x73
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 40000, DstIP: net.ParseIP("10.244.4.4"), DstPort: 53, ID: sockP2P},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	for range 4 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) != 0 {
		t.Fatalf("destroyed a direct UDP P2P socket on a managed port: %x", destroyed)
	}
}

// TestUDPStaleLocalBoundSrcPortIsReplySocketNeverDestroyed pins the
// reply-socket guard: a connected UDP socket whose SrcPort is bound
// locally in the same netns is a server answering a client, never a
// blackhole to a dead Service backend.
func TestUDPStaleLocalBoundSrcPortIsReplySocketNeverDestroyed(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	e := fixture(t, node,
		udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50"),
		udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99"))
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")
	// Port 53 is bound in this netns — e.g. a DNS server replying to
	// a client whose address happens to be a vanished endpoint IP.
	e.H.Cfg.Seams.Host.UDPBoundPortsFn = func(pid int) (map[uint16]bool, error) {
		if pid == 200 {
			return map[uint16]bool{53: true}, nil
		}
		return map[uint16]bool{}, nil
	}

	var sockReply [48]byte
	sockReply[0] = 0x74
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 53, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sockReply},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")
	for range 4 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) != 0 {
		t.Fatalf("destroyed a server reply socket (SrcPort bound locally): %x", destroyed)
	}
}

// A backend that is still in the slice but Terminating / Serving=false
// is in the ever-seen ledger yet NOT live: its blackhole must be
// destroyed without waiting for the endpoint object to disappear.
func TestUDPStaleNonServingEndpointIsNotLive(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	sl := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
	notServing := false
	sl.Endpoints[0].Conditions.Serving = &notServing
	e := fixture(t, node, sl)
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sock [48]byte
	sock[0] = 0x74
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 40002, DstIP: net.ParseIP("10.244.2.50"), DstPort: 53, ID: sock},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}
	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	// First cycle seeds the ledger; the endpoint is already non-serving,
	// so there is no live window — every later cycle is a valid kill.
	for range 3 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) == 0 {
		t.Fatal("non-serving EndpointSlice endpoint must not count as live")
	}
}

func TestUDPStaleSliceIsolationNoCrossContamination(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
	}
	// Slice 0: TCP port 80 with 10.244.5.5 Serving=true.
	tcpProto := corev1.ProtocolTCP
	tcpPort := int32(80)
	servingTrue := true
	slTCP := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: "web-tcp"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Port: &tcpPort, Protocol: &tcpProto}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.244.5.5"},
			Conditions: discoveryv1.EndpointConditions{Serving: &servingTrue},
		}},
	}
	// Slice 1: UDP port 53 with 10.244.5.5 Serving=false.
	slUDP := udpEndpointSlice("dns-udp", 53, "10.244.5.5")
	servingFalse := false
	slUDP.Endpoints[0].Conditions.Serving = &servingFalse

	e := fixture(t, node, slTCP, slUDP)
	setupPodNetnsProc(t, e.Fixture, 1, "40001")
	setupPodNetnsProc(t, e.Fixture, 200, "40002")

	var sock [48]byte
	sock[0] = 0x88
	var destroyed [][48]byte
	e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
		if pid != 200 {
			return nil, nil
		}
		return []netlinkx.ConnectedUDPSocket{
			{Family: 2, SrcPort: 40002, DstIP: net.ParseIP("10.244.5.5"), DstPort: 53, ID: sock},
		}, nil
	}
	e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
		destroyed = append(destroyed, id)
		return true, nil
	}

	chk := e.H.Check(wdeps.CheckUDPStale)
	ce := udpCycleEnv(200)
	for range 3 {
		chk.Run(context.Background(), ce)
	}
	if len(destroyed) == 0 {
		t.Fatal("TCP slice Serving=true contaminated UDP slice Serving=false liveByAddr")
	}
}

func TestUDPStaleCtrTaskRootUnreadableAbortsPreservingStreaks(t *testing.T) {
	t.Run("tasks-incomplete-flag", func(t *testing.T) {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
		}
		epSlice := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
		deadSeed := udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99")
		e := fixture(t, node, epSlice, deadSeed)
		setupPodNetnsProc(t, e.Fixture, 1, "40001")
		setupPodNetnsProc(t, e.Fixture, 200, "40002")

		var sock [48]byte
		sock[0] = 0x99
		var destroyed [][48]byte
		e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
			if pid != 200 {
				return nil, nil
			}
			return []netlinkx.ConnectedUDPSocket{
				{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sock},
			}, nil
		}
		e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
			destroyed = append(destroyed, id)
			return true, nil
		}

		ce := udpCycleEnv(200)
		chk := e.H.Check(wdeps.CheckUDPStale)
		seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")

		// Cycle 1: streak hits 1/2.
		chk.Run(context.Background(), ce)
		if len(destroyed) != 0 {
			t.Fatalf("destroyed prematurely on cycle 1: %v", destroyed)
		}

		// Cycle 2: incomplete task map -> must abort and preserve streak at 1/2.
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			TasksOnce:    func() (map[string][]wdeps.CtrTask, bool) { return nil, false },
		})
		if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUDPStale, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1", got)
		}
		if len(destroyed) != 0 {
			t.Fatalf("destroyed during incomplete task map: %v", destroyed)
		}

		// Cycle 3: task map recovers -> streak reaches 2/2 and destroys socket immediately.
		chk.Run(context.Background(), ce)
		if len(destroyed) != 1 || destroyed[0] != sock {
			t.Fatalf("streak wiped during incomplete task map: destroyed=%v want [%x]", destroyed, sock)
		}
	})

	t.Run("ctrtaskroot-chmod-0000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
		}
		epSlice := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
		deadSeed := udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99")
		e := fixture(t, node, epSlice, deadSeed)
		setupPodNetnsProc(t, e.Fixture, 1, "40001")
		setupPodNetnsProc(t, e.Fixture, 200, "40002")
		e.Live[200] = true
		e.MkTask(t, wdepstest.UIDA, "pause", 200)

		var sock [48]byte
		sock[0] = 0xAB
		var destroyed [][48]byte
		e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
			if pid != 200 {
				return nil, nil
			}
			return []netlinkx.ConnectedUDPSocket{
				{Family: 2, SrcPort: 50000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sock},
			}, nil
		}
		e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
			destroyed = append(destroyed, id)
			return true, nil
		}

		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
		chk := e.H.Check(wdeps.CheckUDPStale)
		seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")

		chk.Run(context.Background(), ce) // streak = 1/2

		if err := os.Chmod(e.CtrDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.CtrDir, 0o755) })
		chk.Run(context.Background(), ce) // unreadable CtrTaskRoot -> abort
		if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUDPStale, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1", got)
		}

		if err := os.Chmod(e.CtrDir, 0o755); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce) // recovery -> streak reaches 2/2 -> destroy
		if len(destroyed) != 1 || destroyed[0] != sock {
			t.Fatalf("streak lost during CtrTaskRoot 0o000: destroyed=%v", destroyed)
		}
	})
}

func TestUDPStalePartialDumpErrPreservesStreaks(t *testing.T) {
	t.Run("partial-dump-err-with-other-candidates", func(t *testing.T) {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
		}
		epSlice := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
		deadSeed := udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99", "10.244.8.88")
		e := fixture(t, node, epSlice, deadSeed)
		setupPodNetnsProc(t, e.Fixture, 1, "40001")
		setupPodNetnsProc(t, e.Fixture, 200, "40002")
		setupPodNetnsProc(t, e.Fixture, 201, "40003")

		var sock200 [48]byte
		sock200[0] = 0x20
		var sock201 [48]byte
		sock201[0] = 0x21

		fail200 := false
		var destroyed [][48]byte
		e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
			switch pid {
			case 200:
				if fail200 {
					return nil, errors.New("netlink EACCES on pid 200")
				}
				return []netlinkx.ConnectedUDPSocket{
					{Family: 2, SrcPort: 40000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sock200},
				}, nil
			case 201:
				return []netlinkx.ConnectedUDPSocket{
					{Family: 2, SrcPort: 40001, DstIP: net.ParseIP("10.244.8.88"), DstPort: 53, ID: sock201},
				}, nil
			default:
				return nil, nil
			}
		}
		e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
			destroyed = append(destroyed, id)
			return true, nil
		}

		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
				return map[string][]wdeps.CtrTask{
					wdepstest.UIDA: {{Name: "pause", PID: 200, Live: true}},
					wdepstest.UIDB: {{Name: "pause", PID: 201, Live: true}},
				}, true
			},
		}
		chk := e.H.Check(wdeps.CheckUDPStale)
		seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")

		// Cycle 1: both 200 and 201 reach streak 1/2.
		chk.Run(context.Background(), ce)
		if len(destroyed) != 0 {
			t.Fatalf("premature destroy on cycle 1: %v", destroyed)
		}

		// Cycle 2: pid 200 netns dump fails (dumpErr=true), pid 201 succeeds ->
		// 201 confirms and is destroyed, while 200's streak 1/2 is preserved!
		fail200 = true
		chk.Run(context.Background(), ce)
		if len(destroyed) != 1 || destroyed[0] != sock201 {
			t.Fatalf("expected pid 201 destroyed during partial dumpErr: destroyed=%v", destroyed)
		}

		// Cycle 3: pid 200 recovers -> reaches 2/2 immediately and destroys sock200.
		fail200 = false
		chk.Run(context.Background(), ce)
		if len(destroyed) != 2 || destroyed[1] != sock200 {
			t.Fatalf("pid 200 streak wiped by partial dumpErr: destroyed=%v want [sock201, sock200]", destroyed)
		}
	})

	t.Run("dump-err-with-zero-candidates-aborts-preserving-streak", func(t *testing.T) {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Spec:       corev1.NodeSpec{PodCIDR: "10.244.0.0/16"},
		}
		epSlice := udpEndpointSlice("dns-svc-abc", 53, "10.244.2.50")
		deadSeed := udpEndpointSlice("dead-backend-seed", 53, "10.244.9.99")
		e := fixture(t, node, epSlice, deadSeed)
		setupPodNetnsProc(t, e.Fixture, 1, "40001")
		setupPodNetnsProc(t, e.Fixture, 200, "40002")

		var sock200 [48]byte
		sock200[0] = 0x22
		fail200 := false
		var destroyed [][48]byte
		e.H.Cfg.Seams.Host.DumpConnectedUDPFn = func(pid int) ([]netlinkx.ConnectedUDPSocket, error) {
			if pid != 200 {
				return nil, nil
			}
			if fail200 {
				return nil, errors.New("transient netns dump err")
			}
			return []netlinkx.ConnectedUDPSocket{
				{Family: 2, SrcPort: 40000, DstIP: net.ParseIP("10.244.9.99"), DstPort: 53, ID: sock200},
			}, nil
		}
		e.H.Cfg.Seams.Host.DestroyUDPSocketFn = func(_ int, _ uint8, id [48]byte) (bool, error) {
			destroyed = append(destroyed, id)
			return true, nil
		}

		ce := udpCycleEnv(200)
		chk := e.H.Check(wdeps.CheckUDPStale)
		seedDeadUDPBackend(t, e, ce, "dead-backend-seed", "10.244.9.99")

		chk.Run(context.Background(), ce) // streak = 1/2

		fail200 = true
		chk.Run(context.Background(), ce) // dumpErr=true, len(rawCandidates)==0 -> abort
		if got := promtestutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUDPStale, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1", got)
		}

		fail200 = false
		chk.Run(context.Background(), ce) // recovery -> streak reaches 2/2 -> destroy
		if len(destroyed) != 1 || destroyed[0] != sock200 {
			t.Fatalf("streak wiped when dumpErr=true & len(candidates)==0: destroyed=%v", destroyed)
		}
	})
}
