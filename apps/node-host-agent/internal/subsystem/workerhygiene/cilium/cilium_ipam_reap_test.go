// cilium_ipam_reap_test.go — unit tests for ParseCiliumEndpoints and
// CiliumIPAMCheck's L1 dead-netdev zombie endpoint reaper.
package cilium_test

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

type epJSON struct {
	ID     int64  `json:"id"`
	State  string `json:"state"`
	Status struct {
		State      string `json:"state"`
		Networking struct {
			InterfaceName string `json:"interface-name"`
			Addressing    []struct {
				IPv4 string `json:"ipv4,omitempty"`
				IPv6 string `json:"ipv6,omitempty"`
			} `json:"addressing"`
		} `json:"networking"`
	} `json:"status"`
}

func makeEndpointsJSON(t *testing.T, specs []struct {
	id       int64
	topState string
	state    string
	iface    string
	ipv4     string
	ipv6     string
}) []byte {
	t.Helper()
	items := make([]epJSON, 0, len(specs))
	for _, s := range specs {
		var e epJSON
		e.ID = s.id
		e.State = s.topState
		e.Status.State = s.state
		e.Status.Networking.InterfaceName = s.iface
		if s.ipv4 != "" || s.ipv6 != "" {
			e.Status.Networking.Addressing = append(e.Status.Networking.Addressing, struct {
				IPv4 string `json:"ipv4,omitempty"`
				IPv6 string `json:"ipv6,omitempty"`
			}{IPv4: s.ipv4, IPv6: s.ipv6})
		}
		items = append(items, e)
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runIPAMCycles(t *testing.T, e *env, pods []corev1.Pod, apiOK bool, count int) {
	t.Helper()
	chk := wdepstest.Check[*cilium.CiliumIPAMCheck](e.H, wdeps.CheckCiliumIPAM)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        apiOK,
		Pods:         pods,
	}
	for range count {
		chk.Run(context.Background(), ce)
	}
}

func TestParseCiliumEndpoints(t *testing.T) {
	realShape := `[{
		"id": 179,
		"state": "ready",
		"status": {
			"state": "ready",
			"identity": {"id": 12345},
			"external-identifiers": {"cni-attachment-id": "dd36c76b:eth0"},
			"networking": {
				"addressing": [
					{"ipv4": "10.0.3.6", "ipv4-pool-name": "default", "ipv6": "fd00::3b1", "ipv6-pool-name": "default"}
				],
				"container-interface-name": "eth0",
				"interface-index": 19925,
				"interface-name": "lxc765ca6d2514a"
			}
		}
	}, {
		"id": 42,
		"state": "ready",
		"status": {
			"state": "ready",
			"networking": {
				"addressing": [{"ipv4": "10.0.3.99"}],
				"interface-name": "lxc_health"
			}
		}
	}, {
		"id": 0,
		"state": "ready",
		"status": {
			"state": "ready",
			"networking": {
				"interface-name": "cilium_host"
			}
		}
	}]`

	eps, err := cilium.ParseCiliumEndpoints([]byte(realShape))
	if err != nil {
		t.Fatalf("ParseCiliumEndpoints: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("len=%d want 3", len(eps))
	}
	if eps[0].ID != 179 || eps[0].State != "ready" || eps[0].TopState != "ready" ||
		eps[0].InterfaceName != "lxc765ca6d2514a" ||
		len(eps[0].IPs) != 2 || eps[0].IPs[0] != "10.0.3.6" || eps[0].IPs[1] != "fd00::3b1" {
		t.Fatalf("eps[0]=%+v", eps[0])
	}
	if eps[1].InterfaceName != "lxc_health" || eps[2].InterfaceName != "cilium_host" || eps[2].ID != 0 {
		t.Fatalf("reserved eps parsed unexpectedly: %+v", eps[1:])
	}

	empty, err := cilium.ParseCiliumEndpoints([]byte("[]"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty array = (%v, %v), want ([], nil)", empty, err)
	}
	nullBody, err := cilium.ParseCiliumEndpoints([]byte("null"))
	if err != nil || len(nullBody) != 0 {
		t.Fatalf("null body = (%v, %v), want (nil, nil)", nullBody, err)
	}

	for _, bad := range []string{"", "not json", `{"ipam":{"ipv4":{"used":40}}}`} {
		if _, err := cilium.ParseCiliumEndpoints([]byte(bad)); err == nil {
			t.Fatalf("ParseCiliumEndpoints(%q) expected error, got nil", bad)
		}
	}
}

func TestCiliumIPAMReapSafetyFilters(t *testing.T) {
	e := fixture(t)
	// Exhausted IPAM (used=50, available=0).
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":50,"available":0}}}`)
	// Create live netdev only for lxc1111aa (ID 101).
	if err := os.MkdirAll(filepath.Join(e.SysNet, "lxc1111aa"), 0o755); err != nil {
		t.Fatal(err)
	}

	e.EndpointsBody = makeEndpointsJSON(t, []struct {
		id       int64
		topState string
		state    string
		iface    string
		ipv4     string
		ipv6     string
	}{
		// 101: live netdev exists → MUST NOT delete.
		{id: 101, topState: "ready", state: "ready", iface: "lxc1111aa", ipv4: "10.0.3.101"},
		// 102: netdev missing, but IPv4 matches live Running pod → MUST NOT delete.
		{id: 102, topState: "ready", state: "ready", iface: "lxc2222bb", ipv4: "10.0.3.102"},
		// 103: netdev missing, IPv6 matches live Pending pod PodIPs → MUST NOT delete.
		{id: 103, topState: "ready", state: "ready", iface: "lxc3333cc", ipv4: "10.0.3.103", ipv6: "fd00::103"},
		// 104: transitional state "creating" → MUST NOT delete.
		{id: 104, topState: "creating", state: "creating", iface: "lxc4444dd", ipv4: "10.0.3.104"},
		// 105: transitional status.state "restoring" → MUST NOT delete.
		{id: 105, topState: "ready", state: "restoring", iface: "lxc5555ee", ipv4: "10.0.3.105"},
		// 106: reserved lxc_health → MUST NOT delete.
		{id: 106, topState: "ready", state: "ready", iface: "lxc_health", ipv4: "10.0.3.106"},
		// 107: reserved cilium_host → MUST NOT delete.
		{id: 107, topState: "ready", state: "ready", iface: "cilium_host", ipv4: "10.0.3.107"},
		// 0: invalid id 0 → MUST NOT delete.
		{id: 0, topState: "ready", state: "ready", iface: "lxc0000ff", ipv4: "10.0.3.108"},
		// 109: non-hex lxc iface → MUST NOT delete.
		{id: 109, topState: "ready", state: "ready", iface: "lxcxyz", ipv4: "10.0.3.109"},
		// 201: netdev missing, IP belongs ONLY to PodSucceeded pod → ZOMBIE, delete!
		{id: 201, topState: "ready", state: "ready", iface: "lxcabcdef01", ipv4: "10.0.3.201", ipv6: "fd00::201"},
		// 202: netdev missing, IP belongs ONLY to HostNetwork pod (node IP) → ZOMBIE, delete!
		{id: 202, topState: "ready", state: "ready", iface: "lxcABCDEF02", ipv4: "10.0.3.202"},
	})

	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "live-v4", Namespace: "default"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.3.102"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "live-v6", Namespace: "default"},
			Status: corev1.PodStatus{
				Phase:  corev1.PodPending,
				PodIPs: []corev1.PodIP{{IP: "10.0.9.9"}, {IP: "fd00:0:0:0::103"}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "done-pod", Namespace: "default"},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded, PodIP: "10.0.3.201"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "hostnet-pod", Namespace: "kube-system"},
			Spec:       corev1.PodSpec{HostNetwork: true},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.3.202"},
		},
	}

	// Cycle 1 (StreakPending), Cycle 2 (latch + 1st observation), Cycle 3 (2nd observation → delete).
	runIPAMCycles(t, e, pods, true, 2)
	if len(e.DeletedEndpoints) != 0 {
		t.Fatalf("deleted too early (before 2nd latched observation): %v", e.DeletedEndpoints)
	}
	// Budget must NOT have been spent on Cycle 2 when nothing was confirmed.
	if !e.H.State.RateOK("last-cilium-ipam-reap", e.H.Cfg.MinRestartInterval) {
		t.Fatal("cooldown spent on 1st observation cycle with 0 confirmed zombies")
	}

	runIPAMCycles(t, e, pods, true, 1)
	if len(e.DeletedEndpoints) != 2 ||
		e.DeletedEndpoints[0] != "/v1/endpoint/201" ||
		e.DeletedEndpoints[1] != "/v1/endpoint/202" {
		t.Fatalf("DeletedEndpoints = %v, want [/v1/endpoint/201 /v1/endpoint/202]", e.DeletedEndpoints)
	}
	if got := testutil.ToFloat64(e.H.Actions.WithLabelValues(wdeps.CheckCiliumIPAM, "endpoint-delete")); got != 2 {
		t.Fatalf("Actions endpoint-delete = %v, want 2", got)
	}
	if !strings.Contains(e.LogLines(t), "ACTION cilium-ipam-reap: deleted=2 failed=0 confirmed=2 remaining=0") {
		t.Fatalf("missing ACTION cilium-ipam-reap log:\n%s", e.LogLines(t))
	}
}

func TestCiliumIPAMReapCapCooldownAndFailClosed(t *testing.T) {
	e := fixture(t)
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":120,"available":0}}}`)

	specs := make([]struct {
		id       int64
		topState string
		state    string
		iface    string
		ipv4     string
		ipv6     string
	}, 75)
	for i := range 75 {
		specs[i] = struct {
			id       int64
			topState string
			state    string
			iface    string
			ipv4     string
			ipv6     string
		}{
			id:       int64(2000 - i), // reverse order to verify deterministic ascending sort
			topState: "ready",
			state:    "ready",
			iface:    fmt.Sprintf("lxc%08x", 2000-i),
			ipv4:     fmt.Sprintf("10.0.4.%d", i+1),
		}
	}
	e.EndpointsBody = makeEndpointsJSON(t, specs)

	// Cycle 1 (pending) + Cycle 2 (1st observation) + Cycle 3 (confirmed → capped at 50).
	runIPAMCycles(t, e, nil, true, 3)
	if len(e.DeletedEndpoints) != 50 {
		t.Fatalf("first reap deleted %d endpoints, want cap 50", len(e.DeletedEndpoints))
	}
	if e.DeletedEndpoints[0] != "/v1/endpoint/1926" || e.DeletedEndpoints[49] != "/v1/endpoint/1975" {
		t.Fatalf("unexpected deterministic slice bounds: first=%s last=%s",
			e.DeletedEndpoints[0], e.DeletedEndpoints[49])
	}

	// Cycle 4 immediately without advancing clock → cooldown blocks reap.
	e.DeletedEndpoints = nil
	runIPAMCycles(t, e, nil, true, 1)
	if len(e.DeletedEndpoints) != 0 {
		t.Fatalf("cooldown failed to block reap: deleted %d", len(e.DeletedEndpoints))
	}
	if !strings.Contains(e.LogLines(t), "cooldown active, skip") {
		t.Fatalf("missing cooldown skip log:\n%s", e.LogLines(t))
	}

	// Advance clock past MinRestartInterval and keep remaining 25 endpoints (1976..2000).
	e.EndpointsBody = makeEndpointsJSON(t, specs[:25])
	e.Now = e.Now.Add(e.H.Cfg.MinRestartInterval + time.Second)
	runIPAMCycles(t, e, nil, true, 1)
	if len(e.DeletedEndpoints) != 25 {
		t.Fatalf("after cooldown expected 25 remaining deletes, got %d", len(e.DeletedEndpoints))
	}
	if e.DeletedEndpoints[0] != "/v1/endpoint/1976" || e.DeletedEndpoints[24] != "/v1/endpoint/2000" {
		t.Fatalf("unexpected remaining slice: first=%s last=%s",
			e.DeletedEndpoints[0], e.DeletedEndpoints[24])
	}

	// StatFn returning non-ENOENT (e.g. EACCES) must fail closed.
	e2 := fixture(t)
	e2.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	e2.EndpointsBody = makeEndpointsJSON(t, []struct {
		id       int64
		topState string
		state    string
		iface    string
		ipv4     string
		ipv6     string
	}{{id: 501, topState: "ready", state: "ready", iface: "lxcdead01", ipv4: "10.0.5.1"}})
	e2.H.Cfg.Seams.Host.StatFn = func(path string) (os.FileInfo, error) {
		if path == e2.SysNet {
			return os.Stat(path)
		}
		return nil, os.ErrPermission
	}
	runIPAMCycles(t, e2, nil, true, 4)
	if len(e2.DeletedEndpoints) != 0 {
		t.Fatalf("unexpected delete on EACCES stat error: %v", e2.DeletedEndpoints)
	}
}

func TestCiliumIPAMReapGatesAndHealthyReset(t *testing.T) {
	zombies := makeEndpointsJSON(t, []struct {
		id       int64
		topState string
		state    string
		iface    string
		ipv4     string
		ipv6     string
	}{{id: 701, topState: "ready", state: "ready", iface: "lxcbeef01", ipv4: "10.0.7.1"}})

	// 1. Maintenance window (HoldEmergencyHeal) blocks delete without spending cooldown.
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-a",
			Annotations: map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
		},
	}
	e := fixture(t, node)
	e.H.Cfg.Coord = nodecoord.NewKube("node-a", e.CS)
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	e.EndpointsBody = zombies
	runIPAMCycles(t, e, nil, true, 3)
	if len(e.DeletedEndpoints) != 0 {
		t.Fatalf("deleted during maintenance window: %v", e.DeletedEndpoints)
	}
	if !strings.Contains(e.LogLines(t), "held by maintenance window") {
		t.Fatalf("missing maintenance hold log:\n%s", e.LogLines(t))
	}

	// Lift maintenance → immediately deletes on next cycle because 2-cycle seen state survived and cooldown was not spent.
	node.Annotations = nil
	if _, err := e.CS.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Coord = nodecoord.NewKube("node-a", e.CS)
	runIPAMCycles(t, e, nil, true, 1)
	if len(e.DeletedEndpoints) != 1 || e.DeletedEndpoints[0] != "/v1/endpoint/701" {
		t.Fatalf("after maintenance lifted got %v, want [/v1/endpoint/701]", e.DeletedEndpoints)
	}

	// 2. !e.APIOK aborts cleanly and does not delete.
	e2 := fixture(t)
	e2.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	e2.EndpointsBody = zombies
	runIPAMCycles(t, e2, nil, true, 2) // latch + 1st observation
	runIPAMCycles(t, e2, nil, false, 1)
	if len(e2.DeletedEndpoints) != 0 {
		t.Fatalf("deleted when APIOK=false: %v", e2.DeletedEndpoints)
	}

	// 3. Healthy IPAM clears seenZombies so a later exhaustion requires 2 fresh observations again.
	e2.UnixBody = []byte(`{"ipam":{"ipv4":{"used":1,"available":100}}}`)
	runIPAMCycles(t, e2, nil, true, 1) // healthy → resets Fails and seenZombies
	e2.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	runIPAMCycles(t, e2, nil, true, 2) // 1st pending + 2nd latched (1st observation)
	if len(e2.DeletedEndpoints) != 0 {
		t.Fatalf("stale seenZombies survived healthy reset: %v", e2.DeletedEndpoints)
	}
	runIPAMCycles(t, e2, nil, true, 1) // 2nd observation → deletes
	if len(e2.DeletedEndpoints) != 1 {
		t.Fatalf("expected delete after fresh 2-cycle observation, got %v", e2.DeletedEndpoints)
	}

	// 4. IPAMReapEnabled=false disables reaping completely.
	e3 := fixture(t)
	e3.H.Cfg.Cilium.IPAMReapEnabled = false
	e3.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	e3.EndpointsBody = zombies
	runIPAMCycles(t, e3, nil, true, 4)
	if len(e3.DeletedEndpoints) != 0 {
		t.Fatalf("deleted when IPAMReapEnabled=false: %v", e3.DeletedEndpoints)
	}

	// 5. Partial UnixDelete failure counts only successes and keeps failed ID for retry.
	e4 := fixture(t)
	e4.UnixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":0}}}`)
	e4.EndpointsBody = makeEndpointsJSON(t, []struct {
		id       int64
		topState string
		state    string
		iface    string
		ipv4     string
		ipv6     string
	}{
		{id: 801, topState: "ready", state: "ready", iface: "lxcaaa01", ipv4: "10.0.8.1"},
		{id: 802, topState: "ready", state: "ready", iface: "lxcaaa02", ipv4: "10.0.8.2"},
	})
	e4.EndpointDeleteErrs = map[string]error{"/v1/endpoint/801": errors.New("socket busy")}
	runIPAMCycles(t, e4, nil, true, 3)
	if len(e4.DeletedEndpoints) != 2 {
		t.Fatalf("expected 2 delete attempts, got %v", e4.DeletedEndpoints)
	}
	if got := testutil.ToFloat64(e4.H.Actions.WithLabelValues(wdeps.CheckCiliumIPAM, "endpoint-delete")); got != 1 {
		t.Fatalf("Actions endpoint-delete = %v, want 1 (only successful delete)", got)
	}
	if !strings.Contains(e4.LogLines(t), "ACTION cilium-ipam-reap: deleted=1 failed=1 confirmed=2 remaining=1") {
		t.Fatalf("missing partial failure ACTION log:\n%s", e4.LogLines(t))
	}
}
