// cilium_ipam_test.go — check 38 cilium-bpf-ipam leak/exhaustion
// latch + parseCiliumIPAM shape coverage.
package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// --- check: cilium-bpf-ipam (38) ---

// runningPod builds a Running pod on node-a; hostNetwork excludes it
// from the IPAM in-use count.
func runningPod(name, ns, uid string, hostNetwork bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a", HostNetwork: hostNetwork},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if !hostNetwork {
		// The IPAM check counts "pods holding an address" — a pod
		// without status.podIP is treated as not holding one.
		p.Status.PodIP = "10.0.0.1"
	}
	return p
}

func TestCiliumIPAMLeakedLatch(t *testing.T) {
	e := fixture(t)
	// 40 cilium-allocated IPs but only 5 in-use pods → 35 leaked.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	for i := 0; i < 5; i++ {
		p := runningPod(fmt.Sprintf("app-%d", i), "default",
			fmt.Sprintf("uid-%d", i), false)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	if !strings.Contains(logLines(t, e), "leaked=35") {
		t.Fatalf("missing suspect log:\n%s", logLines(t, e))
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing after %d consecutive cycles: %v", 2, err)
	}
	if !strings.Contains(logLines(t, e), "STATE-ENTER: cilium-ipam-exhausted") {
		t.Fatalf("missing STATE-ENTER log:\n%s", logLines(t, e))
	}
	if got := testutil.ToFloat64(e.h.ciliumAllocated); got != 40 {
		t.Fatalf("allocated gauge=%v want 40", got)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 35 {
		t.Fatalf("leaked gauge=%v want 35", got)
	}
}

func TestCiliumIPAMAvailableLowLatches(t *testing.T) {
	e := fixture(t)
	// Leak-free but the pool is nearly exhausted: available <=2 alone
	// arms the latch after ConsecNeeded.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":5,"available":2}}}`)
	for i := 0; i < 5; i++ {
		p := runningPod(fmt.Sprintf("app-%d", i), "default",
			fmt.Sprintf("uid-%d", i), false)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing on available<=2: %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 0 {
		t.Fatalf("leaked gauge=%v want 0", got)
	}
}

func TestCiliumIPAMHealthyClearsLatch(t *testing.T) {
	e := fixture(t)
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("setup latch missing: %v", err)
	}
	// IPs reclaimed — leaked drops under the threshold.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":10,"available":130}}}`)
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after IPAM recovered")
	}
	if e.h.ciliumIPAMFails != 0 {
		t.Fatalf("counter=%d want 0 after recovery", e.h.ciliumIPAMFails)
	}
	if !strings.Contains(logLines(t, e), "STATE-EXIT: cilium-ipam-exhausted") {
		t.Fatalf("missing STATE-EXIT log:\n%s", logLines(t, e))
	}
}

func TestCiliumIPAMHostNetworkExcludedFromInUse(t *testing.T) {
	e := fixture(t)
	// used=32, one normal Running pod, one hostNetwork pod — if
	// hostNetwork were counted in-use would be 2 → leaked 30 (no
	// latch); correct exclusion gives leaked=31 >30 → latch.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":32,"available":100}}}`)
	for _, p := range []*corev1.Pod{
		runningPod("app", "default", uidA, false),
		runningPod("node-local-dns-x", "kube-system", uidB, true),
	} {
		if _, err := e.cs.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing — hostNetwork pod wrongly counted in-use: %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 31 {
		t.Fatalf("leaked gauge=%v want 31 (hostNetwork excluded)", got)
	}
}

func TestCiliumIPAMInconclusiveKeepsCounter(t *testing.T) {
	e := fixture(t)
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1", e.h.ciliumIPAMFails)
	}
	// Socket fails → inconclusive: counter kept, not reset (same
	// hysteresis rule as checkCiliumInitStuck).
	e.unixErr = errors.New("socket dead")
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1 (inconclusive keeps)", e.h.ciliumIPAMFails)
	}
	if got := e.h.cycles.WithLabelValues(checkCiliumIPAM, "abort"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("abort=%v want 1", testutil.ToFloat64(got))
	}
	// Garbage body → same inconclusive path.
	e.unixErr = nil
	e.unixBody = []byte(`{"cilium":{"state":"Ok"}}`)
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1 (unparseable keeps)", e.h.ciliumIPAMFails)
	}
}

func TestCiliumIPAMUpstreamArrayShape(t *testing.T) {
	e := fixture(t)
	// Real cilium healthz shape: ipam.ipv4 is the allocated-IP list
	// and allocations maps each IP to an owner-name STRING
	// ({"ip": "pod-a"}) — cluster-pool free slots appear as entries
	// with an empty-string owner. used=40 allocated, 2 free.
	ips := make([]string, 0, 40)
	var b strings.Builder
	b.WriteString(`{"ipam":{"ipv4":[`)
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		ips = append(ips, ip)
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q", ip)
	}
	b.WriteString(`],"allocations":{`)
	for i, ip := range ips {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", ip, fmt.Sprintf("pod-%d", i))
	}
	// Two pool entries with empty owner → available=2.
	b.WriteString(`,"10.0.0.250":"","10.0.0.251":""}}}`)
	e.unixBody = []byte(b.String())
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing (leaked=40>30 AND available=2): %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumAllocated); got != 40 {
		t.Fatalf("allocated gauge=%v want 40 (array length)", got)
	}
}

func TestParseCiliumIPAMShapes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantUsed  int
		wantAvail int
		wantOK    bool
	}{
		{"object numbers", `{"ipam":{"ipv4":{"used":10,"available":3}}}`, 10, 3, true},
		{"object collections", `{"ipam":{"ipv4":{"used":["a","b"],"available":[]}}}`, 2, 0, true},
		{"object missing available", `{"ipam":{"ipv4":{"used":4}}}`, 4, -1, true},
		{"array", `{"ipam":{"ipv4":["10.0.0.1","10.0.0.2"]}}`, 2, -1, true},
		{"array real allocations", `{"ipam":{"ipv4":["10.0.0.1"],"allocations":{"10.0.0.1":"pod-a","10.0.0.9":""}}}`, 1, 1, true},
		{"array all-owned allocations", `{"ipam":{"ipv4":["10.0.0.1"],"allocations":{"10.0.0.1":"pod-a"}}}`, 1, -1, true},
		{"bare number", `{"ipam":{"ipv4":7}}`, 7, -1, true},
		{"no ipam", `{"cilium":{"state":"Ok"}}`, 0, -1, false},
		{"garbage", `not json`, 0, -1, false},
		{"empty ipv4", `{"ipam":{"status":"Ok"}}`, 0, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			used, avail, ok := parseCiliumIPAM([]byte(tc.body))
			if ok != tc.wantOK || used != tc.wantUsed || avail != tc.wantAvail {
				t.Fatalf("parseCiliumIPAM(%s)=(%d,%d,%v) want (%d,%d,%v)",
					tc.body, used, avail, ok, tc.wantUsed, tc.wantAvail, tc.wantOK)
			}
		})
	}
}
