// dns_resolv_wave5_test.go — Wave-5 P0: hostconfig T9 writes a
// deliberate "nameserver 127.0.0.1" stub plus real upstreams on every
// node. These tests pin that the guard neither spams a loopback
// warning every cycle nor kills a healthy CoreDNS over a stub that
// T9 owns.
package pods_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// runDNS builds a one-pod CycleEnv with a live pause task and runs n
// cycles of the dns-resolv check.
func runDNS(t *testing.T, e *env, p corev1.Pod, uid string, pid int,
	hostConf, podConf string, cycles int) {
	t.Helper()
	wdepstest.WriteFile(t, e.ResolvConf, hostConf)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, fmt.Sprint(pid), "root", "etc", "resolv.conf"), podConf)
	chk := e.H.Check(wdeps.CheckDNS)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{p},
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				uid: {{Name: "pause", PID: pid, Live: true}},
			}, true
		},
	}
	for range cycles {
		chk.Run(context.Background(), ce)
	}
}

func t9DNSConf(upstream string) string {
	return "nameserver 127.0.0.1\n" + upstream + "\n"
}

// TestDNST9LoopbackNormalIsNoOp: host and DNS pod both carry T9's
// 127.0.0.1 stub + the same external upstreams. The old isLoopbackNS
// merge fired the "both loopback" suspect on every 60s cycle and
// blocked the real drift branch underneath it.
func TestDNST9LoopbackNormalIsNoOp(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 901,
		t9DNSConf("nameserver 1.1.1.1"), t9DNSConf("nameserver 1.1.1.1"), 3)
	if len(e.Kills) != 0 {
		t.Fatalf("killed pause on a healthy T9 DNS pod: %v", e.Kills)
	}
	if strings.Contains(e.LogLines(t), "suspect: dns-resolv loopback") {
		t.Fatalf("T9 loopback spammed the loopback suspect:\n%s", e.LogLines(t))
	}
	if strings.Contains(e.LogLines(t), "dns-resolv-stale") {
		t.Fatalf("T9 loopback latched stale:\n%s", e.LogLines(t))
	}
}

// TestDNST9RealDriftWithLoopbackStillKills: even with the expected
// 127.0.0.1 stub on both sides, a different external upstream is real
// drift and must still reach the pause-kill action.
func TestDNST9RealDriftWithLoopbackStillKills(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 902,
		t9DNSConf("nameserver 1.1.1.1"), t9DNSConf("nameserver 8.8.8.8"), 2)
	if len(e.Kills) != 1 || e.Kills[0].PID != 902 {
		t.Fatalf("kills=%v want one SIGKILL of 902", e.Kills)
	}
}

// TestDNSCRIFiltersLoopbackNoKill: CRI stripped 127.0.0.1 from the
// pod's resolv.conf while the upstream set still matches. Comparing
// the non-loopback sets must produce no action.
// TestDNST9SystemdStubInPodIsSuspectNotKill: T9's host uses its own
// 127.0.0.1 local stub plus a real upstream, so hostStub is false but
// hostHasLoopback is true. A DNS pod still pinned to 127.0.0.53 used
// to slip through every old case. It must now emit the same
// dns-loopback suspect (event name/metric unchanged) and never kill.
func TestDNST9SystemdStubInPodIsSuspectNotKill(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 909,
		t9DNSConf("nameserver 1.1.1.1"), "nameserver 127.0.0.53\nnameserver 1.1.1.1\n", 3)
	if len(e.Kills) != 0 {
		t.Fatalf("T9 systemd stub in pod caused a pause kill: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "suspect: dns-resolv systemd stub in DNS pod") {
		t.Fatalf("missing pod-stub suspect log:\n%s", e.LogLines(t))
	}
	evs, err := e.CS.EventsV1().Events("kube-system").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "DNSLoopbackNameserver" {
		t.Fatalf("want exactly one DNSLoopbackNameserver event, got %+v (err=%v)", evs.Items, err)
	}
}

// TestDNST9StubWithUpstreamDriftStillKills: the podStub-only suspect
// must not swallow a real upstream drift. A pod still pinned to
// 127.0.0.53 whose external upstream ALSO differs from the host's is
// stale on two counts — suspecting the loopback risk alone leaves the
// wrong upstream serving. The drift verdict now outranks the suspect.
func TestDNST9StubWithUpstreamDriftStillKills(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 910,
		t9DNSConf("nameserver 1.1.1.1"), "nameserver 127.0.0.53\nnameserver 8.8.8.8\n", 2)
	if len(e.Kills) != 1 || e.Kills[0].PID != 910 {
		t.Fatalf("kills=%v want one SIGKILL of 910 (stub + upstream drift)", e.Kills)
	}
	if strings.Contains(e.LogLines(t), "suspect: dns-resolv systemd stub in DNS pod") {
		t.Fatalf("drifted T9 pod was only suspected:\n%s", e.LogLines(t))
	}
}

func TestDNSCRIFiltersLoopbackNoKill(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 903,
		t9DNSConf("nameserver 1.1.1.1"), "nameserver 1.1.1.1\n", 3)
	if len(e.Kills) != 0 {
		t.Fatalf("killed pause when CRI filtered the loopback stub: %v", e.Kills)
	}
}

// TestDNSHostNetworkSkipped: a hostNetwork DNS pod shares the host's
// resolv.conf, so a pod-vs-host difference is not drift.
func TestDNSHostNetworkSkipped(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("node-local-dns-abc12", wdepstest.UIDA)
	p.Spec.HostNetwork = true
	runDNS(t, e, p, wdepstest.UIDA, 904,
		"nameserver 10.96.0.10\n", "nameserver 8.8.8.8\n", 3)
	if len(e.Kills) != 0 {
		t.Fatalf("hostNetwork DNS pod pause killed: %v", e.Kills)
	}
}

// TestDNSDeletingPodSkipped: a terminating pod is already going away;
// piling a pause SIGKILL on it is both noisy and unsafe.
func TestDNSDeletingPodSkipped(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	now := metav1.Now()
	p.DeletionTimestamp = &now
	runDNS(t, e, p, wdepstest.UIDA, 905,
		"nameserver 10.96.0.10\n", "nameserver 8.8.8.8\n", 3)
	if len(e.Kills) != 0 {
		t.Fatalf("deleting DNS pod pause killed: %v", e.Kills)
	}
}

// TestDNSNoHostExternalNeverKills: the hard safety rail. A host with
// only the systemd-resolved stub (no usable upstream) cannot be used
// as a drift reference against a healthy DNS pod.
func TestDNSNoHostExternalNeverKills(t *testing.T) {
	e := fixture(t)
	p := *e.DNSPod("coredns-abc12-def34", wdepstest.UIDA)
	runDNS(t, e, p, wdepstest.UIDA, 906,
		"nameserver 127.0.0.53\nnameserver 127.0.0.1\n", "nameserver 8.8.8.8\n", 3)
	if len(e.Kills) != 0 {
		t.Fatalf("killed healthy DNS pod with no host external upstream: %v", e.Kills)
	}
}

// TestDNSResolvCacheKeyedByPausePID: a recreated sandbox (same UID,
// new pid) must re-inspect its resolv.conf instead of inheriting the
// dead pause's overflow verdict.
func TestDNSResolvCacheKeyedByPausePID(t *testing.T) {
	e := fixture(t)
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web-1", UID: wdepstest.UIDA},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	runDNS(t, e, p, wdepstest.UIDA, 907,
		"nameserver 1.1.1.1\n", "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\nnameserver 4.4.4.4\n", 1)
	if e.H.Series.PodDNSResolvOverflow != 1 {
		t.Fatalf("overflow=%d want 1", e.H.Series.PodDNSResolvOverflow)
	}
	// New pause pid, healthy resolv.conf: the cache key changes so the
	// stale overflow verdict is dropped on the next cycle.
	runDNS(t, e, p, wdepstest.UIDA, 908,
		"nameserver 1.1.1.1\n", "nameserver 1.1.1.1\n", 1)
	if e.H.Series.PodDNSResolvOverflow != 0 {
		t.Fatalf("overflow=%d want 0 after sandbox recreate", e.H.Series.PodDNSResolvOverflow)
	}
}
