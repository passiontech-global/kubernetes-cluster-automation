package pods_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestDNSResolvOverflowCachedAndEmitsEvent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web-1", UID: "uid-web-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	wdepstest.WriteFile(t, e.ResolvConf, "nameserver 1.1.1.1\n")

	pid := 401
	e.Live[pid] = true
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "401", "root", "etc", "resolv.conf"),
		"nameserver 10.96.0.10\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\nsearch a b c d e f g\n")

	chk := e.H.Check(wdeps.CheckDNS)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*pod},
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				"uid-web-1": {{Name: "pause", PID: pid, Live: true}},
			}, true
		},
	}
	chk.Run(context.Background(), ce)
	if e.H.Series.PodDNSResolvOverflow != 1 {
		t.Fatalf("PodDNSResolvOverflow = %d, want 1", e.H.Series.PodDNSResolvOverflow)
	}
	evs, err := e.CS.EventsV1().Events("app").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "PodDNSResolvOverflow" {
		t.Fatalf("expected 1 PodDNSResolvOverflow event, got %+v (err=%v)", evs.Items, err)
	}

	// Second cycle uses UID cache (no duplicate event, count stays 1).
	chk.Run(context.Background(), ce)
	evs, _ = e.CS.EventsV1().Events("app").List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("expected deduped 1 event on 2nd cycle, got %d", len(evs.Items))
	}
}

func TestDNSLoopbackHostAndPodBoth127_0_0_53(t *testing.T) {
	dnsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns-abc123-xyz", UID: "uid-dns-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, dnsPod)
	wdepstest.WriteFile(t, e.ResolvConf, "nameserver 127.0.0.53\n")

	pid := 402
	e.Live[pid] = true
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "402", "root", "etc", "resolv.conf"),
		"nameserver 127.0.0.53\n")

	chk := e.H.Check(wdeps.CheckDNS)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         []corev1.Pod{*dnsPod},
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				"uid-dns-1": {{Name: "pause", PID: pid, Live: true}},
			}, true
		},
	}
	chk.Run(context.Background(), ce)
	if len(e.Kills) != 0 {
		t.Fatalf("must not SIGKILL pause when host also points to 127.0.0.53: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "suspect: dns-resolv loopback") {
		t.Fatalf("missing suspect loopback log:\n%s", e.LogLines(t))
	}
	evs, err := e.CS.EventsV1().Events("kube-system").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "DNSLoopbackNameserver" {
		t.Fatalf("expected 1 DNSLoopbackNameserver event, got %+v (err=%v)", evs.Items, err)
	}
}
