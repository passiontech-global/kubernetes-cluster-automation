package pods_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10DNSResolvUnreadableConfAbortsPreservesLatch(t *testing.T) {
	t.Run("HostResolvConf_0000_and_recovery", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		p := *e.DNSPod("coredns-abc12-xyz34", wdepstest.UIDA)
		podConf := filepath.Join(e.ProcDir, "310", "root", "etc", "resolv.conf")
		wdepstest.WriteFile(t, e.ResolvConf, "nameserver 1.1.1.1\n")
		wdepstest.WriteFile(t, podConf, "nameserver 8.8.8.8\n")

		chk := e.H.Check(wdeps.CheckDNS)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{p},
			TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
				return map[string][]wdeps.CtrTask{
					wdepstest.UIDA: {{Name: "pause", PID: 310, Live: true}},
				}, true
			},
		}
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("setup: LatchDNSResolvStale not armed")
		}

		// chmod 0o000 HostResolvConf -> must abort and preserve LatchDNSResolvStale.
		if err := os.Chmod(e.ResolvConf, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.ResolvConf, 0o644) })
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDNS, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("LatchDNSResolvStale falsely exited when HostResolvConf returned 0o000")
		}

		// Recovery: restore permissions with matching nameservers -> exits latch cleanly.
		if err := os.Chmod(e.ResolvConf, 0o644); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, podConf, "nameserver 1.1.1.1\n")
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("LatchDNSResolvStale did not exit after recovery")
		}
	})

	t.Run("pod_resolv_conf_0000_aborts_and_preserves_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		p := *e.DNSPod("coredns-abc12-xyz35", wdepstest.UIDB)
		podConf := filepath.Join(e.ProcDir, "311", "root", "etc", "resolv.conf")
		wdepstest.WriteFile(t, e.ResolvConf, "nameserver 1.1.1.1\n")
		wdepstest.WriteFile(t, podConf, "nameserver 8.8.8.8\n")

		chk := e.H.Check(wdeps.CheckDNS)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{p},
			TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
				return map[string][]wdeps.CtrTask{
					wdepstest.UIDB: {{Name: "pause", PID: 311, Live: true}},
				}, true
			},
		}
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("setup: LatchDNSResolvStale not armed")
		}

		if err := os.Chmod(podConf, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(podConf, 0o644) })
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDNS, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("LatchDNSResolvStale falsely exited when pod resolv.conf returned 0o000")
		}

		if err := os.Chmod(podConf, 0o644); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, podConf, "nameserver 1.1.1.1\n")
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchDNSResolvStale) {
			t.Fatal("LatchDNSResolvStale did not exit after pod resolv.conf recovery")
		}
	})
}
