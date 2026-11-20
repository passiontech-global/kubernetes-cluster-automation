package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestNetfilterGuardLockPathAndProcLocksErrorsPreserveLatch(t *testing.T) {
	armLatch := func(t *testing.T) (*env, string, int) {
		t.Helper()
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		e.H.Cfg.Wave2.NetfilterGuardLegacyProbe = false
		runDir := t.TempDir()
		lockPath := filepath.Join(runDir, "xtables.lock")
		if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(lockPath, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatalf("flock: %v", err)
		}
		e.H.Cfg.Disk.HostRunDir = runDir
		e.H.Cfg.Wave2.NetfilterGuardLockPath = ""
		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("setup: LatchNetfilterLocked not armed")
		}
		return e, runDir, fd
	}

	t.Run("HostRunDir_0000_preserves_latch_and_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, runDir, fd := armLatch(t)
		if err := os.Chmod(runDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(runDir, 0o755) })

		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		e.H.Check(wdeps.CheckNetfilterGuard).Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("LatchNetfilterLocked falsely exited when HostRunDir returned EACCES")
		}

		if err := os.Chmod(runDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = unix.Flock(fd, unix.LOCK_UN)
		e.H.Check(wdeps.CheckNetfilterGuard).Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("LatchNetfilterLocked did not exit after unlock")
		}
	})

	t.Run("HostRunDir_ENOTDIR_preserves_latch", func(t *testing.T) {
		e, _, _ := armLatch(t)
		badFile := filepath.Join(t.TempDir(), "notadir")
		wdepstest.WriteFile(t, badFile, "file")
		e.H.Cfg.Disk.HostRunDir = badFile

		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		e.H.Check(wdeps.CheckNetfilterGuard).Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("LatchNetfilterLocked falsely exited on HostRunDir ENOTDIR")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})

	t.Run("ProcLocks_0000_no_fallback_to_host_proc_locks", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
		e.H.Cfg.Wave2.NetfilterGuardLegacyProbe = false
		runDir := t.TempDir()
		lockPath := filepath.Join(runDir, "xtables.lock")
		wdepstest.WriteFile(t, lockPath, "")
		var st unix.Stat_t
		if err := unix.Stat(lockPath, &st); err != nil {
			t.Fatal(err)
		}
		target := fmt.Sprintf("%02x:%02x:%d", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
		locksPath := filepath.Join(e.ProcDir, "locks")
		wdepstest.WriteFile(t, locksPath, fmt.Sprintf("1: FLOCK ADVISORY WRITE 1234 %s 0 EOF\n", target))
		e.H.Cfg.Disk.HostRunDir = runDir

		chk := e.H.Check(wdeps.CheckNetfilterGuard)
		ce := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: func() []int { return nil }, PidsOK: func() bool { return true }}
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("setup: LatchNetfilterLocked not armed")
		}

		if err := os.Chmod(locksPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locksPath, 0o644) })
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchNetfilterLocked) {
			t.Fatal("LatchNetfilterLocked cleared via silent /proc/locks fallback when <ProcRoot>/locks returned EACCES")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetfilterGuard, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}

func TestGuardsNilClientDoesNotPanic(t *testing.T) {
	t.Run("SpegelCheck", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Client = nil
		sp := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "spegel-abcde",
				Namespace:         "spegel",
				UID:               types.UID(wdepstest.UIDA),
				CreationTimestamp: metav1.NewTime(e.Now.Add(-10 * time.Minute)),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		chk := wdepstest.Check[*guards.SpegelCheck](e.H, wdeps.CheckSpegel)
		chk.Fails = e.H.Cfg.ConsecNeeded - 1
		chk.Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{sp},
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSpegel, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if _, err := os.Stat(filepath.Join(e.StateDir, "last-spegel-restart")); !os.IsNotExist(err) {
			t.Fatal("last-spegel-restart spent while Client==nil")
		}
	})

	t.Run("CalicoCheck", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Client = nil
		wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.SysClassNet, "cali123", "carrier"), "1\n")
		wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.SysClassNet, "wireguard.cali", "operstate"), "down\n")
		e.H.Cfg.Calico.FelixReadyURL = "http://127.0.0.1:9099/readiness"
		e.H.Cfg.Seams.Probe.ProbeHTTPStatus = func(context.Context, string, string, time.Duration) (int, error) {
			return 503, nil
		}
		felix := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-node-abc12",
				Namespace: "kube-system",
				UID:       types.UID(wdepstest.UIDB),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		chk := wdepstest.Check[*guards.CalicoCheck](e.H, wdeps.CheckCalico)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{felix}}
		for range 3 {
			chk.Run(context.Background(), ce)
		}
		if !strings.Contains(e.LogLines(t), "kubernetes client nil") {
			t.Fatalf("expected nil-client guard log:\n%s", e.LogLines(t))
		}
	})

	t.Run("PSIThrashCheck", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Client = nil
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "pressure", "memory"),
			"some avg10=50.00 avg60=50.00 avg300=50.00 total=100\n"+
				"full avg10=50.00 avg60=50.00 avg300=50.00 total=100\n")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "meminfo"),
			"MemTotal: 1000000 kB\nMemAvailable: 10000 kB\nSUnreclaim: 10000 kB\n")
		uid := wdepstest.UIDC
		cgRel := "kubepods.slice/kubepods-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice"
		wdepstest.WriteFile(t, filepath.Join(e.H.Cfg.Runtime.CgroupRoot, cgRel, "memory.current"),
			fmt.Sprintf("%d\n", 2<<30))
		e.MkStatProc(t, 5001, "hog", "S", "")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "5001", "cgroup"), "0::/"+cgRel+"/c.scope\n")
		victim := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "hog", Namespace: "default", UID: types.UID(uid),
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		chk := wdepstest.Check[*guards.PSIThrashCheck](e.H, wdeps.CheckPSIThrash)
		ce := &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{victim},
			PidsOnce:     func() []int { return []int{5001} },
			PidsOK:       func() bool { return true },
		}
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPSIThrash, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if _, err := os.Stat(filepath.Join(e.StateDir, "last-psi-evict")); !os.IsNotExist(err) {
			t.Fatal("last-psi-evict spent while Client==nil")
		}
	})
}
