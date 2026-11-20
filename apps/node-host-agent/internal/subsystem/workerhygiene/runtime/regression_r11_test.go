package runtime_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR11InotifyStaleCacheWithinTTLPreservesLatchAndRecovers(t *testing.T) {
	t.Run("lastScanAborted_bypasses_SharedFDCache_within_TTL", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		// Transient EACCES at t+65s populates SharedFDCache with empty Inotify and aborts.
		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure exited on abort")
		}

		// Permissions recover within inotifyFDTTL (+15s < 60s) while leak persists -> MUST NOT exit!
		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(15 * time.Second)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited within inotifyFDTTL while PID 4001 leak persisted")
		}

		// Genuine recovery when leak actually drops -> exits cleanly via direct scan.
		mkInotifyPID(t, e, 4001, 0, 0, "")
		e.Now = e.Now.Add(15 * time.Second)
		inotifyRun(e, 1, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit after leak actually dropped")
		}
	})

	t.Run("hostmetrics_poisoned_cache_before_exit_verified_directly", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		// Simulate hostmetrics calling SharedFDCache during a 1s EACCES blip after TTL expiry:
		// fdcache.Snapshot must NOT cache the Partial snapshot, so once permissions recover at t=80s
		// SharedFDCache refreshes cleanly and caches the valid 100% snapshot for [80s, 140s).
		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
		e.Now = e.Now.Add(65 * time.Second)
		eaccesSnap := procfs.SharedFDCache(e.ProcDir, func() time.Time { return e.Now }).Snapshot(60 * time.Second)
		if !eaccesSnap.ProcOK || !eaccesSnap.Partial || len(eaccesSnap.Inotify) != 0 {
			t.Fatalf("t=65s EACCES snap = %+v, want ProcOK=true Partial=true Inotify=0", eaccesSnap)
		}

		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(15 * time.Second) // t=80s (+15s < 60s after t=65s)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited at t=80s recovery")
		}
		recoveredSnap := procfs.SharedFDCache(e.ProcDir, func() time.Time { return e.Now }).Snapshot(60 * time.Second)
		if recoveredSnap.Partial || len(recoveredSnap.Inotify) != 10 || !recoveredSnap.At.Equal(e.Now) {
			t.Fatalf("t=80s cached snap = %+v (At=%v want %v), want Partial=false len(Inotify)=10",
				recoveredSnap, recoveredSnap.At, e.Now)
		}

		// After PID 4001 exits, within t=80s's 60s TTL (t=95s < 140s), the valid t=80s cached
		// 100% snapshot keeps LatchInotifyPressure armed cleanly without aborting.
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "4001"))
		e.Now = e.Now.Add(15 * time.Second) // t=95s (+15s < 60s TTL since t=80s)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure exited prematurely within valid t=80s SharedFDCache TTL")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}

		// Once t=80s's 60s TTL expires (t=141s > 140s), SharedFDCache re-scans, observes PID 4001
		// exited (ENOENT), and exits LatchInotifyPressure cleanly.
		e.Now = e.Now.Add(46 * time.Second) // t=141s (+61s >= 60s TTL since t=80s)
		inotifyRun(e, 1, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit after t=80s SharedFDCache TTL expired and PID exited (ENOENT)")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}
	})

	t.Run("readlink_eacces_0444_fd_dir_aborts_preserves_latch_and_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0444 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		// 0o444 allows os.Open + Readdirnames(1) on /proc/4001/fd while os.Readlink
		// fails with EACCES -> ScanFDs marks snap.Partial=true. Must abort and
		// preserve LatchInotifyPressure (no STATE-EXIT).
		fdDir := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fdDir, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited on /proc/4001/fd 0o444 (snap.Partial=true)")
		}
		if logBytes, err := os.ReadFile(e.H.Cfg.WatchdogLogFile); err == nil {
			if strings.Contains(string(logBytes), "STATE-EXIT: inotify-pressure") {
				t.Fatalf("unexpected STATE-EXIT in watchdog log:\n%s", logBytes)
			}
		}

		// Restore 0o755 while leak persists -> latch remains armed.
		if err := os.Chmod(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(15 * time.Second)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure exited after 0o755 restore while leak persisted")
		}

		// Genuine recovery when leak drops -> exits latch cleanly.
		mkInotifyPID(t, e, 4001, 0, 0, "")
		e.Now = e.Now.Add(15 * time.Second)
		inotifyRun(e, 1, 4001)
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit after leak dropped")
		}
	})

	t.Run("unrelated_pid_partial_falls_back_to_CyclePIDs_cleanly", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0444 does not block root")
		}
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		// Unrelated PID 9999 outside e.PidsOnce has 0o444 fd/ (SharedFDCache returns Partial=true),
		// while PID 4001 recovered to 0 inotify FDs. Direct fallback ScanFDs([1, 4001]) must
		// succeed cleanly and release the latch without aborting.
		mkInotifyPID(t, e, 9999, 1, 1, "")
		fd9999 := filepath.Join(e.ProcDir, "9999", "fd")
		if err := os.Chmod(fd9999, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fd9999, 0o755) })
		mkInotifyPID(t, e, 4001, 0, 0, "")
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 0 {
			t.Fatalf("abort=%v want 0", got)
		}
		if inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure did not exit when only unrelated PID 9999 was Partial")
		}
	})

	t.Run("fdinfo_eisdir_direct_scan_aborts_via_Partial", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 10
		writeInotifySysctls(t, e, 10, 8192)
		mkInotifyPID(t, e, 1, 0, 0, "")
		mkInotifyPID(t, e, 4001, 10, 1, "")
		inotifyRun(e, 1, 4001)
		inotifyRun(e, 1, 4001)
		if !inotifyLatched(e) {
			t.Fatal("setup: LatchInotifyPressure not armed")
		}

		// Replace fdinfo/1 with a directory so os.Open succeeds while Read fails EISDIR ->
		// ScanFDs marks snap.Partial=true. Must abort and keep LatchInotifyPressure armed.
		fdinfo1 := filepath.Join(e.ProcDir, "4001", "fdinfo", "1")
		if err := os.Remove(fdinfo1); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(fdinfo1, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(65 * time.Second)
		inotifyRun(e, 1, 4001)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !inotifyLatched(e) {
			t.Fatal("LatchInotifyPressure falsely exited on fdinfo EISDIR (snap.Partial=true)")
		}
	})
}

func TestR11VMAPressureMultiCandidatePartialMaps0000(t *testing.T) {
	t.Run("PidsOK_false_aborts_and_preserves_ratio", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.Wave3.VMAMaxCeiling = 100
		if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")
		e.H.Series.VMAMaxUtilRatio = 0.90

		e.H.Check(wdeps.CheckCgroupThrottle).Run(context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			StatsOnce:    func() map[int]procfs.Stat { return nil },
			PidsOK:       func() bool { return false },
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if e.H.Series.VMAMaxUtilRatio != 0.90 {
			t.Fatalf("VMAMaxUtilRatio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
		}
	})

	t.Run("multi_pid_partial_maps_0000_preserves_ratio_and_evented", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vma-pod", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		e.H.Cfg.Wave3.VMAMaxCeiling = 100
		if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")

		writeMaps := func(pid, n int) string {
			pdir := filepath.Join(e.ProcDir, fmt.Sprint(pid))
			wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
				fmt.Sprintf("%d (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 %d 0\n", pid, 1<<30))
			var sb strings.Builder
			for i := range n {
				fmt.Fprintf(&sb, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
			}
			mp := filepath.Join(pdir, "maps")
			wdepstest.WriteFile(t, mp, sb.String())
			return mp
		}
		writeMaps(5002, 5)
		maps5001 := writeMaps(5001, 90)
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "5001", "cgroup"),
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
				strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-c1.scope\n")

		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		chk := e.H.Check(wdeps.CheckCgroupThrottle)
		chk.Run(context.Background(), ce)
		if e.H.Series.VMAMaxUtilRatio != 0.9 {
			t.Fatalf("setup VMAMaxUtilRatio=%v want 0.9", e.H.Series.VMAMaxUtilRatio)
		}
		evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "PodVMAMapCountPressure" {
			t.Fatalf("setup events=%+v err=%v", evs.Items, err)
		}

		// PID 5001 maps 0o000 while PID 5002 remains readable -> must abort and preserve ratio & vmaEvented.
		if err := os.Chmod(maps5001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(maps5001, 0o644) })
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if e.H.Series.VMAMaxUtilRatio != 0.9 {
			t.Fatalf("VMAMaxUtilRatio clobbered=%v want 0.9", e.H.Series.VMAMaxUtilRatio)
		}

		// Restore permissions (still 90 VMAs) -> no duplicate event!
		if err := os.Chmod(maps5001, 0o644); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), ce)
		evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 {
			t.Fatalf("events=%d want 1 (vmaEvented was wiped)", len(evs.Items))
		}

		// Exited PID 5001 (ENOENT) updates ratio cleanly to 0.05 (PID 5002).
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "5001"))
		chk.Run(context.Background(), ce)
		if e.H.Series.VMAMaxUtilRatio != 0.05 {
			t.Fatalf("recovered VMAMaxUtilRatio=%v want 0.05", e.H.Series.VMAMaxUtilRatio)
		}
	})
}

func TestR11EphemeralPortsPartialProcUnreadablePreservesMarkerAndLatch(t *testing.T) {
	const tcpStateCloseWait = 8
	setupTwoPods := func(t *testing.T) (*env, *corev1.Pod, *corev1.Pod, string) {
		t.Helper()
		isCtrl := true
		podA := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "leaker-a", UID: types.UID(wdepstest.UIDA),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-1", Controller: &isCtrl,
			}},
		}}
		podB := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "other-b", UID: types.UID(wdepstest.UIDB),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs2", UID: "rs-2", Controller: &isCtrl,
			}},
		}}
		e := fixture(t, podA, podB)
		e.H.Cfg.Wave2.PortEvictRunawayPod = true
		e.H.Cfg.Wave2.PortLeakMinPct = 50
		e.H.Cfg.Wave2.PortLeakWindowSec = 120
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "net", "ipv4", "ip_local_port_range"), "32768 33767\n")

		mkNS := func(pid int, ino string) {
			nsDir := filepath.Join(e.ProcDir, fmt.Sprint(pid), "ns")
			if err := os.MkdirAll(nsDir, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = os.Symlink("net:["+ino+"]", filepath.Join(nsDir, "net"))
		}
		mkNS(1, "1001")
		mkNS(4001, "4001")
		mkNS(4002, "4002")

		// PID 1 has 1 CLOSE_WAIT socket (inode 1), PID 4002 has 1 CLOSE_WAIT socket (inode 2),
		// PID 4001 has 1200 CLOSE_WAIT sockets (inodes 90000..91199).
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "1", "net", "tcp"),
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 0100007F:1F90 0100007F:C350 08 00000000:00000000 00:00000000 00000000 0 0 1 1 00000000 0\n")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4002", "net", "tcp"),
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 0100007F:1F90 0100007F:C350 08 00000000:00000000 00:00000000 00000000 0 0 2 1 00000000 0\n")
		fd4002 := filepath.Join(e.ProcDir, "4002", "fd")
		if err := os.MkdirAll(fd4002, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Symlink("socket:[2]", filepath.Join(fd4002, "3"))
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4002", "cgroup"),
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
				strings.ReplaceAll(wdepstest.UIDB, "-", "_")+".slice/cri-containerd-b.scope\n")

		var tcpBuf strings.Builder
		tcpBuf.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
		fd4001 := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.MkdirAll(fd4001, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range 1200 {
			inode := 90000 + i
			fmt.Fprintf(&tcpBuf, "%4d: 0100007F:1F90 0100007F:C350 08 00000000:00000000 00:00000000 00000000 0 0 %d 1 00000000 0\n", i, inode)
			_ = os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fd4001, fmt.Sprint(i)))
		}
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4001", "net", "tcp"), tcpBuf.String())
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4001", "cgroup"),
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+
				strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-a.scope\n")

		e.H.Cfg.Seams.Host.TCPTablesFn = func(pid int) (netlinkx.TCPCensus, error) {
			if pid == 4001 {
				return netlinkx.TCPCensus{States: map[uint8]int{tcpStateCloseWait: 3000}}, nil
			}
			return netlinkx.TCPCensus{States: map[uint8]int{tcpStateCloseWait: 1}}, nil
		}
		markerPath := filepath.Join(e.StateDir, "port-leak-"+wdepstest.UIDA)
		return e, podA, podB, markerPath
	}

	t.Run("partial_net_tcp_0000_across_netns", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, podA, podB, markerPath := setupTwoPods(t)
		ce := &wdeps.CycleEnv{
			WorkerActive: true, APIOK: true,
			Pods:     []corev1.Pod{*podA, *podB},
			PidsOnce: func() []int { return []int{1, 4001, 4002} },
			PidsOK:   func() bool { return true },
		}
		chk := e.H.Check(wdeps.CheckEphemeralPorts)
		chk.Run(context.Background(), ce) // stamps port-leak-<UIDA>
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("setup marker missing: %v", err)
		}

		tcp4001 := filepath.Join(e.ProcDir, "4001", "net", "tcp")
		if err := os.Chmod(tcp4001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(tcp4001, 0o644) })
		e.Now = e.Now.Add(60 * time.Second)
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckEphemeralPorts, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("port-leak marker wiped under partial net/tcp 0o000: %v", err)
		}
	})

	t.Run("partial_pod_fd_0000_across_pods", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, podA, podB, markerPath := setupTwoPods(t)
		ce := &wdeps.CycleEnv{
			WorkerActive: true, APIOK: true,
			Pods:     []corev1.Pod{*podA, *podB},
			PidsOnce: func() []int { return []int{1, 4001, 4002} },
			PidsOK:   func() bool { return true },
		}
		chk := e.H.Check(wdeps.CheckEphemeralPorts)
		chk.Run(context.Background(), ce)

		fd4001 := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.Chmod(fd4001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fd4001, 0o755) })
		e.Now = e.Now.Add(60 * time.Second)
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckEphemeralPorts, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("port-leak marker wiped under partial pod fd 0o000: %v", err)
		}
	})

	t.Run("pod_ns_net_0000_aborts_and_enoent_recovers", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e, podA, podB, markerPath := setupTwoPods(t)
		ce := &wdeps.CycleEnv{
			WorkerActive: true, APIOK: true,
			Pods:     []corev1.Pod{*podA, *podB},
			PidsOnce: func() []int { return []int{1, 4001, 4002} },
			PidsOK:   func() bool { return true },
		}
		chk := e.H.Check(wdeps.CheckEphemeralPorts)
		chk.Run(context.Background(), ce)
		chk.Run(context.Background(), ce)
		if !e.H.State.Exists(latchdefs.LatchEphemeralPortPressure) {
			t.Fatal("setup: LatchEphemeralPortPressure not armed")
		}

		ns4001 := filepath.Join(e.ProcDir, "4001", "ns")
		if err := os.Chmod(ns4001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ns4001, 0o755) })
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckEphemeralPorts, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchEphemeralPortPressure) {
			t.Fatal("LatchEphemeralPortPressure falsely exited on /proc/4001/ns 0o000")
		}
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("port-leak marker wiped on /proc/4001/ns 0o000: %v", err)
		}

		// Exited PID (ENOENT) clears latch and prunes marker cleanly.
		_ = os.Chmod(ns4001, 0o755)
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "4001"))
		chk.Run(context.Background(), ce)
		if e.H.State.Exists(latchdefs.LatchEphemeralPortPressure) {
			t.Fatal("LatchEphemeralPortPressure did not exit after PID 4001 exited (ENOENT)")
		}
		if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
			t.Fatalf("stale port-leak marker not pruned after recovery: err=%v", err)
		}
	})
}

func TestR11CgroupThrottleBurstableScopeCPUStat0000PreservesCPUEvented(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "burstable", UID: types.UID(wdepstest.UIDB)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	sliceDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDB, "-", "_")+".slice")
	scopeDir := filepath.Join(sliceDir, "cri-containerd-app.scope")
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.pressure"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 0\n")
	// Pod-level cpu.stat stays readable with 0 throttling.
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "cpu.stat"), "nr_periods 100\nnr_throttled 0\n")
	scopeCPUStat := filepath.Join(scopeDir, "cpu.stat")
	procStatPath := filepath.Join(e.ProcDir, "stat")
	wdepstest.WriteFile(t, procStatPath, "cpu  0 0 0 0 0 0 0 0\n")
	wdepstest.WriteFile(t, scopeCPUStat, "nr_periods 100\nnr_throttled 0\n")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), ce) // baseline
	for i := 1; i <= 3; i++ {
		wdepstest.WriteFile(t, procStatPath, fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, scopeCPUStat, fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != "PodCPUCFSThrottled" {
		t.Fatalf("setup events=%+v err=%v", evs.Items, err)
	}

	// 1) scope/cpu.stat 0o000 while pod cpu.stat stays readable -> must abort and preserve cpuEvented.
	if err := os.Chmod(scopeCPUStat, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(scopeCPUStat, 0o644) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}

	// 2) scopeDir 0o000 while pod cpu.stat stays readable -> must ALSO abort and preserve cpuEvented.
	if err := os.Chmod(scopeCPUStat, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scopeDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(scopeDir, 0o755) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2", got)
	}

	// Restore permissions while throttling continues -> NO duplicate Event.
	if err := os.Chmod(scopeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 4; i <= 6; i++ {
		wdepstest.WriteFile(t, procStatPath, fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, scopeCPUStat, fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		chk.Run(context.Background(), ce)
	}
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("events=%d want 1 (cpuEvented wiped)", len(evs.Items))
	}

	// Deleted child scope (ENOENT) -> non-throttled ok cycle re-arms cpuEvented cleanly.
	_ = os.RemoveAll(scopeDir)
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupThrottle, "ok")); got == 0 {
		t.Fatal("expected ok cycle after child scope deleted")
	}
}

func TestR11CgroupThrottleAndVMAAPIOKFalseDefersEventsUntilRecovery(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api-blip", UID: types.UID(wdepstest.UIDA)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	e.H.Cfg.Wave3.VMAMaxCeiling = 100
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "max_map_count"), "100\n")

	sliceDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	if err := os.MkdirAll(sliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.pressure"),
		"some avg10=50.00 avg60=50.00 avg300=50.00 total=100\nfull avg10=50.00 avg60=50.00 avg300=50.00 total=100\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 10\n")
	procStatPath := filepath.Join(e.ProcDir, "stat")
	cpuStatPath := filepath.Join(sliceDir, "cpu.stat")
	wdepstest.WriteFile(t, procStatPath, "cpu  0 0 0 0 0 0 0 0\n")
	wdepstest.WriteFile(t, cpuStatPath, "nr_periods 100\nnr_throttled 0\n")

	pdir := filepath.Join(e.ProcDir, "5100")
	wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
		fmt.Sprintf("5100 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 %d 0\n", 1<<30))
	var mapsBuf strings.Builder
	for i := range 90 {
		fmt.Fprintf(&mapsBuf, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
	}
	wdepstest.WriteFile(t, filepath.Join(pdir, "maps"), mapsBuf.String())
	wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"),
		"0::/kubepods.slice/kubepods-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-c1.scope\n")

	chk := e.H.Check(wdeps.CheckCgroupThrottle)
	downEnv := &wdeps.CycleEnv{WorkerActive: true, APIOK: false}
	chk.Run(context.Background(), downEnv) // baseline memory.events & cpu.stat
	for i := 1; i <= 3; i++ {
		wdepstest.WriteFile(t, procStatPath, fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0\n", i*30, i*70))
		wdepstest.WriteFile(t, cpuStatPath, fmt.Sprintf("nr_periods %d\nnr_throttled %d\n", 100+i*100, i*80))
		wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), fmt.Sprintf("high %d\n", 10+i*5))
		chk.Run(context.Background(), downEnv)
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 0 {
		t.Fatalf("unexpected events while APIOK=false: %+v err=%v", evs.Items, err)
	}

	// API recovers while pressure persists -> all 3 Warning Events MUST be emitted!
	wdepstest.WriteFile(t, procStatPath, "cpu  120 0 0 280 0 0 0 0\n")
	wdepstest.WriteFile(t, cpuStatPath, "nr_periods 500\nnr_throttled 320\n")
	wdepstest.WriteFile(t, filepath.Join(sliceDir, "memory.events"), "high 30\n")
	upEnv := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk.Run(context.Background(), upEnv)
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]int{}
	for _, ev := range evs.Items {
		reasons[ev.Reason]++
	}
	for _, want := range []string{"PodMemoryHighThrottled", "PodCPUCFSThrottled", "PodVMAMapCountPressure"} {
		if reasons[want] != 1 {
			t.Fatalf("reason %s count=%d want 1 (all=%+v)", want, reasons[want], reasons)
		}
	}
}

func TestR11SystemdSessionFile0000AbortsPreservesLatchAndGauge(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	sessDir := t.TempDir()
	e.H.Cfg.Runtime.SessionsDir = sessDir
	old := e.Now.Add(-3 * time.Hour)
	var sessFiles []string
	for i := range 20 {
		p := filepath.Join(sessDir, fmt.Sprintf("c%d", i+1))
		wdepstest.WriteFile(t, p, "STATE=abandoned\n")
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
		sessFiles = append(sessFiles, p)
	}
	e.SDReply["Running"] = "running"

	chk := e.H.Check(wdeps.CheckSystemdSessions)
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
		t.Fatal("setup: LatchSystemdSessionBloat not armed")
	}
	if e.H.Series.SystemdSessionsStale != 20 {
		t.Fatalf("setup stale=%d want 20", e.H.Series.SystemdSessionsStale)
	}

	// chmod 0o000 one session file -> must abort, keep latch and SystemdSessionsStale=20.
	if err := os.Chmod(sessFiles[0], 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sessFiles[0], 0o644) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSystemdSessions, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
		t.Fatal("LatchSystemdSessionBloat falsely exited when session file returned 0o000")
	}
	if e.H.Series.SystemdSessionsStale != 20 {
		t.Fatalf("SystemdSessionsStale clobbered=%d want 20", e.H.Series.SystemdSessionsStale)
	}

	// Restore and clean stale sessions -> exits latch cleanly.
	if err := os.Chmod(sessFiles[0], 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range sessFiles {
		_ = os.Remove(p)
	}
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchSystemdSessionBloat) {
		t.Fatal("LatchSystemdSessionBloat did not exit after sessions cleared")
	}
	if e.H.Series.SystemdSessionsStale != 0 {
		t.Fatalf("recovered SystemdSessionsStale=%d want 0", e.H.Series.SystemdSessionsStale)
	}
}

func TestR11UnlinkedOpenFilesPartialProcFD0000PreservesGauges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.DiskUsed = 0.90
	e.MkStatProc(t, 1, "systemd", "S", "")
	if err := os.MkdirAll(filepath.Join(e.ProcDir, "1", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkStatProc(t, 4001, "fluent-bit", "S", "")
	e.mkDeletedFD(t, 4001, 3, "/var/log/a.log")
	e.stubDeletedFDStats(map[string]deletedStat{"4001:3": {dev: 1, ino: 10, size: mib(128)}})

	chk := e.H.Check(wdeps.CheckUnlinkedOpenFiles)
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{1, 4001} },
		PidsOK:       func() bool { return true },
	}
	chk.Run(context.Background(), ce)
	if e.H.UnlinkedOpenFileBytes != mib(128) || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("setup gauges=%d/%d want %d/1", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount, mib(128))
	}

	fdDir := filepath.Join(e.ProcDir, "4001", "fd")
	if err := os.Chmod(fdDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
	e.Now = e.Now.Add(e.H.Cfg.Disk.BloatScanInterval + time.Minute)
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive=%v want 1", got)
	}
	if e.H.UnlinkedOpenFileBytes != mib(128) || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("gauges clobbered=%d/%d want %d/1", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount, mib(128))
	}

	// Exited PID 4001 (ENOENT) updates gauges cleanly to 0/0.
	_ = os.Chmod(fdDir, 0o755)
	_ = os.RemoveAll(filepath.Join(e.ProcDir, "4001"))
	chk.Run(context.Background(), ce)
	if e.H.UnlinkedOpenFileBytes != 0 || e.H.UnlinkedOpenFileCount != 0 {
		t.Fatalf("recovered gauges=%d/%d want 0/0", e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount)
	}
}

func TestR11CgroupDyingPartialStat0000AbortsPreservesLatchAndGauge(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	cg := e.H.Cfg.Runtime.CgroupRoot
	wdepstest.WriteFile(t, filepath.Join(cg, "cgroup.stat"), "nr_dying_descendants 0\n")
	kpStat := filepath.Join(cg, "kubepods.slice", "cgroup.stat")
	wdepstest.WriteFile(t, kpStat, "nr_dying_descendants 6000\n")

	chk := e.H.Check(wdeps.CheckCgroupDying)
	ce := &wdeps.CycleEnv{WorkerActive: true}
	chk.Run(context.Background(), ce)
	chk.Run(context.Background(), ce)
	if !e.H.State.Exists(latchdefs.LatchCgroupDyingLeak) {
		t.Fatal("setup: LatchCgroupDyingLeak not armed")
	}
	if e.H.CgroupDyingDescendants != 6000 {
		t.Fatalf("setup dying=%d want 6000", e.H.CgroupDyingDescendants)
	}

	if err := os.Chmod(kpStat, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(kpStat, 0o644) })
	chk.Run(context.Background(), ce)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCgroupDying, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchCgroupDyingLeak) {
		t.Fatal("LatchCgroupDyingLeak falsely exited when kubepods.slice/cgroup.stat returned 0o000")
	}
	if e.H.CgroupDyingDescendants != 6000 {
		t.Fatalf("CgroupDyingDescendants clobbered=%d want 6000", e.H.CgroupDyingDescendants)
	}

	// Restore with 0 dying descendants -> exits latch cleanly.
	if err := os.Chmod(kpStat, 0o644); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, kpStat, "nr_dying_descendants 0\n")
	chk.Run(context.Background(), ce)
	if e.H.State.Exists(latchdefs.LatchCgroupDyingLeak) {
		t.Fatal("LatchCgroupDyingLeak did not exit after recovery")
	}
	if e.H.CgroupDyingDescendants != 0 {
		t.Fatalf("recovered dying=%d want 0", e.H.CgroupDyingDescendants)
	}
}

func TestR11ProactiveRuntimeAudit(t *testing.T) {
	t.Run("run_tmpfs_partial_proc_fd_0000_does_not_unlink_open_tmp", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.DiskUsed = 0.85
		runDir := t.TempDir()
		e.H.Cfg.Disk.HostRunDir = runDir
		tmpFile := filepath.Join(runDir, "spool.tmp")
		wdepstest.WriteFile(t, tmpFile, "data\n")
		old := e.Now.Add(-3 * time.Hour)
		if err := os.Chtimes(tmpFile, old, old); err != nil {
			t.Fatal(err)
		}

		// PID 1 readable, PID 4001 /proc/4001/fd 0o000 -> must NOT delete spool.tmp!
		if err := os.MkdirAll(filepath.Join(e.ProcDir, "1", "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		fd4001 := filepath.Join(e.ProcDir, "4001", "fd")
		if err := os.MkdirAll(fd4001, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fd4001, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fd4001, 0o755) })

		e.H.Check(wdeps.CheckRunTmpfs).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if _, err := os.Stat(tmpFile); err != nil {
			t.Fatalf("run_tmpfs deleted .tmp file while /proc/4001/fd returned 0o000: %v", err)
		}

		// Restoring fdDir (with PID 4001 holding no fds) past cooldown deletes unheld .tmp cleanly.
		if err := os.Chmod(fd4001, 0o755); err != nil {
			t.Fatal(err)
		}
		e.Now = e.Now.Add(20 * time.Minute)
		e.H.Check(wdeps.CheckRunTmpfs).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatalf("unheld stale .tmp not deleted after fd readability recovered: err=%v", err)
		}
	})

	t.Run("sa_token_ttl_token_0000_aborts_preserves_gauge", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		now := e.Now
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tok-pod", UID: types.UID(wdepstest.UIDA)},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		tokPath := filepath.Join(e.KubepodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~projected", "kube-api", "token")
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		pay := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, now.Unix()+100)))
		wdepstest.WriteFile(t, tokPath, hdr+"."+pay+".sig")

		chk := e.H.Check(wdeps.CheckSATokenTTL)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		chk.Run(context.Background(), ce)
		if e.H.SATokenMinTTLSec != 100 {
			t.Fatalf("setup SATokenMinTTLSec=%v want 100", e.H.SATokenMinTTLSec)
		}

		if err := os.Chmod(tokPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(tokPath, 0o644) })
		chk.Run(context.Background(), ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSATokenTTL, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if e.H.SATokenMinTTLSec != 100 {
			t.Fatalf("SATokenMinTTLSec clobbered=%v want 100", e.H.SATokenMinTTLSec)
		}

		// Restore with fresh TTL=1200 -> updates cleanly.
		if err := os.Chmod(tokPath, 0o644); err != nil {
			t.Fatal(err)
		}
		payFresh := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, now.Unix()+1200)))
		wdepstest.WriteFile(t, tokPath, hdr+"."+payFresh+".sig")
		chk.Run(context.Background(), ce)
		if e.H.SATokenMinTTLSec != 1200 {
			t.Fatalf("recovered SATokenMinTTLSec=%v want 1200", e.H.SATokenMinTTLSec)
		}
	})

	t.Run("disk_bloat_pods_dir_0000_aborts_preserves_latch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.DiskUsed = 0.90
		e.H.Cfg.Disk.BloatWatermark = 0.80
		e.H.State.Enter(latchdefs.LatchDiskBloat, "prior")
		if err := os.Chmod(e.KubepodsDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.KubepodsDir, 0o755) })

		chk := e.H.Check(wdeps.CheckDiskBloat)
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDiskBloat, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
		if !e.H.State.Exists(latchdefs.LatchDiskBloat) {
			t.Fatal("LatchDiskBloat falsely exited on PodsDir 0o000")
		}

		// Restore with 0 bloat (without advancing clock since lastScan wasn't stamped) -> exits cleanly.
		if err := os.Chmod(e.KubepodsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if e.H.State.Exists(latchdefs.LatchDiskBloat) {
			t.Fatal("LatchDiskBloat did not exit after PodsDir recovered")
		}
	})

	t.Run("localpv_quota_unreadable_root_aborts", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		prov := t.TempDir()
		e.H.Cfg.Disk.LocalPVQuotaDir = prov
		if err := os.Chmod(prov, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(prov, 0o755) })

		e.H.Check(wdeps.CheckLocalPVQuota).Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckLocalPVQuota, "abort")); got != 1 {
			t.Fatalf("abort=%v want 1", got)
		}
	})
}
