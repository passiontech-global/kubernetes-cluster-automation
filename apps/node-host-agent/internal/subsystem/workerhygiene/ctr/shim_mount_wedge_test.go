// shim_mount_wedge_test.go — table-driven and scenario tests for K3
// containerd-shim EBUSY mount-namespace wedge detection & remediation.
package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func setupPinningProc(t *testing.T, e *env, pid int, comm, state, cgroup, uidLine string, fdTarget, procMountLine string) {
	t.Helper()
	e.MkStatProc(t, pid, comm, state, "")
	pdir := filepath.Join(e.ProcDir, strconv.Itoa(pid))
	wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"), cgroup)
	wdepstest.WriteFile(t, filepath.Join(pdir, "status"), "Name:\t"+comm+"\n"+uidLine)
	if procMountLine != "" {
		wdepstest.WriteFile(t, filepath.Join(pdir, "mountinfo"), procMountLine)
	}
	fdDir := filepath.Join(pdir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if fdTarget != "" {
		if err := os.Symlink(fdTarget, filepath.Join(fdDir, "4")); err != nil {
			t.Fatal(err)
		}
	}
}

func runMountinfoCycle(e *env, apiOK bool, pods ...corev1.Pod) {
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        apiOK,
		Pods:         pods,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{}, true
		},
	})
}

func TestShimMountWedgeScenarios(t *testing.T) {
	t.Run("confirmed_dead_pod_mount_remediated_and_recovery_clears_latch", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 2
		e.SDReply["umount"] = ""

		deadMount := filepath.Join(e.KubepodsDir, "dead-pod-1", "volumes", "kubernetes.io~empty-dir", "cache")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41001, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))

		// Cycle 1: below ConsecNeeded (2) -> suspect only, no ebusy, no umount, no latch.
		runMountinfoCycle(e, true)
		if e.SDRan("umount") {
			t.Fatal("umount ran before ConsecNeeded cycles")
		}
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("latch entered before ConsecNeeded cycles")
		}
		if strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") {
			t.Fatalf("ebusy logged before ConsecNeeded:\n%s", e.LogLines(t))
		}

		// Cycle 2: confirmed -> enters latch, runs umount -l, logs EBUSY.
		runMountinfoCycle(e, true)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("expected LatchPodTeardownWedged after ConsecNeeded cycles")
		}
		if !e.SDRan("umount") {
			t.Fatal("expected umount -l on confirmed host-root shim EBUSY wedge")
		}
		if len(e.Kills) != 0 {
			t.Fatalf("unexpected SIGKILL when umount -l succeeded: %v", e.Kills)
		}
		if !strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") {
			t.Fatalf("expected EBUSY log:\n%s", e.LogLines(t))
		}

		// Recovery: mountinfo clears -> resets streak and releases LatchPodTeardownWedged.
		writeMountinfo(t, e, nil)
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "41001"))
		runMountinfoCycle(e, true)
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("expected LatchPodTeardownWedged cleared on recovery")
		}
	})

	t.Run("umount_failure_falls_back_to_sigkill_for_host_root_shim", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		// Leaving e.SDReply["umount"] unset makes sdRun return ENOENT.

		deadMount := filepath.Join(e.KubepodsDir, "dead-pod-kill", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41002, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))

		runMountinfoCycle(e, true)
		if len(e.Kills) != 1 || e.Kills[0].PID != 41002 {
			t.Fatalf("Kills = %v, want PID 41002 fallback SIGKILL when umount fails", e.Kills)
		}
		if v := promtest.ToFloat64(e.H.Actions.WithLabelValues(wdeps.CheckMountinfo, "ebusy_shim_kill")); v != 1 {
			t.Fatalf("ebusy_shim_kill action count = %v, want 1", v)
		}
	})

	t.Run("live_pod_mount_and_unpinned_dead_mount_untouched", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		e.SDReply["umount"] = ""

		liveUID := wdepstest.UIDA
		livePod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "default", UID: types.UID(liveUID)},
		}
		liveMount := filepath.Join(e.KubepodsDir, liveUID, "volumes", "kubernetes.io~empty-dir", "data")
		unpinnedDeadMount := filepath.Join(e.KubepodsDir, "dead-unpinned", "volumes", "kubernetes.io~empty-dir", "cache")
		writeMountinfo(t, e, []string{miLine(liveMount), miLine(unpinnedDeadMount)})

		// Shim pins only liveMount.
		setupPinningProc(t, e, 41003, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			liveMount, miLine(liveMount))

		runMountinfoCycle(e, true, livePod)
		runMountinfoCycle(e, true, livePod)
		if e.SDRan("umount") || len(e.Kills) != 0 {
			t.Fatalf("live or unpinned mount touched: umount=%v killed=%v", e.SDRan("umount"), e.Kills)
		}
		if strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") {
			t.Fatalf("unexpected ebusy log:\n%s", e.LogLines(t))
		}
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("unexpected latch for live/unpinned mounts")
		}
	})

	t.Run("octal_040_escaped_mount_path_decoded", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		e.SDReply["umount"] = ""

		deadMount := filepath.Join(e.KubepodsDir, "dead-octal", "volumes", "kubernetes.io~empty-dir", "my dir")
		escaped := strings.ReplaceAll(deadMount, " ", `\040`)
		writeMountinfo(t, e, []string{miLine(escaped)})
		setupPinningProc(t, e, 41004, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(escaped))

		runMountinfoCycle(e, true)
		if !e.SDRan("umount") {
			t.Fatal("expected umount -l for octal-escaped dead mount")
		}
		if !strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") {
			t.Fatalf("expected ebusy log for octal-escaped dead mount:\n%s", e.LogLines(t))
		}
	})

	t.Run("dstate_shim_escalates_without_reading_cmdline_or_sigkill", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		e.SDReply["umount"] = ""

		deadMount := filepath.Join(e.KubepodsDir, "dead-dstate", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41005, "containerd-shim", "D",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))
		// Make cmdline unreadable (000) to verify D-state path never opens cmdline.
		cmdlinePath := filepath.Join(e.ProcDir, "41005", "cmdline")
		wdepstest.WriteFile(t, cmdlinePath, "containerd-shim-runc-v2")
		if err := os.Chmod(cmdlinePath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cmdlinePath, 0o644) })

		runMountinfoCycle(e, true)
		if len(e.Kills) != 0 {
			t.Fatalf("D-state shim must never be SIGKILLed: %v", e.Kills)
		}
		if e.SDRan("umount") {
			t.Fatalf("D-state shim escalation should not run umount")
		}
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("expected LatchPodTeardownWedged for D-state shim")
		}
		if !strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") {
			t.Fatalf("expected EBUSY log for D-state shim:\n%s", e.LogLines(t))
		}
	})

	t.Run("spoofed_kubepods_nonroot_pid_never_sigkilled", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		// Leave e.SDReply["umount"] unset so umount fails; anti-spoof must still block SIGKILL.

		deadMount := filepath.Join(e.KubepodsDir, "dead-spoof", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41006, "containerd-shim", "S",
			"0::/kubepods.slice/kubepods-pod123.slice/cri-containerd-spoof.scope\n",
			"Uid:\t1000\t1000\t1000\t1000\n",
			deadMount, miLine(deadMount))

		runMountinfoCycle(e, true)
		if len(e.Kills) != 0 {
			t.Fatalf("spoofed kubepods/non-root PID was SIGKILLed: %v", e.Kills)
		}
		if !strings.Contains(e.LogLines(t), "shim kill refused") {
			t.Fatalf("expected anti-spoof refusal log:\n%s", e.LogLines(t))
		}
	})

	t.Run("api_unreachable_and_maintenance_hold_suppress_destructive_heal", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			apiOK bool
			held  bool
		}{
			{name: "api_unreachable", apiOK: false, held: false},
			{name: "maintenance_hold", apiOK: true, held: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := fixture(t)
				e.H.Cfg.ConsecNeeded = 1
				if tc.held {
					e.H.Cfg.Coord = &nodecoord.Coord{
						Now: func() time.Time { return e.Now },
						GetAnnos: func(context.Context) (map[string]string, error) {
							return map[string]string{
								nodecond.AnnoClusterMaintenanceUntil: e.Now.Add(time.Hour).UTC().Format(time.RFC3339),
							}, nil
						},
					}
				}
				deadMount := filepath.Join(e.KubepodsDir, "dead-hold", "volumes", "kubernetes.io~empty-dir", "c")
				writeMountinfo(t, e, []string{miLine(deadMount)})
				setupPinningProc(t, e, 41007, "containerd-shim", "S",
					"0::/system.slice/k0sworker.service\n",
					"Uid:\t0\t0\t0\t0\n",
					deadMount, miLine(deadMount))

				runMountinfoCycle(e, tc.apiOK)
				if e.SDRan("umount") || len(e.Kills) != 0 {
					t.Fatalf("%s failed to suppress destructive action: umount=%v killed=%v",
						tc.name, e.SDRan("umount"), e.Kills)
				}
			})
		}
	})

	t.Run("unreadable_proc_fd_fails_closed_preserving_latch_and_streak", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 2
		e.SDReply["umount"] = ""

		deadMount := filepath.Join(e.KubepodsDir, "dead-fd-err", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41008, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))

		// Confirm wedge across 2 cycles so latch is entered.
		runMountinfoCycle(e, true)
		runMountinfoCycle(e, true)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("expected latch to be active")
		}

		// Now remove pinning mountinfo/fd and make /proc/41008/fd unreadable (000).
		_ = os.Remove(filepath.Join(e.ProcDir, "41008", "mountinfo"))
		fdDir := filepath.Join(e.ProcDir, "41008", "fd")
		if err := os.Chmod(fdDir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

		runMountinfoCycle(e, true)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("inconclusive /proc/<pid>/fd error must preserve LatchPodTeardownWedged")
		}
		if v := promtest.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckMountinfo, "abort")); v != 1 {
			t.Fatalf("abort cycles = %v, want 1", v)
		}
	})

	t.Run("shared_latch_preserved_while_pod_teardown_holds_it", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		e.SDReply["umount"] = ""

		// Both pod-teardown and mountinfo-hygiene enter the shared latch.
		e.H.State.EnterFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckTeardown, "stuck pod")
		deadMount := filepath.Join(e.KubepodsDir, "dead-shared", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})
		setupPinningProc(t, e, 41009, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))
		runMountinfoCycle(e, true)

		// Mountinfo recovers -> releases CheckMountinfo hold, but pod-teardown still holds it.
		writeMountinfo(t, e, nil)
		_ = os.RemoveAll(filepath.Join(e.ProcDir, "41009"))
		runMountinfoCycle(e, true)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("shared latch cleared while pod-teardown still holds it")
		}

		// Once pod-teardown also releases, latch clears.
		e.H.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckTeardown, nil)
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("shared latch stayed after all holders released")
		}
	})

	t.Run("post_restart_teardown_and_ctr_tasks_clear_preserves_mountinfo_hold", func(t *testing.T) {
		e := fixture(t)
		// Simulate post-restart: latch exists on disk from prior run,
		// no RAM holders entered yet; pod-teardown & ctr-tasks pass.
		wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-"+latchdefs.LatchPodTeardownWedged), "1\n")
		e.H.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckTeardown, nil)
		e.H.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckCtrTasks, nil)
		if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("shared latch cleared prematurely before mountinfo-hygiene reported")
		}
		// Once mountinfo-hygiene also reports healthy, the latch clears.
		e.H.State.ExitFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckMountinfo, nil)
		if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
			t.Fatal("shared latch stayed after mountinfo-hygiene also released")
		}
	})
}

func TestShimMountWedgePID1Skipped(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.ConsecNeeded = 1
	deadMount := filepath.Join(e.KubepodsDir, "dead-pid1", "volumes", "kubernetes.io~empty-dir", "c")
	writeMountinfo(t, e, []string{miLine(deadMount)})
	// Even if PID 1 has stat & mountinfo, PID 1 must never be treated as a pinning shim.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "1", "stat"), "1 (containerd-shim) S 0 0 0")
	runMountinfoCycle(e, true)
	if strings.Contains(strings.ToLower(e.LogLines(t)), "ebusy") || e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
		t.Fatalf("PID 1 triggered K3 false positive:\n%s", e.LogLines(t))
	}
}

func TestShimMountWedgeMultiHolderFailedUmountAndPIDReuse(t *testing.T) {
	t.Run("failed_umount_on_non_shim_still_kills_subsequent_host_root_shim", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		// Leave e.SDReply["umount"] unset so umount -l fails.
		deadMount := filepath.Join(e.KubepodsDir, "dead-multi", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})

		// Lower PID: non-host-root process pinning deadMount (triggers umount -l first, which fails).
		setupPinningProc(t, e, 40001, "containerd-shim", "S",
			"0::/kubepods.slice/kubepods-pod123.slice/cri-containerd-spoof.scope\n",
			"Uid:\t1000\t1000\t1000\t1000\n",
			deadMount, miLine(deadMount))
		// Higher PID: real host-root containerd-shim pinning the SAME mount.
		setupPinningProc(t, e, 40002, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))

		runMountinfoCycle(e, true)
		if len(e.Kills) != 1 || e.Kills[0].PID != 40002 {
			t.Fatalf("Kills = %v, want SIGKILL on host-root shim PID 40002 after failed umount", e.Kills)
		}
	})

	t.Run("pid_reuse_during_hold_check_refuses_sigkill", func(t *testing.T) {
		e := fixture(t)
		e.H.Cfg.ConsecNeeded = 1
		deadMount := filepath.Join(e.KubepodsDir, "dead-reuse", "volumes", "kubernetes.io~empty-dir", "c")
		writeMountinfo(t, e, []string{miLine(deadMount)})

		// Write 22-field stat with starttime=12345 for PID 40010.
		fields1 := "40010 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0"
		setupPinningProc(t, e, 40010, "containerd-shim", "S",
			"0::/system.slice/k0sworker.service\n",
			"Uid:\t0\t0\t0\t0\n",
			deadMount, miLine(deadMount))
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "40010", "stat"), fields1)

		// Simulate PID reuse inside HoldLocalAction (same PID now has new starttime=99999).
		e.H.Cfg.Coord = &nodecoord.Coord{
			Now: func() time.Time { return e.Now },
			GetAnnos: func(context.Context) (map[string]string, error) {
				fields2 := "40010 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999 0 0"
				wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "40010", "stat"), fields2)
				return map[string]string{}, nil
			},
		}

		runMountinfoCycle(e, true)
		if len(e.Kills) != 0 {
			t.Fatalf("reused PID was SIGKILLed: %v", e.Kills)
		}
		if !strings.Contains(e.LogLines(t), "identity changed before kill") {
			t.Fatalf("expected identity-changed refusal log:\n%s", e.LogLines(t))
		}
	})
}
