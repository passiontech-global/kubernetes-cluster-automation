// regression_r31_test.go — R3.1 security regression tests for
// workerhygiene/ctr: spoofed containerd-shim rejection inside kubepods
// cgroup (runnable and D/Z), non-root UID rejection, empty cgroup,
// missing/unreadable cgroup or status (fail-closed + inconclusive abort).
package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR31SpoofedShimInKubepodsOrNonRootRejected(t *testing.T) {
	cases := []struct {
		name   string
		state  string
		cgroup string
		status string
		noCg   bool
		noSt   bool
	}{
		{
			name:   "runnable_in_kubepods",
			state:  "S",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/pod123.slice/app.scope\n",
			status: "Name:\tcontainerd-shim\nUid:\t0\t0\t0\t0\n",
		},
		{
			name:   "dz_in_kubepods",
			state:  "D",
			cgroup: "0::/kubepods.slice/kubepods-besteffort.slice/pod456.slice/app.scope\n",
			status: "Name:\tcontainerd-shim\nUid:\t0\t0\t0\t0\n",
		},
		{
			name:   "z_in_kubepods",
			state:  "Z",
			cgroup: "0::/kubepods.slice/pod789.slice/app.scope\n",
			status: "Name:\tcontainerd-shim\nUid:\t0\t0\t0\t0\n",
		},
		{
			name:   "non_root_uid",
			state:  "S",
			cgroup: "0::/system.slice/containerd.service\n",
			status: "Name:\tcontainerd-shim\nUid:\t1000\t1000\t1000\t1000\n",
		},
		{
			name:   "non_root_euid",
			state:  "S",
			cgroup: "0::/system.slice/containerd.service\n",
			status: "Name:\tcontainerd-shim\nUid:\t0\t1000\t0\t1000\n",
		},
		{
			name:   "empty_cgroup",
			state:  "S",
			cgroup: "\n",
			status: "Name:\tcontainerd-shim\nUid:\t0\t0\t0\t0\n",
		},
		{
			name:   "missing_cgroup",
			state:  "S",
			noCg:   true,
			status: "Name:\tcontainerd-shim\nUid:\t0\t0\t0\t0\n",
		},
		{
			name:   "missing_status",
			state:  "S",
			cgroup: "0::/system.slice/containerd.service\n",
			noSt:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			sid := strings.Repeat("a", 64)
			const pid = 9800
			e.MkStatProc(t, pid, "containerd-shim", tc.state, "")
			if tc.state == "D" || tc.state == "Z" {
				fdDir := filepath.Join(e.ProcDir, "9800", "fd")
				if err := os.MkdirAll(fdDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(e.CtrDir, sid, "log.json")+" (deleted)",
					filepath.Join(fdDir, "3")); err != nil {
					t.Fatal(err)
				}
			} else {
				wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9800", "cmdline"),
					"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
						"\x00-address\x00/run/k0s/containerd.sock\x00")
			}
			if !tc.noCg {
				wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9800", "cgroup"), tc.cgroup)
			}
			if !tc.noSt {
				wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9800", "status"), tc.status)
			}
			old := e.Now.Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(e.ProcDir, "9800"), old, old); err != nil {
				t.Fatal(err)
			}

			// Also seed a confirmed orphan sandbox matching sid: a spoofed shim
			// must NOT populate shimIDs[sid] to block sandbox reaping.
			sbDir := filepath.Join(e.SbDir, sid)
			if err := os.MkdirAll(sbDir, 0o755); err != nil {
				t.Fatal(err)
			}
			oldSB := e.Now.Add(-45 * time.Minute)
			if err := os.Chtimes(sbDir, oldSB, oldSB); err != nil {
				t.Fatal(err)
			}
			wdepstest.WriteFile(t, filepath.Join(e.StateDir, "sandbox-orphan-seen-"+sid),
				"1\n")

			e.H.Cycle(context.Background())

			if len(e.Kills) != 0 {
				t.Fatalf("spoofed shim SIGKILLed: %+v", e.Kills)
			}
			if e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
				t.Fatal("spoofed shim triggered LatchPodTeardownWedged")
			}
			if _, err := os.Stat(sbDir); !os.IsNotExist(err) {
				t.Fatalf("spoofed shim pinned shimIDs and blocked sandbox reaper: err=%v", err)
			}
		})
	}
}

func TestR31UnreadableCgroupOrStatusMarksInconclusive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	for _, target := range []string{"cgroup", "status"} {
		t.Run("unreadable_"+target, func(t *testing.T) {
			e := fixture(t)
			sid := strings.Repeat("b", 64)
			e.MkStatProc(t, 9801, "containerd-shim", "S", "")
			wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9801", "cmdline"),
				"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
					"\x00-address\x00/run/k0s/containerd.sock\x00")
			seedHostRootShim(t, e, 9801)
			old := e.Now.Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(e.ProcDir, "9801"), old, old); err != nil {
				t.Fatal(err)
			}

			// Pre-arm latch and orphan sandbox to verify inconclusive scan
			// preserves both and aborts.
			e.H.State.EnterFrom(latchdefs.LatchPodTeardownWedged, wdeps.CheckCtrTasks, "prior")
			sbDir := filepath.Join(e.SbDir, sid)
			if err := os.MkdirAll(sbDir, 0o755); err != nil {
				t.Fatal(err)
			}
			oldSB := e.Now.Add(-45 * time.Minute)
			if err := os.Chtimes(sbDir, oldSB, oldSB); err != nil {
				t.Fatal(err)
			}
			wdepstest.WriteFile(t, filepath.Join(e.StateDir, "sandbox-orphan-seen-"+sid), "1\n")

			targetPath := filepath.Join(e.ProcDir, "9801", target)
			if err := os.Chmod(targetPath, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(targetPath, 0o644) })

			e.H.Check(wdeps.CheckCtrTasks).Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				PidsOnce:     func() []int { return []int{9801} },
				PidsOK:       func() bool { return true },
			})

			if len(e.Kills) != 0 {
				t.Fatalf("killed shim despite unreadable %s: %+v", target, e.Kills)
			}
			if !e.H.State.Exists(latchdefs.LatchPodTeardownWedged) {
				t.Fatalf("latch released on unreadable %s", target)
			}
			if _, err := os.Stat(sbDir); err != nil {
				t.Fatalf("sandbox dir reaped on inconclusive %s: %v", target, err)
			}
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCtrTasks, "abort")); got != 1 {
				t.Fatalf("abort=%v want 1", got)
			}
		})
	}
}
