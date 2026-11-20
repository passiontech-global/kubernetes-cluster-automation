package wdeps_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR10BuildTaskMapInitPidUnreadableMarksIncomplete(t *testing.T) {
	t.Run("EACCES_0000_marks_incomplete", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.MkTask(t, wdepstest.UIDA, "app", 400)
		initPid := filepath.Join(e.CtrDir, "task-app-"+wdepstest.UIDA[:8], "init.pid")
		if err := os.Chmod(initPid, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(initPid, 0o644) })

		tasks, complete := e.D.BuildTaskMap()
		if complete {
			t.Fatalf("BuildTaskMap returned complete=true (CountLive=%d) when init.pid had EACCES",
				wdeps.CountLive(tasks[wdepstest.UIDA]))
		}
		if !strings.Contains(e.LogLines(t), "init.pid unreadable") {
			t.Fatalf("missing suspect log:\n%s", e.LogLines(t))
		}

		// Recovery: chmod 0644 -> complete=true and live task detected.
		if err := os.Chmod(initPid, 0o644); err != nil {
			t.Fatal(err)
		}
		e.Live[400] = true
		tasks, complete = e.D.BuildTaskMap()
		if !complete || wdeps.CountLive(tasks[wdepstest.UIDA]) != 1 {
			t.Fatalf("recovered complete=%v live=%d want true/1",
				complete, wdeps.CountLive(tasks[wdepstest.UIDA]))
		}
	})

	t.Run("EISDIR_marks_incomplete", func(t *testing.T) {
		e := fixture(t)
		taskDir := filepath.Join(e.CtrDir, "task-init-dir")
		wdepstest.WriteFile(t, filepath.Join(taskDir, "config.json"),
			`{"annotations":{"io.kubernetes.pod.uid":"`+wdepstest.UIDB+`"}}`)
		if err := os.MkdirAll(filepath.Join(taskDir, "init.pid"), 0o755); err != nil {
			t.Fatal(err)
		}

		_, complete := e.D.BuildTaskMap()
		if complete {
			t.Fatal("BuildTaskMap returned complete=true when init.pid was a directory (EISDIR)")
		}
	})

	t.Run("ENOENT_remains_complete", func(t *testing.T) {
		e := fixture(t)
		taskDir := filepath.Join(e.CtrDir, "task-exited")
		wdepstest.WriteFile(t, filepath.Join(taskDir, "config.json"),
			`{"annotations":{"io.kubernetes.pod.uid":"`+wdepstest.UIDC+`"}}`)

		tasks, complete := e.D.BuildTaskMap()
		if !complete {
			t.Fatal("BuildTaskMap returned complete=false on benign ENOENT init.pid")
		}
		if wdeps.CountLive(tasks[wdepstest.UIDC]) != 0 {
			t.Fatalf("CountLive=%d want 0", wdeps.CountLive(tasks[wdepstest.UIDC]))
		}
	})
}
