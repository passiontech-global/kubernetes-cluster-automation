package wdeps_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestBuildTaskMapConfigJSONUnreadableMarksIncomplete(t *testing.T) {
	t.Run("EACCES_0000_marks_incomplete", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.Live[400] = true
		e.MkTask(t, wdepstest.UIDA, "app", 400)
		lockedCfg := filepath.Join(e.CtrDir, "task-locked", "config.json")
		wdepstest.WriteFile(t, lockedCfg, `{"annotations":{"io.kubernetes.pod.uid":"`+wdepstest.UIDB+`"}}`)
		if err := os.Chmod(lockedCfg, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(lockedCfg, 0o644) })

		_, complete := e.D.BuildTaskMap()
		if complete {
			t.Fatal("BuildTaskMap returned complete=true when task config.json had EACCES")
		}
		if !strings.Contains(e.LogLines(t), "config.json unreadable") {
			t.Fatalf("missing suspect log:\n%s", e.LogLines(t))
		}
	})

	t.Run("EISDIR_marks_incomplete", func(t *testing.T) {
		e := fixture(t)
		badCfgDir := filepath.Join(e.CtrDir, "task-dir-cfg", "config.json")
		if err := os.MkdirAll(badCfgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, complete := e.D.BuildTaskMap()
		if complete {
			t.Fatal("BuildTaskMap returned complete=true when task config.json was a directory (EISDIR)")
		}
	})

	t.Run("ENOENT_remains_complete", func(t *testing.T) {
		e := fixture(t)
		wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "task-exited", "init.pid"), "401\n")
		_, complete := e.D.BuildTaskMap()
		if !complete {
			t.Fatal("BuildTaskMap returned complete=false on benign ENOENT config.json")
		}
	})
}

func TestWdepsDeletePodNilClientAndNilDeletionTimestampNoPanic(t *testing.T) {
	e := fixture(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "default",
			UID:       types.UID(wdepstest.UIDA),
		},
	}

	// Valid client + nil DeletionTimestamp must not panic.
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.D.ForceDeletePod(context.Background(), pod); err != nil {
		t.Fatalf("ForceDeletePod with nil DeletionTimestamp: %v", err)
	}

	// Nil Client must return error and not panic or log POD-TEARDOWN-FORCE-DELETE.
	e2 := fixture(t)
	e2.D.Cfg.Client = nil
	if err := e2.D.ForceDeletePod(context.Background(), pod); err == nil {
		t.Fatal("ForceDeletePod with Client=nil expected error")
	}
	if strings.Contains(e2.LogLines(t), "POD-TEARDOWN-FORCE-DELETE") {
		t.Fatalf("unexpected POD-TEARDOWN-FORCE-DELETE log when Client=nil:\n%s", e2.LogLines(t))
	}
	if err := e2.D.DeletePodGraceful(context.Background(), pod); err == nil {
		t.Fatal("DeletePodGraceful with Client=nil expected error")
	}
	var nilDeps *wdeps.Deps
	if err := nilDeps.ForceDeletePod(context.Background(), pod); err == nil {
		t.Fatal("nil Deps ForceDeletePod expected error")
	}
	if err := nilDeps.DeletePodGraceful(context.Background(), pod); err == nil {
		t.Fatal("nil Deps DeletePodGraceful expected error")
	}
}
