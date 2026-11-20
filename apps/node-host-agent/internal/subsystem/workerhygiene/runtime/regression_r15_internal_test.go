package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15ShimTaskIDStat0000NeverOpensFIFO(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	d, f := rtDeps(t)
	pdir := filepath.Join(f.ProcDir, "7210")
	statPath := filepath.Join(pdir, "stat")
	wdepstest.WriteFile(t, statPath,
		"7210 (containerd-shim) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
	cmdFIFO := filepath.Join(pdir, "cmdline")
	if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if fp, err := os.OpenFile(cmdFIFO, os.O_RDWR, 0); err == nil {
			_ = fp.Close()
		}
	})
	if err := os.Chmod(statPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })

	gotCh := make(chan string, 1)
	go func() {
		gotCh <- shimTaskID(d, 7210)
	}()
	select {
	case got := <-gotCh:
		if got != "unknown" {
			t.Fatalf("shimTaskID=%q want unknown", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("shimTaskID blocked opening FIFO cmdline on 0o000 stat")
	}

	// mkShim compatibility: ENOENT stat still reads cmdline and extracts -id.
	f.MkProc(t, 7211, "S", "", "")
	_ = os.Remove(filepath.Join(f.ProcDir, "7211", "stat"))
	wdepstest.WriteFile(t, filepath.Join(f.ProcDir, "7211", "cmdline"),
		"/var/lib/k0s/bin/containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00task-enoent\x00")
	if got := shimTaskID(d, 7211); got != "task-enoent" {
		t.Fatalf("mkShim ENOENT stat shimTaskID=%q want task-enoent", got)
	}
}
