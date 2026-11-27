// proc_rss_test.go — unit tests for Deps.ProcVMRSS (/proc/<pid>/status parsing).
package cdeps_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestProcVMRSS(t *testing.T) {
	proc := t.TempDir()
	d := &cdeps.Deps{Proc: procfs.New(proc)}

	if v, ok := d.ProcVMRSS(0); ok || v != 0 {
		t.Fatalf("pid=0: got (%d, %v), want (0, false)", v, ok)
	}
	if v, ok := d.ProcVMRSS(9999); ok || v != 0 {
		t.Fatalf("missing pid: got (%d, %v), want (0, false)", v, ok)
	}

	writeStatus := func(pid, content string) {
		t.Helper()
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeStatus("100", "Name:\tkine\nVmSize:\t1000 kB\nVmRSS:\t   43008 kB\n")
	if v, ok := d.ProcVMRSS(100); !ok || v != 42<<20 {
		t.Fatalf("valid status: got (%d, %v), want (%d, true)", v, ok, uint64(42<<20))
	}

	writeStatus("101", "Name:\tkine\nState:\tS (sleeping)\n")
	if v, ok := d.ProcVMRSS(101); ok || v != 0 {
		t.Fatalf("missing VmRSS: got (%d, %v), want (0, false)", v, ok)
	}

	writeStatus("102", "VmRSS:\n")
	if v, ok := d.ProcVMRSS(102); ok || v != 0 {
		t.Fatalf("bare VmRSS header: got (%d, %v), want (0, false)", v, ok)
	}

	writeStatus("103", "VmRSS:\tnotanumber kB\n")
	if v, ok := d.ProcVMRSS(103); ok || v != 0 {
		t.Fatalf("non-numeric VmRSS: got (%d, %v), want (0, false)", v, ok)
	}
}
