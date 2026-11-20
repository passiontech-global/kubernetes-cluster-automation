package wdeps_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15PidsWithCmdlineStatGuards(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)

	mkFIFO := func(pid int) string {
		p := filepath.Join(e.ProcDir, string(rune('0'+pid/1000))+
			string(rune('0'+(pid/100)%10))+
			string(rune('0'+(pid/10)%10))+
			string(rune('0'+pid%10)), "cmdline")
		if err := unix.Mkfifo(p, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if fp, err := os.OpenFile(p, os.O_RDWR, 0); err == nil {
				_ = fp.Close()
			}
		})
		return p
	}

	// 2010: stat 0o000 (EACCES) + FIFO cmdline
	e.MkProc(t, 2010, "S", "", "")
	_ = os.Remove(filepath.Join(e.ProcDir, "2010", "cmdline"))
	mkFIFO(2010)
	stat2010 := filepath.Join(e.ProcDir, "2010", "stat")
	if err := os.Chmod(stat2010, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stat2010, 0o644) })

	// 2011: stat EISDIR + FIFO cmdline
	if err := os.MkdirAll(filepath.Join(e.ProcDir, "2011", "stat"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkFIFO(2011)

	// 2012: /proc/2012 is a regular file (ENOTDIR)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2012"), "not-a-dir")

	// 2013: stat ENOENT + FIFO cmdline
	if err := os.MkdirAll(filepath.Join(e.ProcDir, "2013"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkFIFO(2013)

	// 2014..2017: D/Z/X/x states + FIFO cmdline
	for idx, state := range []string{"D", "Z", "X", "x"} {
		pid := 2014 + idx
		e.MkProc(t, pid, state, "", "")
		_ = os.Remove(filepath.Join(e.ProcDir, string(rune('0'+pid/1000))+
			string(rune('0'+(pid/100)%10))+
			string(rune('0'+(pid/10)%10))+
			string(rune('0'+pid%10)), "cmdline"))
		mkFIFO(pid)
	}

	// 2018: readable S-state matching PID
	e.MkProc(t, 2018, "S", "containerd-shim\x00-id\x00target-needle\x00", "")

	done := make(chan []int, 1)
	go func() {
		done <- e.D.PidsWithCmdline("target-needle", []int{2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018})
	}()
	select {
	case got := <-done:
		if len(got) != 1 || got[0] != 2018 {
			t.Fatalf("PidsWithCmdline=%v want [2018]", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PidsWithCmdline blocked opening FIFO cmdline on guarded stat")
	}
}
