package ctr

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR15RuncCmdlineQualifiesStat0000AndFIFO(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	f := wdepstest.New(t)
	d := ctrDeps(t, f)

	// Case 1: stat 0o000 + FIFO cmdline -> (false, true) without opening FIFO.
	pdir := filepath.Join(f.ProcDir, "9360")
	statPath := filepath.Join(pdir, "stat")
	wdepstest.WriteFile(t, statPath,
		"9360 (runc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
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

	type res struct {
		q   bool
		inc bool
	}
	ch := make(chan res, 1)
	go func() {
		q, inc := runcCmdlineQualifiesChecked(d, 9360, "runc")
		ch <- res{q: q, inc: inc}
	}()
	select {
	case r := <-ch:
		if r.q || !r.inc {
			t.Fatalf("runcCmdlineQualifiesChecked=(%v,%v) want (false,true)", r.q, r.inc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("runcCmdlineQualifiesChecked blocked opening FIFO cmdline on 0o000 stat")
	}

	// Case 2: X-state stat + FIFO cmdline -> (false, false) without opening FIFO.
	if err := os.Chmod(statPath, 0o644); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, statPath,
		"9360 (runc) X 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
	go func() {
		q, inc := runcCmdlineQualifiesChecked(d, 9360, "runc")
		ch <- res{q: q, inc: inc}
	}()
	select {
	case r := <-ch:
		if r.q || r.inc {
			t.Fatalf("X-state runcCmdlineQualifiesChecked=(%v,%v) want (false,false)", r.q, r.inc)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("runcCmdlineQualifiesChecked blocked opening FIFO cmdline on X-state stat")
	}
}
