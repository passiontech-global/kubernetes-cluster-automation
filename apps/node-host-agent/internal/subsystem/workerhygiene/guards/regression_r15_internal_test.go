package guards

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestR15NftMonitorClassifiesStatesAndStat0000WithoutFIFO(t *testing.T) {
	d, f := gDeps(t)
	chk := NewNetfilterGuard(d)

	mkCmdFIFO := func(pid int) string {
		pdir := filepath.Join(f.ProcDir, fmt.Sprint(pid))
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		cmdFIFO := filepath.Join(pdir, "cmdline")
		if err := unix.Mkfifo(cmdFIFO, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if fp, err := os.OpenFile(cmdFIFO, os.O_RDWR, 0); err == nil {
				_ = fp.Close()
			}
		})
		return cmdFIFO
	}
	runSafe := func(pid int) nftMonitorResult {
		ch := make(chan nftMonitorResult, 1)
		go func() { ch <- chk.nftMonitor(pid) }()
		select {
		case r := <-ch:
			return r
		case <-time.After(2 * time.Second):
			t.Fatalf("nftMonitor(%d) blocked opening FIFO cmdline", pid)
			return nftCmdReadErr
		}
	}

	// D -> nftCmdStateD (never opens FIFO cmdline)
	f.MkStatProc(t, 6410, "nft", "D", "")
	mkCmdFIFO(6410)
	if got := runSafe(6410); got != nftCmdStateD {
		t.Fatalf("D-state nftMonitor=%v want nftCmdStateD", got)
	}

	// Z, X, x, R -> nftCmdSkip (never opens FIFO cmdline)
	for i, state := range []string{"Z", "X", "x", "R"} {
		pid := 6411 + i
		f.MkStatProc(t, pid, "nft", state, "")
		mkCmdFIFO(pid)
		if got := runSafe(pid); got != nftCmdSkip {
			t.Fatalf("%s-state nftMonitor=%v want nftCmdSkip", state, got)
		}
	}

	// ENOENT stat -> nftCmdSkip (never opens FIFO cmdline)
	mkCmdFIFO(6415)
	if got := runSafe(6415); got != nftCmdSkip {
		t.Fatalf("ENOENT stat nftMonitor=%v want nftCmdSkip", got)
	}

	// stat 0o000 -> nftCmdReadErr (never opens FIFO cmdline)
	if os.Geteuid() != 0 {
		f.MkStatProc(t, 6416, "nft", "S", "")
		mkCmdFIFO(6416)
		statPath := filepath.Join(f.ProcDir, "6416", "stat")
		if err := os.Chmod(statPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(statPath, 0o644) })
		if got := runSafe(6416); got != nftCmdReadErr {
			t.Fatalf("stat 0o000 nftMonitor=%v want nftCmdReadErr", got)
		}
	}

	// Readable S-state `nft monitor` -> nftCmdMonitor
	f.MkProc(t, 6417, "S", "nft\x00monitor\x00", "")
	if got := chk.nftMonitor(6417); got != nftCmdMonitor {
		t.Fatalf("nft monitor nftMonitor=%v want nftCmdMonitor", got)
	}

	// Readable S-state `nft add table` and stat-only S-state `nft` (ENOENT cmdline) -> nftCmdNonMonitor
	f.MkProc(t, 6418, "S", "nft\x00add\x00table\x00", "")
	if got := chk.nftMonitor(6418); got != nftCmdNonMonitor {
		t.Fatalf("nft add table nftMonitor=%v want nftCmdNonMonitor", got)
	}
	f.MkStatProc(t, 6419, "nft", "S", "")
	if got := chk.nftMonitor(6419); got != nftCmdNonMonitor {
		t.Fatalf("stat-only nft nftMonitor=%v want nftCmdNonMonitor", got)
	}
}
