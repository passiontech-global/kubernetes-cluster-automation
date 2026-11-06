// netns_w12_test.go — W12-KR2 coverage for the orphan
// /run/netns/cni-* reaper: the file-mtime qualifier, the
// containerd live-task cross-check (fail closed on an unreadable
// task map) and the 10-per-cycle reap cap.
package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// netnsW12Fixture points the reaper at a tempdir netns root inside
// the proc tree (same filesystem → hardlinks work for the
// live-inode tests) and returns the dir.
func netnsW12Fixture(t *testing.T, e *env) string {
	t.Helper()
	dir := filepath.Join(e.ProcDir, "netns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Net.NetnsDir = dir
	return dir
}

// armOrphan creates a confirmed orphan candidate: the cni-* file
// backdated past the 30m mtime qualifier plus a pre-armed
// cni-netns-seen-<name> marker already past the confirm window.
func armOrphan(t *testing.T, e *env, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	wdepstest.WriteFile(t, p, "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(e.StateDir,
		"cni-netns-seen-"+name), fmt.Sprintf("%d\n",
		e.Now.Add(-time.Hour).Unix()))
	return p
}

// TestOrphanNetnsLiveTaskProtected: a netns whose inode a LIVE
// containerd task's init still sits inside must not be unmounted
// — the task map is the stronger verdict even when the pid sweep
// (empty here) missed it.
func TestOrphanNetnsLiveTaskProtected(t *testing.T) {
	e := fixture(t)
	dir := netnsW12Fixture(t, e)
	p := armOrphan(t, e, dir, "cni-heldbytask")
	e.SDReply["umount"] = ""
	// The pid sweep sees nothing, but a live task init (8001)
	// references the same nsfs inode — reap must skip.
	nsdir := filepath.Join(e.ProcDir, "8001", "ns")
	if err := os.MkdirAll(nsdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(nsdir, "net")); err != nil {
		t.Fatalf("hardlink netns: %v", err)
	}
	tasksOnce := func() (map[string][]wdeps.CtrTask, bool) {
		return map[string][]wdeps.CtrTask{
			"uid-a": {{UID: "uid-a", Name: "app", PID: 8001, Live: true}},
		}, true
	}
	wdepstest.Check[*guards.CNINetnsCheck](e.H, wdeps.CheckCNINetns).Run(
		context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     wdepstest.PidsOf(),
			TasksOnce:    tasksOnce,
		})
	if e.SDRan("umount") {
		t.Fatal("umount ran on a netns held by a live containerd task")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("netns file removed while a live task references it")
	}
}

// TestOrphanNetnsIncompleteTaskMapSkips: an unreadable task map
// makes "no live containerd task" unverifiable — the reap fails
// closed and retries next cycle.
func TestOrphanNetnsIncompleteTaskMapSkips(t *testing.T) {
	e := fixture(t)
	dir := netnsW12Fixture(t, e)
	p := armOrphan(t, e, dir, "cni-unknownmap")
	e.SDReply["umount"] = ""
	wdepstest.Check[*guards.CNINetnsCheck](e.H, wdeps.CheckCNINetns).Run(
		context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     wdepstest.PidsOf(),
			TasksOnce:    func() (map[string][]wdeps.CtrTask, bool) { return nil, false },
		})
	if e.SDRan("umount") {
		t.Fatal("umount ran with an unverifiable task map")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("netns file removed with an incomplete task map")
	}
}

// TestOrphanNetnsReapCap: the reaper drains at most 10 confirmed
// orphans per cycle — the rest wait for the next pass (marker
// intact).
func TestOrphanNetnsReapCap(t *testing.T) {
	e := fixture(t)
	dir := netnsW12Fixture(t, e)
	for i := 0; i < 12; i++ {
		armOrphan(t, e, dir, fmt.Sprintf("cni-orphan%02d", i))
	}
	e.SDReply["umount"] = ""
	wdepstest.Check[*guards.CNINetnsCheck](e.H, wdeps.CheckCNINetns).Run(
		context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     wdepstest.PidsOf(),
		})
	umounts := 0
	for _, argv := range e.SDCmds {
		if strings.Contains(strings.Join(argv, " "), "umount") {
			umounts++
		}
	}
	remaining := 0
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir,
			fmt.Sprintf("cni-orphan%02d", i))); err == nil {
			remaining++
		}
	}
	if umounts != 10 {
		t.Fatalf("umount count=%d want 10 (reap cap)", umounts)
	}
	if remaining != 2 {
		t.Fatalf("remaining orphans=%d want 2 (cap left the tail)", remaining)
	}
	if got := e.LogLines(t); !strings.Contains(got, "reap cap") {
		t.Fatalf("missing reap-cap suspect line:\n%s", got)
	}
}

// TestOrphanNetnsFreshMtimeProtected: a file whose marker aged
// past the confirm window but whose mtime is fresh (recreated,
// or the sweep raced a CNI ADD) is never unmounted.
func TestOrphanNetnsFreshMtimeProtected(t *testing.T) {
	e := fixture(t)
	dir := netnsW12Fixture(t, e)
	p := filepath.Join(dir, "cni-toofresh")
	wdepstest.WriteFile(t, p, "") // fresh mtime ~ now
	wdepstest.WriteFile(t, filepath.Join(e.StateDir,
		"cni-netns-seen-cni-toofresh"), fmt.Sprintf("%d\n",
		e.Now.Add(-time.Hour).Unix()))
	e.SDReply["umount"] = ""
	wdepstest.Check[*guards.CNINetnsCheck](e.H, wdeps.CheckCNINetns).Run(
		context.Background(), &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     wdepstest.PidsOf(),
		})
	if e.SDRan("umount") {
		t.Fatal("umount ran on a fresh-mtime netns")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("fresh netns file removed")
	}
}
