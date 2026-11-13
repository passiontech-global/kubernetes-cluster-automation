package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- check 6: ctr-tasks (31) ---

// TestCtrTasksUmountsRootfsBeforeRemove: a wedged task
// bundle whose rootfs is still a mount must be lazily unmounted in
// the HOST mount namespace BEFORE the dir removal — RemoveAll would
// hit EBUSY and leak the mountpoint into the mountinfo table.
func TestCtrTasksUmountsRootfsBeforeRemove(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "ef0ce17"+strings.Repeat("f", 57))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir, "log.json"), "{}\n")
	// The still-mounted rootfs — contents on the leaked mount.
	wdepstest.WriteFile(t, filepath.Join(dir, "rootfs", "bin", "sh"), "#!/bin/sh\n")
	e.SDReply["umount"] = ""

	e.H.Cycle(context.Background()) // marker only
	if e.SDRan("umount") {
		t.Fatal("umount ran before the wedged-dir confirmation window")
	}
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm + clean
	if !e.SDRan("umount -l " + filepath.Join(dir, "rootfs")) {
		t.Fatalf("no lazy umount of the task rootfs; sdcmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir not removed after umount")
	}
	if !strings.Contains(e.LogLines(t), "umount -l rootfs of task") {
		t.Fatalf("missing umount ACTION line:\n%s", e.LogLines(t))
	}

	// A task dir WITHOUT a rootfs subtree (already unmounted) must
	// not fire a umount.
	dir2 := filepath.Join(e.CtrDir, "deadc0d"+strings.Repeat("0", 57))
	wdepstest.WriteFile(t, filepath.Join(dir2, "init.pid"), "77778")
	wdepstest.WriteFile(t, filepath.Join(dir2, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir2, "log.json"), "{}\n")
	e.H.Cycle(context.Background())
	e.Now = e.Now.Add(6 * time.Minute)
	n := 0
	for _, c := range e.SDCmds {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "umount") && strings.Contains(joined, dir2) {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("umount fired for a dir without rootfs: %d", n)
	}
}

func TestCtrTasksWedgedDirTwoPhase(t *testing.T) {
	e := fixture(t)
	// Dead-init task dir (init.pid points at nothing live).
	dir := filepath.Join(e.CtrDir, "deadbeef"+strings.Repeat("a", 56))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "77777")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(dir, "log.json"), "{}\n")

	e.H.Cycle(context.Background())
	// First sighting: marker only — no cleanup yet.
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("dir removed before marker confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-"+filepath.Base(dir))); err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	// Advance past the 5m confirm window → cleanup.
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir not removed after 5m marker")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"wedged-seen-"+filepath.Base(dir))); !os.IsNotExist(err) {
		t.Fatal("marker not consumed by cleanup")
	}
	if !strings.Contains(e.LogLines(t), "rm wedged task dir") {
		t.Fatalf("missing rm-dir log:\n%s", e.LogLines(t))
	}
}

func TestCtrTasksLiveAndSandboxSkipped(t *testing.T) {
	e := fixture(t)
	// Live init, log.json present → healthy task, marker cleared.
	liveDir := filepath.Join(e.CtrDir, "livetask"+strings.Repeat("b", 57))
	wdepstest.WriteFile(t, filepath.Join(liveDir, "init.pid"), "9100")
	wdepstest.WriteFile(t, filepath.Join(liveDir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(liveDir, "log.json"), "{}\n")
	e.MkProc(t, 9100, "S", "", "")
	// Sandbox (pause) missing log.json → legitimately skipped.
	sbDir := filepath.Join(e.CtrDir, "sandboxx"+strings.Repeat("c", 57))
	wdepstest.WriteFile(t, filepath.Join(sbDir, "init.pid"), "9101")
	wdepstest.WriteFile(t, filepath.Join(sbDir, "config.json"),
		`{"annotations":{"cri.container-type":"sandbox"}}`)
	e.MkProc(t, 9101, "S", "", "")
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
		e.Now = e.Now.Add(6 * time.Minute)
	}
	if _, err := os.Stat(liveDir); err != nil {
		t.Fatal("live task dir removed")
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir removed (log.json missing is normal)")
	}
}

func TestCtrTasksMissingLogJSONKillsInit(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.CtrDir, "0fa11ce"+strings.Repeat("d", 57))
	wdepstest.WriteFile(t, filepath.Join(dir, "init.pid"), "9102")
	wdepstest.WriteFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	// No log.json + LIVE init on a container task → dead wedge.
	e.MkProc(t, 9102, "S", "", "")
	e.H.Cycle(context.Background()) // marker
	e.Now = e.Now.Add(6 * time.Minute)
	e.H.Cycle(context.Background()) // confirm + clean
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dir with missing log.json not removed")
	}
	if len(e.Kills) == 0 || e.Kills[0].PID != 9102 {
		t.Fatalf("init not SIGKILLed, kills=%v", e.Kills)
	}
}

func TestCtrTasksOrphanShim(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("e", 64)
	// Orphan shim: cmdline holds -id <sid> but no task dir anywhere.
	// -address pins it to the k0s containerd socket (host-side path —
	// ContainerdSocket's /host mount prefix is stripped for the
	// comparison).
	e.MkProc(t, 9200, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// Fresh proc mtime — must survive the 5m orphan window.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("fresh shim killed before 5m window")
	}
	// Age the /proc entry past 5m.
	old := e.Now.Add(-6 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9200"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 9200 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("orphan shim not killed, kills=%v", e.Kills)
	}
}

func TestCtrTasksHealthyShimKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("f", 64)
	e.MkProc(t, 9201, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// The task dir exists → shim is not an orphan.
	if err := os.MkdirAll(filepath.Join(e.CtrDir, sid), 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9201"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("healthy shim killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignShimNotKilled is the NodeOverloaded-incident
// regression: a host dockerd shim (namespace moby, socket
// /run/containerd/containerd.sock — a DIFFERENT containerd root) has
// no task dir under the k0s k8s.io root, so the pre-fix reaper
// SIGKILLed every docker shim each sweep. It must now read as
// out-of-scope and survive even past the 5m age window.
func TestCtrTasksForeignShimNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("a", 64)
	e.MkProc(t, 9300, "S",
		"containerd-shim-runc-v2\x00-namespace\x00moby\x00-id\x00"+sid+
			"\x00-address\x00/run/containerd/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9300"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("docker/moby shim killed by orphan reaper, kills=%v", e.Kills)
	}
}

// TestCtrTasksK8sNsForeignAddressNotKilled: namespace alone is not
// scope — a foreign containerd can also serve a k8s.io-looking
// namespace (a second CRI daemon, a concourse worker's containerd).
// The -address flag is the instance identity.
func TestCtrTasksK8sNsForeignAddressNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("b", 64)
	e.MkProc(t, 9301, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+
			"\x00-address\x00/run/containerd/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9301"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("k8s.io shim of foreign containerd killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksShimMissingFlagsNotKilled: a shim that can't be tied to
// our containerd (no -address at all) is skipped — fail closed, the
// instance is unverifiable.
func TestCtrTasksShimMissingFlagsNotKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("c", 64)
	e.MkProc(t, 9302, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+"\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9302"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("unverifiable shim (no -address) killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignNsSameSocketKept: a non-k8s.io namespace on OUR
// containerd resolves its task dir under the sibling namespace root —
// a live task must not read as orphan.
func TestCtrTasksForeignNsSameSocketKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("d", 64)
	e.MkProc(t, 9303, "S",
		"containerd-shim-runc-v2\x00-namespace\x00buildkit\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	// Task dir exists under the buildkit namespace root: sibling of
	// the k8s.io root (filepath.Dir(e.CtrDir)/<ns>/<id>).
	if err := os.MkdirAll(
		filepath.Join(filepath.Dir(e.CtrDir), "buildkit", sid), 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9303"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("live foreign-namespace shim on k0s containerd killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksForeignNsSameSocketOrphanKilled: same socket + a
// foreign namespace whose task dir is genuinely gone IS our
// containerd's orphan — reap it like a k8s.io orphan.
func TestCtrTasksForeignNsSameSocketOrphanKilled(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("9", 64)
	e.MkProc(t, 9304, "S",
		"containerd-shim-runc-v2\x00-namespace\x00buildkit\x00-id\x00"+sid+
			"\x00-address\x00/run/k0s/containerd.sock\x00", "")
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.ProcDir, "9304"), old, old); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 9304 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("orphan same-socket foreign-ns shim not killed, kills=%v", e.Kills)
	}
}

// TestCtrTasksOverCapKeepsMarker: dirs dropped by the per-cycle cap
// must KEEP their confirmed wedged-seen marker — removing it on the
// capped pass forced over-cap dirs to re-confirm for 5m forever.
func TestCtrTasksOverCapKeepsMarker(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Ctr.MaxTaskClean = 2
	// 4 confirmed-wedged dirs (dead init: no init.pid at all), each
	// with a marker already past the 5m confirm window. Hex64 ids —
	// the wedge scan gates on CRI id shape before pid-scanning.
	for i := range 4 {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if err := os.MkdirAll(filepath.Join(e.CtrDir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-"+id),
			fmt.Sprintf("%d\n", e.Now.Add(-10*time.Minute).Unix()))
	}
	e.H.Cycle(context.Background())
	// First two (ReadDir order) cleaned, markers consumed.
	for i := range 2 {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if _, err := os.Stat(filepath.Join(e.CtrDir, id)); !os.IsNotExist(err) {
			t.Fatalf("in-cap wedged dir %s not removed", id)
		}
	}
	// The capped two keep BOTH dir and marker — confirmed state
	// survives so next cycle cleans them without a new 5m wait.
	for i := 2; i < 4; i++ {
		id := fmt.Sprintf("%02x%s", i, strings.Repeat("d", 62))
		if _, err := os.Stat(filepath.Join(e.StateDir, "wedged-seen-"+id)); err != nil {
			t.Fatalf("over-cap marker %s dropped — dir would re-confirm forever", id)
		}
	}
}
