// dstate_scopes_test.go — A2 zombie-storm latch + per-episode
// ACTION log + PID-reuse streak resets.
package guards_test

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// --- A2: zombie storm ---

// mkZombieProc writes a Z-state stat for pid whose parent is ppid.
func mkZombieProc(t *testing.T, e *env, pid, ppid int) {
	t.Helper()
	d := filepath.Join(e.ProcDir, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (defunct) Z %d 0 0 0", pid, ppid)
	if err := os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestZombieStormLatchesAndLogsAction(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Pressure.ZombieStormThreshold = 3 // fake proc trees are small
	uid := "11111111_2222_3333_4444_555555555555"
	parent := filepath.Join(e.ProcDir, "777")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uid + ".slice/cri-containerd-x.scope\n"
	if err := os.WriteFile(filepath.Join(parent, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("zombie-storm") {
		t.Fatal("state-zombie-storm should latch after 2 storm cycles")
	}
	data, err := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "ACTION zombie-storm: pod_uid=11111111-2222-3333-4444-555555555555 zombies=5"
	if !strings.Contains(string(data), want) {
		t.Fatalf("log should contain %q; got:\n%s", want, data)
	}
}

// mkParentProc writes a LIVE parent's stat under ProcRoot with the
// given starttime (field 22) — the streak key's generation tag, so
// tests can simulate PID reuse by rewriting start.
func mkParentProc(t *testing.T, e *env, pid int, starttime string) {
	t.Helper()
	// Fields after ')' start at field 3: f[0]=state … f[19]=
	// starttime (field 22) — 20 fields total.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (parent) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %s",
			pid, starttime))
}

// TestZombieStormActionLoggedOncePerEpisode: while the storm
// persists the latch holds but the ACTION line must NOT repeat —
// every repeat becomes a fresh K8s Event via nodereporter.
func TestZombieStormActionLoggedOncePerEpisode(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Pressure.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	for i := 0; i < 4; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("zombie-storm") {
		t.Fatal("storm latch should hold while the storm persists")
	}
	if n := strings.Count(e.LogLines(t), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("ACTION zombie-storm logged %d times over 4 storm cycles, want 1", n)
	}
}

// TestZombieStormPIDReuseResetsStreak: streaks key on (ppid,
// starttime) — a recycled ppid starts at 0 instead of inheriting
// the dead parent's count and holding a dead latch open.
func TestZombieStormPIDReuseResetsStreak(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Pressure.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	e.H.Cycle(context.Background()) // streak 1
	e.H.Cycle(context.Background()) // streak 2 → ACTION + latch
	if !e.H.State.Exists("zombie-storm") {
		t.Fatal("latch expected after 2 storm cycles")
	}
	// pid 777 is RECYCLED — same ppid, different starttime. The
	// dead parent's streak must not carry: the new generation
	// restarts at streak 1, the latch drops, no second ACTION yet.
	mkParentProc(t, e, 777, "222222")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("zombie-storm") {
		t.Fatal("recycled ppid must not inherit the dead parent's streak")
	}
	if n := strings.Count(e.LogLines(t), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("ACTION zombie-storm count=%d want 1", n)
	}
	// The new generation earns its own streak — latch + ACTION
	// again on its own entry.
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("zombie-storm") {
		t.Fatal("recycled parent's own streak should re-latch")
	}
	if n := strings.Count(e.LogLines(t), "ACTION zombie-storm:"); n != 2 {
		t.Fatalf("recycled parent logs its own ACTION on streak entry; count=%d want 2", n)
	}
}

// TestZombieStormLatchDropsBelowThreshold: a stored streak must be
// re-validated against THIS cycle's count before it can hold the
// latch — previously the streak loop latched on any live parent
// with ≥1 zombie, keeping the latch one extra cycle after the
// storm dropped under the threshold.
func TestZombieStormLatchDropsBelowThreshold(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.H.Cfg.Pressure.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("zombie-storm") {
		t.Fatal("latch expected after 2 storm cycles")
	}
	// Storm drains to 2 zombies (≤ threshold but >0) — the parent
	// still has zombie children, but the latch must drop NOW.
	for pid := 800; pid < 803; pid++ {
		if err := os.RemoveAll(filepath.Join(e.ProcDir, strconv.Itoa(pid))); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if e.H.State.Exists("zombie-storm") {
		t.Fatal("latch held an extra cycle after storm dropped below threshold")
	}
}
