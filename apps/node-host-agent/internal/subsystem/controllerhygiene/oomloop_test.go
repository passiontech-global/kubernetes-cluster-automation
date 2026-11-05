// oomloop_test.go — k0scontroller OOM-loop latch and oom_score_adj shielding.

package controllerhygiene

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- Guard c: OOM loop ---

func writeEvents(t *testing.T, e *env, kills int) {
	t.Helper()
	testutil.WriteFile(t, e.cg, fmt.Sprintf("low 0\nhigh 0\nmax 0\noom 0\noom_kill %d\noom_group_kill 0\n", kills))
}

func TestOOMLoopShield(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.mkProc(t, 2002, "kine", []string{"kine"}, 5000)
	// Seed baseline, then +3 kills within the window.
	writeEvents(t, e, 0)
	e.h.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.h.Cycle(context.Background())
	if !e.hasState(stateControllerOOMLop) {
		t.Fatal("k0scontroller-oom-loop missing")
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("apiserver adj=%s want -800", v)
	}
	if v := readAdj(t, e, 2002); v != "500" {
		t.Fatalf("kine adj=%s want 500", v)
	}
	// Loop clears → shield removed + state exits.
	e.now = e.now.Add(2 * time.Hour)
	writeEvents(t, e, 3) // no new kills; old ones pruned out
	e.h.Cycle(context.Background())
	if e.hasState(stateControllerOOMLop) {
		t.Fatal("oom-loop state not cleared")
	}
	if v := readAdj(t, e, 2001); v != "0" {
		t.Fatalf("apiserver not unshielded: %s", v)
	}
}

func TestOOMFirstRunSeedsOnly(t *testing.T) {
	e := fixture(t)
	// Pre-existing cumulative counter must NOT latch on first run.
	writeEvents(t, e, 50)
	e.h.Cycle(context.Background())
	if e.hasState(stateControllerOOMLop) {
		t.Fatal("baseline seeding latched a phantom OOM loop")
	}
}

func TestOOMUnparseableBaselineReseeds(t *testing.T) {
	e := fixture(t)
	// A garbage oomloop-seen file is NO baseline — prev=0 would
	// replay the whole cumulative counter as "new kills".
	testutil.WriteFile(t, filepath.Join(e.state, fileOOMSeen), "garbage\n")
	writeEvents(t, e, 50)
	e.h.Cycle(context.Background())
	if e.hasState(stateControllerOOMLop) {
		t.Fatal("unparseable baseline latched a phantom OOM loop")
	}
	// The re-seeded baseline is the current counter — a real delta
	// from here still counts.
	writeEvents(t, e, 53)
	e.h.Cycle(context.Background())
	if !e.hasState(stateControllerOOMLop) {
		t.Fatal("re-seeded baseline did not count subsequent kills")
	}
}

func TestOOMModeOffUnshields(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.mkProc(t, 2002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 0)
	e.h.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.h.Cycle(context.Background()) // latched + shielded (enforce)
	if !e.hasState(stateControllerOOMLop) {
		t.Fatal("precondition: oom-loop not latched")
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("precondition: apiserver adj=%s want -800", v)
	}
	// Mode flips off while the loop is still in-window — the shield
	// must come off, not persist for the process's lifetime.
	e.h.cfg.OOMLoop.Mode = ModeOff
	writeEvents(t, e, 4)
	e.h.Cycle(context.Background())
	if v := readAdj(t, e, 2001); v != "0" {
		t.Fatalf("apiserver shield survived mode-off: adj=%s", v)
	}
	if v := readAdj(t, e, 2002); v != "0" {
		t.Fatalf("kine shield survived mode-off: adj=%s", v)
	}
}

func readAdj(t *testing.T, e *env, pid int) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.proc, strconv.Itoa(pid), "oom_score_adj"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestOOMShieldSkippedWhenLatchUnwritable(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.mkProc(t, 2002, "kine", []string{"kine"}, 5000)

	// A state dir the probe can read but never write: seed the
	// baseline + in-window kills by hand, then lock the dir. The
	// failed latch write must abort shielding BEFORE any adj lands
	// — an adj pinned with no latch would survive every later
	// unshield (unshieldOOM keys on the file alone).
	dir := filepath.Join(filepath.Dir(e.state), "ro-state")
	testutil.WriteFile(t, filepath.Join(dir, fileOOMSeen), "0\n")
	var kills strings.Builder
	for i := 0; i < defaultOOMMinKills; i++ {
		fmt.Fprintf(&kills, "%d\n", e.now.Unix())
	}
	testutil.WriteFile(t, filepath.Join(dir, fileOOMKills), kills.String())
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e.h.cfg.WatchdogStateDir = dir
	e.h.state.Dir = dir // Store was built in New() — re-point it too

	// cum == baseline → no new kills needed; the seeded in-window
	// entries alone confirm the loop and reach the shield branch.
	writeEvents(t, e, 0)
	e.h.Cycle(context.Background())
	for _, pid := range []int{2001, 2002} {
		if _, err := os.Stat(e.h.proc.File(pid, "oom_score_adj")); err == nil {
			t.Fatalf("pid %d shielded without a persisted latch", pid)
		}
	}
}
