// oomloop_test.go — k0scontroller OOM-loop latch and oom_score_adj shielding.

package oom_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- Guard c: OOM loop ---

func writeEvents(t *testing.T, e *env, kills int) {
	t.Helper()
	testutil.WriteFile(t, e.CG, fmt.Sprintf("low 0\nhigh 0\nmax 0\noom 0\noom_kill %d\noom_group_kill 0\n", kills))
}

func TestOOMLoopShield(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)
	// Seed baseline, then +3 kills within the window.
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("k0scontroller-oom-loop missing")
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("apiserver adj=%s want -800", v)
	}
	if v := readAdj(t, e, 2002); v != "500" {
		t.Fatalf("kine adj=%s want 500", v)
	}
	// Loop clears → shield removed + state exits.
	e.Now = e.Now.Add(2 * time.Hour)
	writeEvents(t, e, 3) // no new kills; old ones pruned out
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateControllerOOMLop) {
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
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("baseline seeding latched a phantom OOM loop")
	}
}

func TestOOMUnparseableBaselineReseeds(t *testing.T) {
	e := fixture(t)
	// A garbage oomloop-seen file is NO baseline — prev=0 would
	// replay the whole cumulative counter as "new kills".
	testutil.WriteFile(t, filepath.Join(e.State, cdeps.FileOOMSeen), "garbage\n")
	writeEvents(t, e, 50)
	e.H.Cycle(context.Background())
	if e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("unparseable baseline latched a phantom OOM loop")
	}
	// The re-seeded baseline is the current counter — a real delta
	// from here still counts.
	writeEvents(t, e, 53)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("re-seeded baseline did not count subsequent kills")
	}
}

func TestOOMModeOffUnshields(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.H.Cycle(context.Background()) // latched + shielded (enforce)
	if !e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("precondition: oom-loop not latched")
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("precondition: apiserver adj=%s want -800", v)
	}
	// Mode flips off while the loop is still in-window — the shield
	// must come off, not persist for the process's lifetime.
	e.H.Cfg.OOMLoop.Mode = cdeps.ModeOff
	writeEvents(t, e, 4)
	e.H.Cycle(context.Background())
	if v := readAdj(t, e, 2001); v != "0" {
		t.Fatalf("apiserver shield survived mode-off: adj=%s", v)
	}
	if v := readAdj(t, e, 2002); v != "0" {
		t.Fatalf("kine shield survived mode-off: adj=%s", v)
	}
}

func readAdj(t *testing.T, e *env, pid int) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.Proc, strconv.Itoa(pid), "oom_score_adj"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestOOMShieldSkippedWhenLatchUnwritable(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)

	// A state dir the probe can read but never write: seed the
	// baseline + in-window kills by hand, then lock the dir. The
	// failed latch write must abort shielding BEFORE any adj lands
	// — an adj pinned with no latch would survive every later
	// unshield (unshieldOOM keys on the file alone).
	dir := filepath.Join(filepath.Dir(e.State), "ro-state")
	testutil.WriteFile(t, filepath.Join(dir, cdeps.FileOOMSeen), "0\n")
	var kills strings.Builder
	for i := 0; i < cdeps.DefaultOOMMinKills; i++ {
		fmt.Fprintf(&kills, "%d\n", e.Now.Unix())
	}
	testutil.WriteFile(t, filepath.Join(dir, cdeps.FileOOMKills), kills.String())
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e.H.Cfg.WatchdogStateDir = dir
	e.H.State.Dir = dir // Store was built in New() — re-point it too

	// cum == baseline → no new kills needed; the seeded in-window
	// entries alone confirm the loop and reach the shield branch.
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	for _, pid := range []int{2001, 2002} {
		if _, err := os.Stat(e.H.Proc.File(pid, "oom_score_adj")); err == nil {
			t.Fatalf("pid %d shielded without a persisted latch", pid)
		}
	}
}

// reassertShields must re-pin BOTH processes every enforce cycle:
// a respawned kine boots at oom_score_adj=0, and skipping its +500
// would leave it fully killable while the loop latch stands — the
// exact crash spiral the shield exists to break.
func TestOOMShieldReassertsKineAfterRespawn(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.H.Cycle(context.Background()) // latched + shielded
	if v := readAdj(t, e, 2002); v != "500" {
		t.Fatalf("precondition: kine adj=%s want 500", v)
	}
	// kine respawns: old pid 2002 gone, new pid 3002 at adj=0.
	if err := os.RemoveAll(filepath.Join(e.Proc, "2002")); err != nil {
		t.Fatal(err)
	}
	e.MkProc(t, 3002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 4) // still latched (in-window kill)
	e.H.Cycle(context.Background())
	if v := readAdj(t, e, 3002); v != "500" {
		t.Fatalf("respawned kine not re-shielded: adj=%s want 500", v)
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("apiserver shield lost across respawn: adj=%s", v)
	}
}
