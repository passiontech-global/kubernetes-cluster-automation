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

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

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

// --- early gates ---

// No memory.events file — not a cgroup-v2 controller — exits 0 the
// same way the shell did: counted, silent, nothing latched.
func TestOOMNoEventsFileNoop(t *testing.T) {
	e := fixture(t) // the fixture never writes CG
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "no_events")); got != 1 {
		t.Fatalf("cycles{no_events}=%v want 1", got)
	}
	if e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("missing memory.events latched an OOM loop")
	}
}

// An events file without an `oom_kill` row parses as "no counter" —
// the probe closes as ok instead of reading a phantom value.
func TestOOMEventsWithoutKillRowNoop(t *testing.T) {
	e := fixture(t)
	testutil.WriteFile(t, e.CG, "low 0\nhigh 0\nmax 0\noom 0\n")
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "ok")); got != 1 {
		t.Fatalf("cycles{ok}=%v want 1", got)
	}
	if e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("counterless memory.events latched an OOM loop")
	}
}

// An oom_kill row whose counter overflows int64 is no parseable
// counter either — re-baseline semantics must not fire on it.
func TestOOMKillCounterOverflowNoop(t *testing.T) {
	e := fixture(t)
	testutil.WriteFile(t, e.CG,
		"low 0\nhigh 0\nmax 0\noom 0\noom_kill 99999999999999999999\noom_group_kill 0\n")
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckOOMLoop, "ok")); got != 1 {
		t.Fatalf("cycles{ok}=%v want 1 — unparseable counter is no counter", got)
	}
	if e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("overflowing oom_kill counter latched an OOM loop")
	}
}

// A kills-file append failure must be surfaced, not swallowed — the
// window then undercounts and the latch can silently stop firing.
func TestOOMKillsAppendFailWarns(t *testing.T) {
	e := fixture(t)
	// Seed a parseable baseline, then make the kills "file" a
	// directory — the O_APPEND open fails with EISDIR.
	testutil.WriteFile(t, filepath.Join(e.State, cdeps.FileOOMSeen), "0\n")
	if err := os.Mkdir(filepath.Join(e.State, cdeps.FileOOMKills), 0o755); err != nil {
		t.Fatal(err)
	}
	writeEvents(t, e, 2) // baseline 0 → 2 new kills to append
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(), "append failed") {
		t.Fatalf("kills append failure not logged:\n%s", e.LogLines())
	}
	if !strings.Contains(e.LogLines(), "2 new memcg OOM kill") {
		t.Fatalf("kill delta not announced:\n%s", e.LogLines())
	}
}

// Dry-run mode confirms the loop but only rules — the DRY-RUN line,
// the dryrun_shield action counter, and neither a latch nor a pin.
func TestOOMDryRunLogsOnly(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.OOMLoop.Mode = cdeps.ModeDryRun
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateControllerOOMLop) {
		t.Fatal("dry-run did not latch the loop state")
	}
	if !strings.Contains(e.LogLines(), "DRY-RUN") {
		t.Fatalf("dry-run verdict not logged:\n%s", e.LogLines())
	}
	if got := promtest.ToFloat64(e.H.Actions.WithLabelValues(cdeps.CheckOOMLoop, "dryrun_shield")); got != 1 {
		t.Fatalf("actions{dryrun_shield}=%v want 1", got)
	}
	if _, err := os.Stat(filepath.Join(e.State, cdeps.FileOOMShielded)); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote a shield latch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.Proc, "2001", "oom_score_adj")); !os.IsNotExist(err) {
		t.Fatalf("dry-run pinned kube-apiserver oom_score_adj: %v", err)
	}
}

// A swallowed oom_score_adj write failure would leave the shield
// half-applied and invisible — every enforce cycle re-pins, so the
// failure must land in the log while the rest of the shield holds.
func TestOOMShieldWriteFailLogged(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "kube-apiserver", []string{"kube-apiserver"}, 5000)
	e.MkProc(t, 2002, "kine", []string{"kine"}, 5000)
	writeEvents(t, e, 0)
	e.H.Cycle(context.Background())
	writeEvents(t, e, 3)
	e.H.Cycle(context.Background()) // latched + shielded
	// Lock the apiserver adj file read-only: the next enforce cycle's
	// reassert must warn about kube-apiserver while kine re-pins fine.
	adj := filepath.Join(e.Proc, "2001", "oom_score_adj")
	if err := os.Chmod(adj, 0o444); err != nil {
		t.Fatal(err)
	}
	writeEvents(t, e, 4) // still latched (in-window kill)
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(), "write oom_score_adj") ||
		!strings.Contains(e.LogLines(), "comm=kube-apiserver") {
		t.Fatalf("adj write failure not logged:\n%s", e.LogLines())
	}
	if v := readAdj(t, e, 2002); v != "500" {
		t.Fatalf("kine re-shield failed despite apiserver write error: adj=%s", v)
	}
	if v := readAdj(t, e, 2001); v != "-800" {
		t.Fatalf("apiserver adj mutated on a failed write: %s", v)
	}
}
