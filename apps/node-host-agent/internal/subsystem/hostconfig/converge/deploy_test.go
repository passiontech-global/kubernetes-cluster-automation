// deploy_test.go — candidate-staged Deploy and NftUnit against a
// fake FileOps/Ops: stage→check→promote ordering, candidate sweep on
// every outcome, and the unchanged-content short-circuit.
package converge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// fakeFileOps drives Deploy over a real TempDir root (Deploy reads
// the joined path off the fs itself) while recording writes,
// removes, and check runs for assertions.
type fakeFileOps struct {
	host      Host
	writes    []string // host paths passed to WriteManaged
	removes   []string // host paths passed to RemoveManaged
	runs      [][]string
	writeErr  error            // returned by every WriteManaged
	writeErrs map[string]error // per-path write error (wins over writeErr)
	runOut    string
	runErr    error
}

func (f *fakeFileOps) Join(p string) string { return f.host.Join(p) }

func (f *fakeFileOps) WriteManaged(p string, c []byte, m os.FileMode) (bool, error) {
	f.writes = append(f.writes, p)
	if err, ok := f.writeErrs[p]; ok {
		return false, err
	}
	if f.writeErr != nil {
		return false, f.writeErr
	}
	return f.host.WriteManaged(p, c, m)
}

func (f *fakeFileOps) RemoveManaged(p string) (bool, error) {
	f.removes = append(f.removes, p)
	return f.host.RemoveManaged(p)
}

func (f *fakeFileOps) Run(_ context.Context, name string, args ...string) (string, error) {
	f.runs = append(f.runs, append([]string{name}, args...))
	return f.runOut, f.runErr
}

func newFakeFileOps(t *testing.T) *fakeFileOps {
	t.Helper()
	return &fakeFileOps{host: Host{Root: t.TempDir()}}
}

func TestDeployStagesChecksPromotes(t *testing.T) {
	o := newFakeFileOps(t)
	changed, err := Deploy(context.Background(), o, "/etc/nftables.conf",
		[]byte("ruleset"), 0o644, "nft", "-c", "-f")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("fresh content must report changed")
	}
	// Stage before promote, candidate swept after.
	if !slices.Equal(o.writes, []string{"/etc/nftables.conf.candidate", "/etc/nftables.conf"}) {
		t.Fatalf("writes = %v", o.writes)
	}
	// The check argv carries the CANDIDATE (host path) appended.
	if !slices.Equal(o.runs[0], []string{"nft", "-c", "-f", "/etc/nftables.conf.candidate"}) {
		t.Fatalf("check argv = %v", o.runs[0])
	}
	if !slices.Equal(o.removes, []string{"/etc/nftables.conf.candidate"}) {
		t.Fatalf("removes = %v", o.removes)
	}
	if got := testutil.ReadFile(t, o.host.Join("/etc/nftables.conf")); got != "ruleset" {
		t.Fatalf("promoted content = %q", got)
	}
	if o.host.FileExists("/etc/nftables.conf.candidate") {
		t.Fatal("candidate must be swept after promote")
	}
}

func TestDeployUnchangedSkipsStaging(t *testing.T) {
	o := newFakeFileOps(t)
	testutil.WriteFile(t, o.host.Join("/etc/nftables.conf"), "ruleset")
	// Plant a stale candidate — the unchanged short-circuit still
	// sweeps what a crashed converge left behind.
	testutil.WriteFile(t, o.host.Join("/etc/nftables.conf.candidate"), "stale")

	changed, err := Deploy(context.Background(), o, "/etc/nftables.conf",
		[]byte("ruleset"), 0o644, "nft", "-c", "-f")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical content must report unchanged")
	}
	if len(o.writes) != 0 || len(o.runs) != 0 {
		t.Fatalf("unchanged must not stage or check: writes=%v runs=%v", o.writes, o.runs)
	}
	if o.host.FileExists("/etc/nftables.conf.candidate") {
		t.Fatal("stale candidate was not swept")
	}
}

func TestDeployCheckFailureSweepsCandidate(t *testing.T) {
	o := newFakeFileOps(t)
	o.runErr = errors.New("nft: syntax error")
	o.runOut = "bad line 3"

	changed, err := Deploy(context.Background(), o, "/etc/nftables.conf",
		[]byte("broken"), 0o644, "nft", "-c", "-f")
	if err == nil {
		t.Fatal("a failing check must error")
	}
	if changed {
		t.Fatal("a failing check must not report changed")
	}
	if !strings.Contains(err.Error(), "candidate check") || !strings.Contains(err.Error(), "bad line 3") {
		t.Fatalf("err = %v, want check context + captured out", err)
	}
	// The live path is never written — only the candidate was staged.
	if !slices.Equal(o.writes, []string{"/etc/nftables.conf.candidate"}) {
		t.Fatalf("writes = %v", o.writes)
	}
	if o.host.FileExists("/etc/nftables.conf") {
		t.Fatal("a failed candidate must not reach the live path")
	}
	if o.host.FileExists("/etc/nftables.conf.candidate") {
		t.Fatal("candidate must be swept after a failed check")
	}
}

func TestDeployNoCheckPromotesUnverified(t *testing.T) {
	o := newFakeFileOps(t)
	changed, err := Deploy(context.Background(), o, "/etc/f", []byte("v"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("fresh content must report changed")
	}
	if len(o.runs) != 0 {
		t.Fatalf("no check must run, runs = %v", o.runs)
	}
	if got := testutil.ReadFile(t, o.host.Join("/etc/f")); got != "v" {
		t.Fatalf("content = %q", got)
	}
}

func TestDeployStagingFailureWrapsErrManagedWrite(t *testing.T) {
	o := newFakeFileOps(t)
	o.writeErr = errors.New("disk full")

	changed, err := Deploy(context.Background(), o, "/etc/f", []byte("v"), 0o644)
	if !errors.Is(err, ErrManagedWrite) {
		t.Fatalf("err = %v, want ErrManagedWrite-wrapped", err)
	}
	if changed {
		t.Fatal("a staging failure must not report changed")
	}
}

// A failed PROMOTE (staging write fine, live-path write fails) must
// surface ErrManagedWrite — it used to be swallowed into a nil
// return, so checkedDeploy read ok=true and unmask/enabled/restarted
// api-local-lb/haproxy/nftables onto a stale or missing config.
func TestDeployPromoteFailurePropagates(t *testing.T) {
	o := newFakeFileOps(t)
	o.writeErrs = map[string]error{"/etc/f": errors.New("disk full")}

	changed, err := Deploy(context.Background(), o, "/etc/f", []byte("v"), 0o644)
	if !errors.Is(err, ErrManagedWrite) {
		t.Fatalf("err = %v, want ErrManagedWrite-wrapped", err)
	}
	if changed {
		t.Fatal("a failed promote must not report changed")
	}
	// The candidate is swept on a promote failure too, and the live
	// path was never reached.
	if o.host.FileExists("/etc/f.candidate") {
		t.Fatal("candidate not swept after promote failure")
	}
	if o.host.FileExists("/etc/f") {
		t.Fatal("failed promote must not reach the live path")
	}
}

// fakeOps adds the unit verbs NftUnit drives to fakeFileOps.
type fakeOps struct {
	fakeFileOps
	verbs []string
}

func (f *fakeOps) DaemonReload(context.Context) { f.verbs = append(f.verbs, "daemon-reload") }
func (f *fakeOps) EnableService(_ context.Context, u string) {
	f.verbs = append(f.verbs, "enable "+u)
}
func (f *fakeOps) StartService(_ context.Context, u string) {
	f.verbs = append(f.verbs, "start "+u)
}
func (f *fakeOps) RestartService(_ context.Context, u string) {
	f.verbs = append(f.verbs, "restart "+u)
}

func TestNftUnitChanged(t *testing.T) {
	o := &fakeOps{fakeFileOps: *newFakeFileOps(t)}
	err := NftUnit(context.Background(), o, "mesh-rules",
		"/etc/nftables.d/mesh.conf", []byte("table inet mesh {}"), "mesh ruleset")
	if err != nil {
		t.Fatal(err)
	}
	// The ruleset is checked on the candidate, never the live path.
	if !slices.Equal(o.runs[0],
		[]string{"nft", "-c", "-f", "/etc/nftables.d/mesh.conf.candidate"}) {
		t.Fatalf("check argv = %v", o.runs[0])
	}
	// Changed ruleset + fresh unit → reload, enable, restart.
	want := []string{"daemon-reload", "enable mesh-rules.service", "restart mesh-rules.service"}
	if !slices.Equal(o.verbs, want) {
		t.Fatalf("verbs = %v, want %v", o.verbs, want)
	}
	unit := testutil.ReadFile(t, o.host.Join("/etc/systemd/system/mesh-rules.service"))
	if !strings.Contains(unit, "Description=mesh ruleset") {
		t.Error("unit file missing the description")
	}
	if !strings.Contains(unit, "ExecStart=/usr/sbin/nft -f /etc/nftables.d/mesh.conf") {
		t.Error("unit file ExecStart must load the LIVE path")
	}
	if got := testutil.ReadFile(t, o.host.Join("/etc/nftables.d/mesh.conf")); got != "table inet mesh {}" {
		t.Fatalf("ruleset content = %q", got)
	}
}

func TestNftUnitUnchangedStartsNotRestarts(t *testing.T) {
	o := &fakeOps{fakeFileOps: *newFakeFileOps(t)}
	content := []byte("table inet mesh {}")
	if err := NftUnit(context.Background(), o, "mesh-rules",
		"/etc/nftables.d/mesh.conf", content, "mesh ruleset"); err != nil {
		t.Fatal(err)
	}
	// Second converge with identical inputs: nothing changed, so no
	// daemon-reload and start instead of restart (enable always runs).
	o.verbs, o.writes, o.runs = nil, nil, nil
	if err := NftUnit(context.Background(), o, "mesh-rules",
		"/etc/nftables.d/mesh.conf", content, "mesh ruleset"); err != nil {
		t.Fatal(err)
	}
	// The unit file still goes through WriteManaged each cycle (the
	// sha256 compare inside makes it a no-op) but the unchanged
	// ruleset short-circuits before any staging write.
	if !slices.Equal(o.writes, []string{"/etc/systemd/system/mesh-rules.service"}) {
		t.Fatalf("writes = %v — the ruleset must not stage", o.writes)
	}
	want := []string{"enable mesh-rules.service", "start mesh-rules.service"}
	if !slices.Equal(o.verbs, want) {
		t.Fatalf("verbs = %v, want %v", o.verbs, want)
	}
}

func TestNftUnitCheckFailurePropagates(t *testing.T) {
	o := &fakeOps{fakeFileOps: *newFakeFileOps(t)}
	o.runErr = errors.New("nft: syntax error")
	err := NftUnit(context.Background(), o, "mesh-rules",
		"/etc/nftables.d/mesh.conf", []byte("broken"), "mesh ruleset")
	if err == nil {
		t.Fatal("a failing nft -c must abort the unit deploy")
	}
	if len(o.verbs) != 0 {
		t.Fatalf("no unit verbs may run after a failed check: %v", o.verbs)
	}
	if o.host.FileExists("/etc/systemd/system/mesh-rules.service") {
		t.Fatal("unit file must not be written after a failed check")
	}
}

// TestNftUnitUnitWriteFailurePropagates: the unit-file write is NOT
// fire-and-forget — a failed WriteManaged must surface ErrManagedWrite-
// wrapped (the caller's errors.Is skip treats it as already attributed)
// and skip every systemctl verb: daemon-reload/enable/start would
// apply a ruleset whose boot unit never landed.
func TestNftUnitUnitWriteFailurePropagates(t *testing.T) {
	o := &fakeOps{fakeFileOps: *newFakeFileOps(t)}
	o.writeErrs = map[string]error{
		"/etc/systemd/system/mesh-rules.service": errors.New("disk full"),
	}
	err := NftUnit(context.Background(), o, "mesh-rules",
		"/etc/nftables.d/mesh.conf", []byte("table inet mesh {}"), "mesh ruleset")
	if !errors.Is(err, ErrManagedWrite) {
		t.Fatalf("err = %v, want ErrManagedWrite-wrapped unit write failure", err)
	}
	if !strings.Contains(err.Error(), "mesh-rules.service") ||
		!strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v, want unit path + cause in the wrap", err)
	}
	if len(o.verbs) != 0 {
		t.Fatalf("no unit verbs may run after a failed unit write: %v", o.verbs)
	}
	// The validated ruleset itself still landed — only the unit
	// write failed.
	if got := testutil.ReadFile(t, o.host.Join("/etc/nftables.d/mesh.conf")); got != "table inet mesh {}" {
		t.Fatalf("ruleset = %q, want promoted", got)
	}
}

// Deploy relies on os.ReadFile(Join(path)) — a fake Join that does
// not root under real fs would break the unchanged check; assert the
// seam by writing through the real Host once more from a different
// content.
func TestDeployRewriteCycle(t *testing.T) {
	o := newFakeFileOps(t)
	ctx := context.Background()
	if _, err := Deploy(ctx, o, "/f", []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Deploy(ctx, o, "/f", []byte("v2"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("v2 over v1 must report changed")
	}
	if got := testutil.ReadFile(t, o.host.Join("/f")); got != "v2" {
		t.Fatalf("content = %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(o.host.Join("/f")))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".candidate") {
			t.Fatalf("candidate left behind: %s", e.Name())
		}
	}
}
