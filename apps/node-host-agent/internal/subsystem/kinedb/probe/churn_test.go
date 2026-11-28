// churn_test.go — the kine-churn top-churn watermark sampler tests,
// lifted out of the flat package's churn tests. The emit half of
// the old test lives in compact's suite now (the guard owns the
// textfile render of Deps.ChurnTop).
package probe

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestProbeTopChurn(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "split_part(name", Out: "pods|120\nleases|40\n"},
		{Substr: "MAX(id)", Out: "9000\n"},
	}
	k, _, dir := fixture(t, rules)
	// Watermark files: head=8000, ts well past the 5m window → the
	// query runs this round and the watermark advances.
	gdir := filepath.Join(dir, "guard")
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileHead), 8000)
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-600)
	var notes []string
	note := func(s string) { notes = append(notes, s) }
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", note)
	if len(k.d.ChurnTop) != 2 || k.d.ChurnTop[0].Resource != "pods" ||
		k.d.ChurnTop[0].Revs != 120 {
		t.Fatalf("churnTop=%+v", k.d.ChurnTop)
	}
	// Watermark advanced to the fresh head.
	if h, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileHead)); h != 9000 {
		t.Fatalf("churn head=%d want 9000", h)
	}
	// A fresh window (<5m) keeps the last result and does NOT query.
	k.d.ChurnTop = nil
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-10)
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", note)
	if k.d.ChurnTop != nil {
		t.Fatalf("churnTop refreshed inside window: %+v", k.d.ChurnTop)
	}
}

// A read-only probe (check-kine-db) never touches the daemon's
// churn watermark — no query, no notes, files untouched.
func TestProbeTopChurnReadOnlySkips(t *testing.T) {
	k, fr, dir := fixture(t, nil)
	k.d.Cfg.ReadOnly = true
	gdir := filepath.Join(dir, "guard")
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileHead), 8000)
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-600)
	var notes []string
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret",
		func(s string) { notes = append(notes, s) })
	if len(notes) != 0 {
		t.Fatalf("notes=%v want none", notes)
	}
	if fr.Joined() != "" {
		t.Fatalf("read-only probe sampled churn:\n%s", fr.Joined())
	}
	if ts, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileTS)); ts != kdepstest.TestNow-600 {
		t.Fatal("read-only probe rebased the churn watermark")
	}
}

// A failed grouped query notes and keeps the previous sample — no
// fabricated zero series, and the window is left open for a retry.
func TestProbeTopChurnQueryFailKeepsWindow(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "split_part(name", Err: errors.New("connection reset")},
	})
	gdir := filepath.Join(dir, "guard")
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileHead), 8000)
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-600)
	var notes []string
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret",
		func(s string) { notes = append(notes, s) })
	if len(notes) != 1 || !strings.Contains(notes[0], "top-churn-query-fail") {
		t.Fatalf("notes=%v", notes)
	}
	if len(k.d.ChurnTop) != 0 {
		t.Fatalf("churnTop fabricated on failure: %+v", k.d.ChurnTop)
	}
	// The window stays open — head watermark untouched.
	if h, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileHead)); h != 8000 {
		t.Fatalf("churn head rebased to %d on failure", h)
	}
	_ = fr
}

// The selfheal-alert-coverage hot-key half: the same window GROUP BYs the full Kine
// key, strips the /registry/ prefix and stores ChurnKeys for the
// guard's textfile emission.
func TestProbeTopHotkeys(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "HAVING COUNT", Out: "/registry/apps/v1/ConfigMap/ns/cm|140\n/registry/policy/v1/PodDisruptionBudget/ns/pdb|75\n"},
	})
	k.probeTopHotkeys(context.Background(), "pg", "postgres", "secret", 8000,
		func(string) {})
	keys := k.d.ChurnKeys
	if len(keys) != 2 || keys[0].Key != "apps/v1/ConfigMap/ns/cm" ||
		keys[0].Revs != 140 || keys[1].Key != "policy/v1/PodDisruptionBudget/ns/pdb" {
		t.Fatalf("churnKeys=%+v", keys)
	}
}

// A failed hot-key query keeps the previous sample — no fabricated
// zero series, and a note records the miss.
func TestProbeTopHotkeysQueryFailKeepsSample(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "HAVING COUNT", Err: errors.New("connection reset")},
	})
	k.d.ChurnKeys = []kdeps.ChurnKeyEntry{{Key: "apps/v1/ConfigMap/ns/cm", Revs: 90}}
	var notes []string
	k.probeTopHotkeys(context.Background(), "pg", "postgres", "secret", 8000,
		func(s string) { notes = append(notes, s) })
	if len(notes) != 1 || !strings.Contains(notes[0], "top-hotkey-query-fail") {
		t.Fatalf("notes=%v", notes)
	}
	if len(k.d.ChurnKeys) != 1 || k.d.ChurnKeys[0].Revs != 90 {
		t.Fatalf("churnKeys clobbered on failure: %+v", k.d.ChurnKeys)
	}
}

// resHead returns an error on a failed head read, and probeTopChurn
// preserves the existing watermark instead of overwriting it with 0
// (which would turn the next window into a WHERE id > 0 full-table scan).
func TestResHeadQueryFailPreservesWatermark(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "split_part(name", Out: "pods|120\n"},
		{Substr: "MAX(id)", Err: errors.New("connection reset")},
	})
	if _, err := k.resHead(context.Background(), "pg", "postgres", "secret"); err == nil {
		t.Fatal("resHead succeeded on SQL error, want error")
	}

	gdir := filepath.Join(dir, "guard")
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileHead), 8000)
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-600)
	var notes []string
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret",
		func(s string) { notes = append(notes, s) })
	if h, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileHead)); h != 8000 {
		t.Fatalf("churn head overwritten to %d on MAX(id) failure, want 8000", h)
	}
	if ts, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileTS)); ts != kdepstest.TestNow-600 {
		t.Fatalf("churn ts advanced to %d on MAX(id) failure", ts)
	}

	// Initial seed failure must not write head=0 + ts=now either.
	k2, _, dir2 := fixture(t, []testutil.ExecRule{
		{Substr: "MAX(id)", Err: errors.New("connection reset")},
	})
	gdir2 := filepath.Join(dir2, "guard")
	k2.probeTopChurn(context.Background(), "pg", "postgres", "secret",
		func(string) {})
	if h, err := kdeps.ReadIntFile(filepath.Join(gdir2, churnFileHead)); err == nil || h != 0 {
		t.Fatalf("initial seed wrote head=%d err=%v on MAX(id) failure", h, err)
	}
	if ts, err := kdeps.ReadIntFile(filepath.Join(gdir2, churnFileTS)); err == nil || ts != 0 {
		t.Fatalf("initial seed wrote ts=%d err=%v on MAX(id) failure", ts, err)
	}
}

func TestProbeTopChurnBackwardClockReseeds(t *testing.T) {
	now := time.Unix(kdepstest.TestNow, 0)
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "split_part(name", Out: "pods|42\n"},
		{Substr: "MAX(id)", Out: "9500\n"},
	})
	k.d.Cfg.Clock.Set(func() time.Time { return now })
	gdir := filepath.Join(dir, "guard")
	// Future watermark (2h ahead of now due to backward clock step).
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileHead), 12000)
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), now.Add(2*time.Hour).Unix())

	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", func(string) {})
	if strings.Contains(fr.Joined(), "split_part(name") {
		t.Fatalf("expected watermark re-seed, not churn query:\n%s", fr.Joined())
	}
	if ts, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileTS)); ts != now.Unix() {
		t.Fatalf("churn ts not re-seeded to now: got %d want %d", ts, now.Unix())
	}
	if h, _ := kdeps.ReadIntFile(filepath.Join(gdir, churnFileHead)); h != 9500 {
		t.Fatalf("churn head not re-seeded to resHead: got %d want 9500", h)
	}

	// Advancing past defaultChurnWindow (5m, well before +2h) resumes sampling.
	now = now.Add(defaultChurnWindow + time.Second)
	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", func(string) {})
	if len(k.d.ChurnTop) != 1 || k.d.ChurnTop[0].Resource != "pods" {
		t.Fatalf("churn sampling stayed frozen after re-seed: %+v", k.d.ChurnTop)
	}
}

func TestProbeTopChurnMissingOrCorruptHeadReseeds(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "split_part(name", Out: "pods|120\n"},
		{Substr: "MAX(id)", Out: "9500\n"},
	})
	gdir := filepath.Join(dir, "guard")
	// TS is present and past 5m, but churnFileHead is missing — must re-seed
	// instead of running WHERE id > 0 across the entire table.
	kdeps.WriteIntFile(filepath.Join(gdir, churnFileTS), kdepstest.TestNow-600)

	k.probeTopChurn(context.Background(), "pg", "postgres", "secret", func(string) {})
	if strings.Contains(fr.Joined(), "split_part(name") {
		t.Fatalf("expected re-seed when churn head file missing, got full-table query:\n%s", fr.Joined())
	}
	if h, err := kdeps.ReadIntFile(filepath.Join(gdir, churnFileHead)); err != nil || h != 9500 {
		t.Fatalf("churn head=%d err=%v want 9500", h, err)
	}
}
