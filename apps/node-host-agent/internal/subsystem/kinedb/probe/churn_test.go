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

// resHead answers 0 on a failed head read — callers treat it as "no
// data" rather than an error.
func TestResHeadQueryFailZeros(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "MAX(id)", Err: errors.New("connection reset")},
	})
	if got := k.resHead(context.Background(), "pg", "postgres", "secret"); got != 0 {
		t.Fatalf("resHead=%d want 0", got)
	}
}
