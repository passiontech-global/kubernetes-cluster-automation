// churn_test.go — the W13-CP4 top-churn watermark sampler tests,
// lifted out of the flat package's w13_test.go. The emit half of
// the old test lives in compact's suite now (the guard owns the
// textfile render of Deps.ChurnTop).
package probe

import (
	"context"
	"path/filepath"
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
