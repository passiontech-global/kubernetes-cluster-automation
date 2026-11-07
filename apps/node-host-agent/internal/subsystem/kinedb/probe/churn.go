// churn.go — the W13-CP4 top-5 write-churn sampler, riding the
// probe cycle. The kine table carries no wall-clock column, so
// "last 5m" is a watermark window under GuardStateDir; the guard
// cycle owns the textfile emission of the result (the probe's own
// .prom must never duplicate the series).
package probe

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	// defaultChurnWindow is the sampling window — a mutating
	// webhook ping-pong shows up as one resource prefix churning
	// thousands of revisions inside it.
	defaultChurnWindow = 5 * time.Minute
	churnTopN          = 5
	churnFileHead      = "last-churn-head"
	churnFileTS        = "last-churn-ts"
)

// probeTopChurn is the W13-CP4 top-5 write-churn sampler. The kine
// table carries no wall-clock column, so "last 5m" is a watermark
// window: once the stored (head, ts) pair is >= defaultChurnWindow
// old, one light grouped query counts revisions minted since it
// and the watermark advances to (current head, now). Skipped
// windows keep the last result — a failed query never fabricates
// a zero series.
func (p *Probe) probeTopChurn(ctx context.Context, pg, user, pass string,
	note func(string)) {
	if p.d.Cfg.ReadOnly {
		// The watermark files are the DAEMON's sampling window — a
		// read-only probe (check-kine-db) must not rebase it. The
		// sample itself feeds only the guard textfile, which the
		// CLI does not render, so there is nothing to report here.
		return
	}
	dir := p.d.Cfg.GuardStateDir
	prevHead, _ := kdeps.ReadIntFile(filepath.Join(dir, churnFileHead))
	prevTS, _ := kdeps.ReadIntFile(filepath.Join(dir, churnFileTS))
	now := p.d.Cfg.Clock.Now().Unix()
	if prevTS == 0 {
		// First sighting — seed the watermark only. A missing
		// watermark treated as head=0 would group-by the WHOLE
		// table (the COUNT(*) the probe budget forbids).
		kdeps.WriteIntFile(filepath.Join(dir, churnFileTS), now)
		kdeps.WriteIntFile(filepath.Join(dir, churnFileHead),
			p.resHead(ctx, pg, user, pass))
		return
	}
	if now-prevTS < int64(defaultChurnWindow.Seconds()) {
		return // window still filling — keep the last result
	}
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT split_part(name,'/',3) AS res, COUNT(*) FROM %[1]s "+
			"WHERE id > %[2]d AND name LIKE '/registry/%%' "+
			"GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT %d",
		kdeps.SQLIdent(p.d.Cfg.Table), prevHead, churnTopN))
	if err != nil {
		note(fmt.Sprintf("top-churn-query-fail: %v", err))
		return
	}
	var top []kdeps.ChurnEntry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		n, perr := strconv.ParseInt(f[1], 10, 64)
		if perr == nil {
			top = append(top, kdeps.ChurnEntry{Resource: f[0], Revs: n})
		}
	}
	p.d.ChurnMu.Lock()
	p.d.ChurnTop = top
	p.d.ChurnMu.Unlock()
	// Advance the watermark — a churn-free window still moves it
	// so the next window measures fresh ground.
	kdeps.WriteIntFile(filepath.Join(dir, churnFileHead), p.resHead(ctx, pg, user, pass))
	kdeps.WriteIntFile(filepath.Join(dir, churnFileTS), now)
}

// resHead re-reads MAX(id) for the watermark advance — best-effort:
// a failed read writes 0, which makes the next window count "id>0"
// and safely degrade to a full-table count once.
func (p *Probe) resHead(ctx context.Context, pg, user, pass string) int64 {
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT COALESCE((SELECT MAX(id) FROM %s),0)", kdeps.SQLIdent(p.d.Cfg.Table)))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(kdeps.FirstLine(out), 10, 64)
	return v
}
