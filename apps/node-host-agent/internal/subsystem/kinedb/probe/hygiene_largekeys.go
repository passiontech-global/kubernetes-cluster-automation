// hygiene_largekeys.go — item 8: the kine large-key census (top-5
// live keys over 512KiB) on its 15m budget, with the in-process
// cache on *Probe re-emitting between windows.
package probe

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneLargeKeys — item 8: the top-5 LIVE kine keys whose value
// exceeds 512KiB. DISTINCT ON (name) ... ORDER BY name, id DESC
// mirrors kine's own latest-revision read, so deleted=0 on that row
// means the key is live; OCTET_LENGTH counts the bytea payload the
// controller-side kine_large_objects audit sizes via the API. The
// scan detoasts every live row's value — far too heavy for every
// 2-minute probe round — so it rides the persisted 15m
// last-kine-large-keys budget (spend-on-attempt, same contract as
// last-kine-analyze) and the in-process cache re-emits the last
// census until the next window. ReadOnly skips the query entirely:
// the textfile writer already refuses to emit there.
func (p *Probe) hygieneLargeKeys(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	p.largeKeysMu.Lock()
	h.largeKeys, h.largeSeen = p.largeKeysRows, p.largeKeysSeen
	p.largeKeysMu.Unlock()
	if p.d.Cfg.ReadOnly {
		return
	}
	// MkdirAll before the spend — Store.WriteEpochFile does not
	// create the state dir itself (same note as hygieneSeqScan).
	_ = os.MkdirAll(p.d.Cfg.GuardStateDir, 0o755)
	if !p.d.State.RateTrySpend(largeKeysFile, largeKeysBudget) {
		return // inside the 15m window — cached rows still emit
	}
	// `bytes|name` field order: name lands LAST so a key containing
	// '|' still parses (Cut takes the first separator only).
	out, err := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT OCTET_LENGTH(value), name FROM ("+
			"SELECT DISTINCT ON (name) name, value, deleted "+
			"FROM %s ORDER BY name, id DESC) latest "+
			"WHERE deleted = 0 AND OCTET_LENGTH(value) > %d "+
			"ORDER BY 1 DESC LIMIT %d",
		kdeps.SQLIdent(p.d.Cfg.Table), largeKeyMinBytes, largeKeysTopN))
	if err != nil {
		note(fmt.Sprintf("large-keys-fail: %v", err))
		return
	}
	var rows []largeKeyRow
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		sz, name, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		b, perr := strconv.ParseInt(strings.TrimSpace(sz), 10, 64)
		if perr != nil {
			continue
		}
		rows = append(rows, largeKeyRow{key: name, bytes: b})
	}
	p.largeKeysMu.Lock()
	p.largeKeysRows, p.largeKeysSeen = rows, true
	p.largeKeysMu.Unlock()
	h.largeKeys, h.largeSeen = rows, true
}
