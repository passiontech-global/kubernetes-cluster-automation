// textfile_prom.go — node-exporter textfile channel helpers shared
// by the control-plane checks that export node_agent_* gauges.
//
// W10 metrics note: the subsystem prometheus registry is owned by
// controllerhygiene.go's New() (outside this file), so the
// node_agent_* gauges are emitted through the node-exporter
// textfile channel — the DaemonSet bind-mounts
// /host/var/lib/node-exporter rw for exactly this (kinedb/hostconfig
// parity).
package controllerhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// textfileDirOverride wins over the K0sDir-derived textfile dir —
// test seam.
var textfileDirOverride = ""

// textfilePromDir resolves the node-exporter textfile drop dir:
// K0sDir is <hostRoot>/var/lib/k0s, so the dir is its sibling
// <hostRoot>/var/lib/node-exporter/textfile (DaemonSet:
// /host/var/lib/..., standalone: /var/lib/...). The override wins
// for tests.
func (h *Hygiene) textfilePromDir() string {
	if textfileDirOverride != "" {
		return textfileDirOverride
	}
	return filepath.Join(filepath.Dir(h.cfg.K0sDir),
		"node-exporter", "textfile")
}

// writeTextfileProm atomically installs content as <dir>/<name>
// (tmp+rename — node_exporter only reads complete .prom files; the
// .tmp suffix keeps the staging file out of the *.prom glob).
// Failures go through suspectLog — a broken/missing mount must not
// spam the watchdog tail every cycle.
func (h *Hygiene) writeTextfileProm(name, content string) {
	dir := h.textfilePromDir()
	fail := func(err error) {
		h.state.SuspectLog("textfile-prom", fmt.Sprintf(
			"textfile prom %s unwritable (dir=%s): %v", name, dir, err),
			h.cfg.SuspectLogCadence)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
		return
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		fail(err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		fail(err)
	}
}

// textfileProm accumulates HELP/TYPE/sample lines for one textfile —
// headers once per family (the textfile collector rejects duplicate
// HELP/TYPE). kinedb's promBuf parity, kept file-local.
type textfileProm struct {
	b    strings.Builder
	seen map[string]bool
}

func (p *textfileProm) header(name, help string) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func (p *textfileProm) gauge(name, help string, v float64) {
	p.header(name, help)
	fmt.Fprintf(&p.b, "%s %s\n", name,
		strconv.FormatFloat(v, 'f', -1, 64))
}

func (p *textfileProm) String() string { return p.b.String() }
