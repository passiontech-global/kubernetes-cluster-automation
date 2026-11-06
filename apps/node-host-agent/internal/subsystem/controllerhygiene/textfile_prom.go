// textfile_prom.go — node-exporter textfile channel helpers shared
// by the control-plane checks that export node_agent_* gauges.
//
// W10 metrics note: the subsystem prometheus registry is owned by
// controllerhygiene.go's New() (outside this file), so the
// node_agent_* gauges are emitted through the node-exporter
// textfile channel — the DaemonSet bind-mounts
// /host/var/lib/node-exporter rw for exactly this (kinedb/hostconfig
// parity). The .prom rendering + atomic install machinery lives in
// platform/promfile.
package controllerhygiene

import (
	"fmt"
	"path/filepath"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// textfileDirOverride wins over the K0sDir-derived textfile dir —
// test seam.
var textfileDirOverride = ""

// textfilePromDir resolves the node-exporter textfile drop dir:
// K0sDir is <hostRoot>/var/lib/k0s, so the dir is its sibling
// <hostRoot>/var/lib/node-exporter/textfile (DaemonSet:
// /host/var/lib/..., standalone: /var/lib/...). The override wins
// for tests.
func (d *deps) textfilePromDir() string {
	if textfileDirOverride != "" {
		return textfileDirOverride
	}
	return filepath.Join(filepath.Dir(d.cfg.K0sDir),
		"node-exporter", "textfile")
}

// writeTextfileProm atomically installs content as <dir>/<name>
// (promfile.Write: tmp+rename — node_exporter only reads complete
// .prom files). Failures go through suspectLog — a broken/missing
// mount must not spam the watchdog tail every cycle.
func (d *deps) writeTextfileProm(name, content string) {
	dir := d.textfilePromDir()
	if err := promfile.Write(dir, name, []byte(content)); err != nil {
		d.state.SuspectLog("textfile-prom", fmt.Sprintf(
			"textfile prom %s unwritable (dir=%s): %v", name, dir, err),
			d.cfg.SuspectLogCadence)
	}
}
