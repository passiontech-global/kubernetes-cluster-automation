// Package promfile is the shared builder + installer for
// node-exporter textfile-collector (.prom) files — the channel the
// subsystems that can't rely on a Prometheus scrape use to export
// metrics (kinedb on the standalone Kine DB VM, controllerhygiene's
// node_agent_* checks, hostmetrics' standalone prom_emit port). The
// DaemonSet bind-mounts /host/var/lib/node-exporter rw for exactly
// this: each writer renders a .prom file under the mounted textfile
// dir and node_exporter ingests it on its next scan.
//
// Two contracts the collector enforces (a violation rejects the
// WHOLE file, not just the offending line):
//
//   - "# HELP" / "# TYPE" header lines appear at most once per
//     metric family — Builder dedupes them by name.
//   - Samples are `name{labels} value` — Builder renders values
//     with strconv.FormatFloat 'f' -1; callers that pre-render
//     (hostmetrics sorts/dedupes series and emits counters too)
//     append raw lines via Line.
//
// Write stages through a CreateTemp ".<name>.*" staging file and
// renames — node_exporter globs "*.prom" and must never see a
// partial file. The staging name deliberately is NOT hostutil's
// ".tmp-<name>" convention: ".tmp-x.prom" still ENDS in .prom and
// Go's glob * swallows the leading dot, so it would match the
// collector's glob. ".x.prom.<rand>" cannot match.
package promfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// Builder accumulates HELP/TYPE/sample lines for one textfile.
// Headers (# HELP / # TYPE) are emitted once per metric family —
// node_exporter's textfile collector rejects duplicate HELP/TYPE
// lines for the same metric name.
type Builder struct {
	b    strings.Builder
	seen map[string]bool
}

// Header emits the "# HELP name help" / "# TYPE name gauge" pair
// once per name — also usable standalone to emit a headers-only
// family (a check with no samples emits the header so the series
// goes absent rather than rendering a stale value).
func (b *Builder) Header(name, help string) {
	b.HeaderType(name, help, "gauge")
}

// HeaderType is Header for non-gauge families — the textfile
// writer that renders counters (hostmetrics' vmstat swap-thrash
// series) passes "counter".
func (b *Builder) HeaderType(name, help, typ string) {
	if b.seen == nil {
		b.seen = map[string]bool{}
	}
	if b.seen[name] {
		return
	}
	b.seen[name] = true
	fmt.Fprintf(&b.b, "# HELP %s %s\n# TYPE %s %s\n",
		name, help, name, typ)
}

// Gauge emits the gauge header (once) then the bare sample
// `name v`.
func (b *Builder) Gauge(name, help string, v float64) {
	b.GaugeLabels(name, help, "", v)
}

// GaugeLabels is Gauge with a pre-rendered label set
// (`k="v",k2="v2"`) — the sample lands as `name{labels} v`.
func (b *Builder) GaugeLabels(name, help, labels string, v float64) {
	b.Header(name, help)
	val := strconv.FormatFloat(v, 'f', -1, 64)
	if labels != "" {
		fmt.Fprintf(&b.b, "%s{%s} %s\n", name, labels, val)
	} else {
		fmt.Fprintf(&b.b, "%s %s\n", name, val)
	}
}

// Line appends a pre-rendered sample line verbatim — for callers
// that build `name{labels} v` themselves (sorting/dedup/counter
// formatting happens outside the Builder).
func (b *Builder) Line(sample string) {
	b.b.WriteString(sample)
	b.b.WriteByte('\n')
}

func (b *Builder) String() string { return b.b.String() }

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// EscapeLabelValue applies the textfile-format label escaping
// (backslash, double-quote and newline).
func EscapeLabelValue(v string) string {
	return labelEscaper.Replace(v)
}

// stagingPattern is Write's CreateTemp pattern: a leading dot keeps
// the file out of casual listings and the random suffix means it
// can never end in ".prom" — node_exporter's "*.prom" glob would
// match ANY name ending in .prom (the * swallows a leading dot).
func stagingPattern(name string) string { return "." + name + ".*" }

// Write atomically installs content as <dir>/<name>: MkdirAll, then
// hostutil.WriteAtomic (CreateTemp staging, payload fsync, rename,
// dir fsync) — the textfile collector rejects partially-written
// files, and without the fsyncs a crash can leave a
// renamed-but-empty file behind (or lose the rename itself). The
// staging shape stays promfile's own: see stagingPattern — sharing
// hostutil's ".tmp-" convention here would put scrapeable
// ".*.prom" names in the collector's glob.
func Write(dir, name string, content []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return hostutil.WriteAtomic(filepath.Join(dir, name), content, hostutil.AtomicOpts{
		Stage:   hostutil.StageTempPattern(stagingPattern(name)),
		Mode:    0o644,
		DirSync: true,
	})
}
