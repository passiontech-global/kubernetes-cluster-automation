// genenvdoc renders ENV.md's enable-gates table to stdout — one row
// per Descriptor in cmd/agent/wiring.go (subsystem + default
// included), followed by any NODE_HOST_AGENT_ENABLE_* gate declared
// in internal/envnames but not wired as a descriptor
// (NODE_HOST_AGENT_ENABLE_FEEDER, read via envx.BoolKnob inside
// controllerhygiene), which gets an empty subsystem/default cell
// since it has no registry entry. scripts/gen-envdoc.sh splices the
// output into ENV.md's "## Enable gates" section between its prose
// header and the knob tables.
//
// Run via `moon run node-host-agent:envdoc` or:
//
//	go run ./internal/envdoc/cmd/genenvdoc -root <module-root>
//
// Parsing is AST-based (internal/envdoc/scan), so comments inside the
// registry cannot forge or split rows the way they could trip the
// line-based awk this replaces.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envdoc/scan"
)

// enablePrefix marks a contract value as an enable gate. Gates
// matching it that ScanGates did not find wired as a Descriptor
// EnvFlag are appended to the table.
const enablePrefix = "NODE_HOST_AGENT_ENABLE_"

func main() {
	// root is the node-host-agent module root; "." is right for
	// scripts/gen-envdoc.sh, which cds to the module root first.
	root := flag.String("root", ".", "node-host-agent module root")
	flag.Parse()

	c, err := scan.CollectContract(*root)
	if err != nil {
		fatal(err)
	}
	gates, err := scan.ScanGates(*root, c)
	if err != nil {
		fatal(err)
	}

	wired := map[string]bool{}
	for _, g := range gates {
		wired[g.EnvFlag] = true
	}
	var unwired []string
	for v := range c.Values {
		if strings.HasPrefix(v, enablePrefix) && !wired[v] {
			unwired = append(unwired, v)
		}
	}
	sort.Strings(unwired)

	for _, g := range gates {
		emit(g.EnvFlag, g.Name, g.Default)
	}
	// A declared-but-unwired gate has no registry entry, hence no
	// subsystem and no tri-state default — emit renders "" as "—".
	for _, v := range unwired {
		emit(v, "", "")
	}
}

// defaultCell renders the Default expression as the VALUE it
// resolves to — the raw wiring.go selector text (`envx.ModeOn`,
// `onOff(w.defKube)`) is plumbing, not an operator fact. The three
// envx mode spellings map to their tri-state word; the defKube flip
// (pod mode on, standalone off) renders both faces. Anything else
// falls back to the verbatim expression so an unrecognized shape
// still lands in the doc.
func defaultCell(def string) string {
	switch def {
	case "envx.ModeOn":
		return "`on`"
	case "envx.ModeOff":
		return "`off`"
	case "envx.ModeAuto":
		return "`auto`"
	case "onOff(w.defKube)":
		return "`on` (pod) / `off` (standalone)"
	case "":
		return "—"
	default:
		return "`" + def + "`"
	}
}

// emit prints one markdown table row; an empty env var, subsystem or
// default renders as "—" (hubsync has no env gate, some descriptors
// no default), matching the doc's existing convention.
func emit(envFlag, subsystem, def string) {
	if envFlag == "" {
		envFlag = "—"
	} else {
		envFlag = "`" + envFlag + "`"
	}
	if subsystem == "" {
		subsystem = "—"
	}
	fmt.Printf("| %s | %s | %s |\n", envFlag, subsystem, defaultCell(def))
}

// fatal reports a scanner failure on stderr and exits nonzero — the
// calling script runs with `set -e`, so ENV.md is left untouched.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "genenvdoc:", err)
	os.Exit(1)
}
