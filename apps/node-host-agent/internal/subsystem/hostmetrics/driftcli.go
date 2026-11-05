// driftcli.go — the library half of `node-host-agent check-k0s-drift`:
// the on-node half of scripts/check-node-config-drift.sh. The bash
// compared each controller's /etc/k0s/k0s.yaml extraArgs against the
// repo's k0sctl.yaml over SSH; the scan reports the same three
// findings the node_k0s_config_drift collector already exports —
// removed-flag, extra-key, missing-key — but on THIS node's file.
//
// Why it matters: k0sctl does NOT regenerate /etc/k0s/k0s.yaml on
// upgrade, so a config key dropped from the repo lives on the node
// forever. When a new k8s version removes that flag the component
// crashloops on the next restart (incident 2026-10-30:
// concurrent-service-syncs removed in k8s 1.37 → KCM dead → PDB
// freeze → drain autopilot stalled → rabbitmq lost a replica).
//
// The flag parsing and the human-readable DRIFT/REMOVED-FLAG report
// live in internal/ops/k0sdrift; this file owns K0sDriftConfig and
// the scan so both the CLI and the collector share one code path.
package hostmetrics

import (
	"os"
	"regexp"

	"sigs.k8s.io/yaml"
)

// K0sDriftConfig carries the check-k0s-drift inputs.
type K0sDriftConfig struct {
	// ConfigFile is the k0s.yaml to scan (default /etc/k0s/k0s.yaml).
	ConfigFile string
	// UnitFile is the k0s controller gate — the check only runs on
	// nodes carrying k0scontroller.service, same rule the collector
	// uses to decide whether node_k0s_config_drift emits at all
	// (a worker's k0s.yaml has no controllerManager block, so an
	// un-gated run would report every expected key as missing).
	// Default /etc/systemd/system/k0scontroller.service; point it at
	// any existing path (e.g. /dev/null) to force the check.
	UnitFile string
	// ExpectedKeys is the expected controllerManager.extraArgs key
	// set — default: the repo-pinned set (defaultExpectedKCMArgs).
	// nil selects the default; an empty non-nil slice is honored as
	// "no expected keys" (every node key reports as extra).
	ExpectedKeys []string
	// RemovedFlags are config keys removed upstream whose presence
	// means drift — default: defaultRemovedFlags. nil selects the
	// default; an empty non-nil slice disables the removed check.
	RemovedFlags []string
}

func (c *K0sDriftConfig) applyDefaults() {
	if c.ConfigFile == "" {
		c.ConfigFile = defaultK0sConfigFile
	}
	if c.UnitFile == "" {
		c.UnitFile = defaultK0sUnitFile
	}
	if c.ExpectedKeys == nil {
		c.ExpectedKeys = defaultExpectedKCMArgs
	}
	if c.RemovedFlags == nil {
		c.RemovedFlags = defaultRemovedFlags
	}
}

// DriftFinding is one drift finding — Reason is removed-flag /
// extra-key / missing-key / unreadable (the collector's
// node_k0s_config_drift{reason,key} label values); Key is the flag
// or extraArgs key it fired on ("k0s.yaml" for unreadable).
type DriftFinding struct {
	Reason string
	Key    string
}

// K0sDriftScan is ScanK0sDrift's result: the normalized config
// (defaults applied — callers print THESE paths, not their raw
// input), whether the unit-file gate skipped the scan, and every
// finding in scanK0sDrift's sorted order.
type K0sDriftScan struct {
	Config        K0sDriftConfig
	NotController bool
	Findings      []DriftFinding
}

// ScanK0sDrift runs the check-k0s-drift scan: the k0scontroller
// unit-file gate (absent → NotController, no findings), the k0s.yaml
// read + parse and the shared scanK0sDrift pass. The check-k0s-drift
// CLI renders the findings; the collector keeps its own scrape-time
// path through scanK0sDrift directly.
func ScanK0sDrift(cfg K0sDriftConfig) K0sDriftScan {
	cfg.applyDefaults()
	scan := K0sDriftScan{Config: cfg}
	if _, err := os.Stat(cfg.UnitFile); err != nil {
		scan.NotController = true
		return scan
	}
	data, err := os.ReadFile(cfg.ConfigFile)
	var parsed map[string]any
	parseOK := err == nil && yaml.Unmarshal(data, &parsed) == nil

	removedRe := make(map[string]*regexp.Regexp, len(cfg.RemovedFlags))
	for _, f := range cfg.RemovedFlags {
		// Same anchored key match the collector compiles in New().
		removedRe[f] = regexp.MustCompile(
			`(?m)^\s*` + regexp.QuoteMeta(f) + `\s*:`)
	}
	expected := make(map[string]bool, len(cfg.ExpectedKeys))
	for _, k := range cfg.ExpectedKeys {
		expected[k] = true
	}
	for _, f := range scanK0sDrift(data, parsed, parseOK,
		removedRe, expected, cfg.ExpectedKeys) {
		scan.Findings = append(scan.Findings,
			DriftFinding{Reason: f.reason, Key: f.key})
	}
	return scan
}
