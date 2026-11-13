// k0sconfig.go — the k0s config drift scan shared by the
// node_k0s_config_drift collector (subsystem/hostmetrics) and the
// `check-k0s-drift` CLI (ops/k0sdrift): the on-node half of
// scripts/check-node-config-drift.sh. The bash compared each
// controller's /etc/k0s/k0s.yaml extraArgs against the repo's
// k0sctl.yaml over SSH; the scan reports the same three findings the
// collector exports — removed-flag, extra-key, missing-key — but on
// THIS node's file.
//
// Why it matters: k0sctl does NOT regenerate /etc/k0s/k0s.yaml on
// upgrade, so a config key dropped from the repo lives on the node
// forever. When a new k8s version removes that flag the component
// crashloops on the next restart (incident 2026-10-30:
// concurrent-service-syncs removed in k8s 1.37 → KCM dead → PDB
// freeze → drain autopilot stalled → rabbitmq lost a replica).
//
// Lives in internal/domain so ops/k0sdrift can drive it without
// pulling in subsystem/hostmetrics (the collector stays there and
// calls Scan through its own mtime+size cache).
package k0sconfig

import (
	"cmp"
	"os"
	"regexp"
	"slices"

	"sigs.k8s.io/yaml"
)

const (
	// DefaultConfigFile is the k0s.yaml the scan reads by default.
	DefaultConfigFile = "/etc/k0s/k0s.yaml"
	// DefaultUnitFile is the k0s controller gate — the check only
	// runs on nodes carrying k0scontroller.service, same rule the
	// collector uses to decide whether node_k0s_config_drift emits
	// at all (a worker's k0s.yaml has no controllerManager block, so
	// an un-gated run would report every expected key as missing).
	DefaultUnitFile = "/etc/systemd/system/k0scontroller.service"
)

// DefaultRemovedFlags are k0s config keys removed upstream whose
// presence means the rendered config drifted from the expected one.
var DefaultRemovedFlags = []string{"concurrent-service-syncs"}

// DefaultExpectedKCMArgs is the expected key set of
// spec.controllerManager.extraArgs — the 11 keys pinned identically in
// all three bootstrap/*/k0sctl.yaml (cicd/nonprod/production). A node
// carrying extra/missing keys vs this set drifts (extra-key/missing-key).
var DefaultExpectedKCMArgs = []string{
	"concurrent-deployment-syncs",
	"concurrent-gc-syncs",
	"concurrent-replicaset-syncs",
	"kube-api-burst",
	"kube-api-qps",
	"leader-elect-lease-duration",
	"leader-elect-renew-deadline",
	"leader-elect-retry-period",
	"node-monitor-grace-period",
	"node-monitor-period",
	"terminated-pod-gc-threshold",
}

// K0sDriftConfig carries the check-k0s-drift inputs.
type K0sDriftConfig struct {
	// ConfigFile is the k0s.yaml to scan (default DefaultConfigFile).
	ConfigFile string
	// UnitFile is the k0s controller gate (default DefaultUnitFile);
	// point it at any existing path (e.g. /dev/null) to force the
	// check.
	UnitFile string
	// ExpectedKeys is the expected controllerManager.extraArgs key
	// set — default: the repo-pinned set (DefaultExpectedKCMArgs).
	// nil selects the default; an empty non-nil slice is honored as
	// "no expected keys" (every node key reports as extra).
	ExpectedKeys []string
	// RemovedFlags are config keys removed upstream whose presence
	// means drift — default: DefaultRemovedFlags. nil selects the
	// default; an empty non-nil slice disables the removed check.
	RemovedFlags []string
}

func (c *K0sDriftConfig) applyDefaults() {
	if c.ConfigFile == "" {
		c.ConfigFile = DefaultConfigFile
	}
	if c.UnitFile == "" {
		c.UnitFile = DefaultUnitFile
	}
	if c.ExpectedKeys == nil {
		c.ExpectedKeys = DefaultExpectedKCMArgs
	}
	if c.RemovedFlags == nil {
		c.RemovedFlags = DefaultRemovedFlags
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
// finding in Scan's sorted order.
type K0sDriftScan struct {
	Config        K0sDriftConfig
	NotController bool
	Findings      []DriftFinding
}

// ScanK0sDrift runs the check-k0s-drift scan: the k0scontroller
// unit-file gate (absent → NotController, no findings), the k0s.yaml
// read + parse and the shared Scan pass. The check-k0s-drift CLI
// renders the findings; the collector keeps its own scrape-time
// path through Scan directly.
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
	scan.Findings = append(scan.Findings,
		Scan(data, parsed, parseOK, removedRe, expected, cfg.ExpectedKeys)...)
	return scan
}

// kcmExtraArgKeys returns the sorted key set of
// spec.controllerManager.extraArgs in the parsed k0s.yaml — the same
// key list node-config-agent's drift task extracts with its awk block.
func kcmExtraArgKeys(parsed map[string]any) []string {
	spec, _ := parsed["spec"].(map[string]any)
	cm, _ := spec["controllerManager"].(map[string]any)
	ea, _ := cm["extraArgs"].(map[string]any)
	keys := make([]string, 0, len(ea))
	for k := range ea {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Scan computes every drift finding on one read of k0s.yaml —
// shared between the node_k0s_config_drift collector (which drives
// it through its own mtime+size cache) and ScanK0sDrift.
// parseOK=false (unreadable/unparseable file) keeps the old drift=1
// semantics as a single {unreadable,k0s.yaml}.
func Scan(data []byte, parsed map[string]any, parseOK bool,
	removedRe map[string]*regexp.Regexp, expected map[string]bool,
	expectedOrder []string) []DriftFinding {
	if !parseOK {
		return []DriftFinding{{"unreadable", "k0s.yaml"}}
	}
	var findings []DriftFinding
	for flag, re := range removedRe {
		if re.Match(data) {
			findings = append(findings, DriftFinding{"removed-flag", flag})
		}
	}
	nodeKeys := kcmExtraArgKeys(parsed)
	nodeSet := make(map[string]bool, len(nodeKeys))
	for _, k := range nodeKeys {
		nodeSet[k] = true
		// A removed flag found in extraArgs reports only under
		// removed-flag — no double counting as extra-key.
		if _, isRemoved := removedRe[k]; !expected[k] && !isRemoved {
			findings = append(findings, DriftFinding{"extra-key", k})
		}
	}
	for _, k := range expectedOrder {
		if !nodeSet[k] {
			findings = append(findings, DriftFinding{"missing-key", k})
		}
	}
	slices.SortFunc(findings, func(a, b DriftFinding) int {
		if c := cmp.Compare(a.Reason, b.Reason); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return findings
}
