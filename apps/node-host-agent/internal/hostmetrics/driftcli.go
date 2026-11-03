// driftcli.go — `node-host-agent check-k0s-drift`: the on-node half
// of scripts/check-node-config-drift.sh. The bash compared each
// controller's /etc/k0s/k0s.yaml extraArgs against the repo's
// k0sctl.yaml over SSH; the CLI runs the same three findings the
// node_k0s_config_drift collector already exports — removed-flag,
// extra-key, missing-key — but on THIS node's file, printed for a
// human and mapped onto a 0/1 exit.
//
// Why it matters: k0sctl does NOT regenerate /etc/k0s/k0s.yaml on
// upgrade, so a config key dropped from the repo lives on the node
// forever. When a new k8s version removes that flag the component
// crashloops on the next restart (incident 2026-10-30:
// concurrent-service-syncs removed in k8s 1.37 → KCM dead → PDB
// freeze → drain autopilot stalled → rabbitmq lost a replica).
package hostmetrics

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

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

// RunK0sDriftCLI scans the k0s config and prints one DRIFT /
// REMOVED-FLAG line per finding in the shell script's phrasing.
// Returns the process exit code: 0 when clean (or the node is not a
// k0s controller), 1 on any drift.
func RunK0sDriftCLI(cfg K0sDriftConfig, out io.Writer) int {
	cfg.applyDefaults()
	if _, err := os.Stat(cfg.UnitFile); err != nil {
		fmt.Fprintf(out, "check-k0s-drift: %s absent — "+
			"not a k0s controller, skip\n", cfg.UnitFile)
		return 0
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
	findings := scanK0sDrift(data, parsed, parseOK,
		removedRe, expected, cfg.ExpectedKeys)
	if len(findings) == 0 {
		fmt.Fprintln(out, "check-k0s-drift: OK (khong drift)")
		return 0
	}

	// Aggregate the way the script did: one line listing every extra
	// key, one for every missing key, one REMOVED-FLAG line per flag.
	var extra, missing, removed []string
	unreadable := false
	for _, f := range findings {
		switch f.reason {
		case "extra-key":
			extra = append(extra, f.key)
		case "missing-key":
			missing = append(missing, f.key)
		case "removed-flag":
			removed = append(removed, f.key)
		default: // unreadable
			unreadable = true
		}
	}
	if unreadable {
		fmt.Fprintf(out,
			"DRIFT %s: khong doc duoc / parse duoc k0s.yaml\n",
			cfg.ConfigFile)
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		fmt.Fprintf(out,
			"DRIFT %s: key co tren node ma khong co trong expected: %s\n",
			cfg.ConfigFile, strings.Join(extra, " "))
	}
	if len(missing) > 0 {
		fmt.Fprintf(out,
			"DRIFT %s: key co trong expected ma thieu tren node: %s\n",
			cfg.ConfigFile, strings.Join(missing, " "))
	}
	slices.Sort(removed)
	for _, flag := range removed {
		fmt.Fprintf(out,
			"REMOVED-FLAG %s: k0s.yaml van con '%s' "+
				"(da xoa -> component se crashloop sau upgrade)\n",
			cfg.ConfigFile, flag)
	}
	return 1
}
