// k0sconfig_test.go — ScanK0sDrift's gate, findings and default
// resolution.

package k0sconfig

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// k0sCleanYAML renders a k0s.yaml whose controllerManager.extraArgs
// matches DefaultExpectedKCMArgs exactly — the only shape that
// produces zero missing-key findings.
func k0sCleanYAML(extraKeys ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: k0s.k0sproject.io/v1beta1\n" +
		"kind: ClusterConfig\nspec:\n  controllerManager:\n    extraArgs:\n")
	for _, k := range DefaultExpectedKCMArgs {
		b.WriteString("      " + k + ": \"5\"\n")
	}
	for _, k := range extraKeys {
		b.WriteString("      " + k + ": \"9\"\n")
	}
	return b.String()
}

// findingKeys returns the keys of every finding with the given
// reason, in scan order.
func findingKeys(scan K0sDriftScan, reason string) []string {
	var out []string
	for _, f := range scan.Findings {
		if f.Reason == reason {
			out = append(out, f.Key)
		}
	}
	return out
}

func TestScanK0sDriftNotAController(t *testing.T) {
	dir := t.TempDir()
	// No unit file → the gate skips the check entirely (worker
	// nodes carry a differently-shaped k0s.yaml — running there
	// would report phantom missing-key drift).
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile: filepath.Join(dir, "k0s.yaml"),
		UnitFile:   filepath.Join(dir, "k0scontroller.service"),
	})
	if !scan.NotController {
		t.Fatal("NotController=false want true (unit file absent)")
	}
	if len(scan.Findings) != 0 {
		t.Fatalf("findings=%v want none", scan.Findings)
	}
}

func TestScanK0sDriftClean(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, unit, "[Unit]\n")
	testutil.WriteFile(t, config, k0sCleanYAML())
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	})
	if scan.NotController {
		t.Fatal("NotController=true want false")
	}
	if len(scan.Findings) != 0 {
		t.Fatalf("findings=%v want none", scan.Findings)
	}
	// The normalized config echoes the resolved paths back for the
	// CLI's report lines.
	if scan.Config.ConfigFile != config || scan.Config.UnitFile != unit {
		t.Fatalf("normalized config=%+v", scan.Config)
	}
}

func TestScanK0sDriftFindings(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, unit, "[Unit]\n")
	// Removed flag + a bogus extra key inside the otherwise-clean set.
	testutil.WriteFile(t, config,
		k0sCleanYAML("concurrent-service-syncs", "bogus-extra-flag"))
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	})
	if got := findingKeys(scan, "removed-flag"); !slices.Equal(got,
		[]string{"concurrent-service-syncs"}) {
		t.Fatalf("removed-flag=%v", got)
	}
	if got := findingKeys(scan, "extra-key"); !slices.Equal(got,
		[]string{"bogus-extra-flag"}) {
		t.Fatalf("extra-key=%v", got)
	}
	// The removed flag must not double-report as an extra key.
	if slices.Contains(findingKeys(scan, "extra-key"),
		"concurrent-service-syncs") {
		t.Fatalf("removed flag double-counted as extra: %+v", scan.Findings)
	}
}

func TestScanK0sDriftMissingKey(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, unit, "[Unit]\n")
	testutil.WriteFile(t, config,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  controllerManager:\n    extraArgs: {}\n")
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	})
	missing := findingKeys(scan, "missing-key")
	if !slices.Contains(missing, "kube-api-qps") {
		t.Fatalf("missing-key findings lack kube-api-qps: %v", missing)
	}
	if len(missing) != len(DefaultExpectedKCMArgs) {
		t.Fatalf("missing-key count=%d want %d (all expected keys)",
			len(missing), len(DefaultExpectedKCMArgs))
	}
}

func TestScanK0sDriftUnreadable(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, unit, "[Unit]\n")
	// Missing file → unreadable finding.
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	})
	if got := findingKeys(scan, "unreadable"); !slices.Equal(got,
		[]string{"k0s.yaml"}) {
		t.Fatalf("missing file: unreadable=%v", got)
	}
	// Unparseable → same finding.
	testutil.WriteFile(t, config, "  {not: [valid: yaml\n")
	scan = ScanK0sDrift(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	})
	if got := findingKeys(scan, "unreadable"); !slices.Equal(got,
		[]string{"k0s.yaml"}) {
		t.Fatalf("unparseable: unreadable=%v", got)
	}
}

func TestScanK0sDriftCustomSets(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, unit, "[Unit]\n")
	testutil.WriteFile(t, config,
		"spec:\n  controllerManager:\n    extraArgs:\n      a: \"1\"\n      dead-flag: \"2\"\n")
	scan := ScanK0sDrift(K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: []string{"a", "b"},
		RemovedFlags: []string{"dead-flag"},
	})
	if got := findingKeys(scan, "removed-flag"); !slices.Equal(got,
		[]string{"dead-flag"}) {
		t.Fatalf("custom removed flag not flagged: %v", got)
	}
	// "a" present → only "b" is missing.
	if got := findingKeys(scan, "missing-key"); !slices.Equal(got,
		[]string{"b"}) {
		t.Fatalf("missing-key=%v want [b]", got)
	}
	// The default removed flag must not fire when overridden.
	if slices.Contains(findingKeys(scan, "removed-flag"),
		"concurrent-service-syncs") {
		t.Fatalf("default removed flag leaked: %+v", scan.Findings)
	}
}

// TestScanK0sDriftConfigDefaults: nil slice fields select the
// repo-pinned defaults and the scan result carries the NORMALIZED
// config (callers print these paths, not their raw input). An empty
// non-nil ExpectedKeys is honored as "expect nothing" — every node
// key reports as extra — and an empty RemovedFlags disables the
// removed check.
func TestScanK0sDriftConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	testutil.WriteFile(t, unit, "[Unit]\nDescription=controller\n")

	scan := ScanK0sDrift(K0sDriftConfig{UnitFile: unit})
	if scan.NotController {
		t.Fatal("existing unit gated the scan off")
	}
	if scan.Config.ConfigFile != DefaultConfigFile {
		t.Fatalf("ConfigFile=%q want the default", scan.Config.ConfigFile)
	}
	if scan.Config.UnitFile != unit {
		t.Fatalf("UnitFile=%q want the given path", scan.Config.UnitFile)
	}
	if !slices.Equal(scan.Config.ExpectedKeys, DefaultExpectedKCMArgs) {
		t.Fatalf("ExpectedKeys=%v want the repo-pinned set", scan.Config.ExpectedKeys)
	}
	if !slices.Equal(scan.Config.RemovedFlags, DefaultRemovedFlags) {
		t.Fatalf("RemovedFlags=%v want the defaults", scan.Config.RemovedFlags)
	}

	// Empty non-nil overrides: no expected keys, no removed flags —
	// the node's flag can only be an extra.
	cfgFile := filepath.Join(dir, "k0s.yaml")
	testutil.WriteFile(t, cfgFile,
		"spec:\n  controllerManager:\n    extraArgs:\n      concurrent-service-syncs: \"4\"\n")
	scan2 := ScanK0sDrift(K0sDriftConfig{
		ConfigFile:   cfgFile,
		UnitFile:     unit,
		ExpectedKeys: []string{},
		RemovedFlags: []string{},
	})
	if got := findingKeys(scan2, "extra-key"); !slices.Equal(got, []string{"concurrent-service-syncs"}) {
		t.Fatalf("extra-key findings=%v want the node key", got)
	}
	if len(findingKeys(scan2, "removed-flag")) != 0 {
		t.Fatalf("removed check ran despite an empty RemovedFlags: %+v", scan2.Findings)
	}
	if len(findingKeys(scan2, "missing-key")) != 0 {
		t.Fatalf("missing-key reported with an empty expected set: %+v", scan2.Findings)
	}

	// A fully bare config: defaults applied, the missing default
	// unit gate skips the scan — no findings, no panic.
	scan3 := ScanK0sDrift(K0sDriftConfig{})
	if !scan3.NotController {
		t.Fatal("bare config ran without a controller unit")
	}
	if scan3.Config.UnitFile != DefaultUnitFile {
		t.Fatalf("UnitFile=%q want the default", scan3.Config.UnitFile)
	}
	if len(scan3.Findings) != 0 {
		t.Fatalf("gated scan produced findings: %+v", scan3.Findings)
	}
}
