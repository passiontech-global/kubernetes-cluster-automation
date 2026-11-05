package hostmetrics

import (
	"path/filepath"
	"slices"
	"testing"
)

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
	write(t, unit, "[Unit]\n")
	write(t, config, k0sCleanYAML())
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
	write(t, unit, "[Unit]\n")
	// Removed flag + a bogus extra key inside the otherwise-clean set.
	write(t, config,
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
	write(t, unit, "[Unit]\n")
	write(t, config,
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
	if len(missing) != len(defaultExpectedKCMArgs) {
		t.Fatalf("missing-key count=%d want %d (all expected keys)",
			len(missing), len(defaultExpectedKCMArgs))
	}
}

func TestScanK0sDriftUnreadable(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
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
	write(t, config, "  {not: [valid: yaml\n")
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
	write(t, unit, "[Unit]\n")
	write(t, config,
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
