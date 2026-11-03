package hostmetrics

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// driftCLI runs RunK0sDriftCLI against temp files and returns
// (exit code, output).
func driftCLI(t *testing.T, unit, config string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := RunK0sDriftCLI(K0sDriftConfig{
		ConfigFile: config,
		UnitFile:   unit,
	}, &out)
	return code, out.String()
}

func TestRunK0sDriftCLIClean(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config, k0sCleanYAML())
	code, out := driftCLI(t, unit, config)
	if code != 0 {
		t.Fatalf("exit=%d want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "check-k0s-drift: OK") {
		t.Fatalf("missing OK line:\n%s", out)
	}
}

func TestRunK0sDriftCLIFindings(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	// Removed flag + a bogus extra key inside the otherwise-clean set.
	write(t, config,
		k0sCleanYAML("concurrent-service-syncs", "bogus-extra-flag"))
	code, out := driftCLI(t, unit, config)
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out)
	}
	for _, want := range []string{
		"REMOVED-FLAG", "'concurrent-service-syncs'",
		"bogus-extra-flag",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// The removed flag must not double-report as an extra key.
	if strings.Contains(out,
		"khong co trong expected: concurrent-service-syncs") {
		t.Fatalf("removed flag double-counted as extra:\n%s", out)
	}
}

func TestRunK0sDriftCLIMissingKey(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  controllerManager:\n    extraArgs: {}\n")
	code, out := driftCLI(t, unit, config)
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "thieu tren node:") ||
		!strings.Contains(out, "kube-api-qps") {
		t.Fatalf("missing-key line absent:\n%s", out)
	}
}

func TestRunK0sDriftCLIUnreadable(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	// Missing file → unreadable drift.
	code, out := driftCLI(t, unit, config)
	if code != 1 || !strings.Contains(out, "DRIFT") {
		t.Fatalf("missing file: exit=%d:\n%s", code, out)
	}
	// Unparseable → same finding.
	write(t, config, "  {not: [valid: yaml\n")
	code, out = driftCLI(t, unit, config)
	if code != 1 || !strings.Contains(out, "DRIFT") {
		t.Fatalf("unparseable: exit=%d:\n%s", code, out)
	}
}

func TestRunK0sDriftCLINotAController(t *testing.T) {
	dir := t.TempDir()
	// No unit file → the gate skips the check entirely (worker
	// nodes carry a differently-shaped k0s.yaml — running there
	// would report phantom missing-key drift).
	code, out := driftCLI(t,
		filepath.Join(dir, "k0scontroller.service"),
		filepath.Join(dir, "k0s.yaml"))
	if code != 0 {
		t.Fatalf("exit=%d want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "not a k0s controller") {
		t.Fatalf("missing skip line:\n%s", out)
	}
}

func TestRunK0sDriftCLICustomSets(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config,
		"spec:\n  controllerManager:\n    extraArgs:\n      a: \"1\"\n      dead-flag: \"2\"\n")
	var out bytes.Buffer
	code := RunK0sDriftCLI(K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: []string{"a", "b"},
		RemovedFlags: []string{"dead-flag"},
	}, &out)
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "'dead-flag'") {
		t.Fatalf("custom removed flag not flagged:\n%s", got)
	}
	// "a" present → only "b" is missing.
	if !strings.Contains(got, "thieu tren node: b") {
		t.Fatalf("missing-key b absent:\n%s", got)
	}
	// The default removed flag must not fire when overridden.
	if strings.Contains(got, "concurrent-service-syncs") {
		t.Fatalf("default removed flag leaked:\n%s", got)
	}
}
