package k0sdrift

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/k0sconfig"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cleanK0sYAML renders a k0s.yaml whose controllerManager.extraArgs
// matches k0sconfig.DefaultExpectedKCMArgs exactly — the only shape
// that produces zero missing-key findings.
func cleanK0sYAML(extraKeys ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: k0s.k0sproject.io/v1beta1\n" +
		"kind: ClusterConfig\nspec:\n  controllerManager:\n    extraArgs:\n")
	for _, k := range k0sconfig.DefaultExpectedKCMArgs {
		b.WriteString("      " + k + ": \"5\"\n")
	}
	for _, k := range extraKeys {
		b.WriteString("      " + k + ": \"9\"\n")
	}
	return b.String()
}

// driftCLI runs runCheck against temp files and returns
// (exit code, output).
func driftCLI(t *testing.T, cfg k0sconfig.K0sDriftConfig) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runCheck(context.Background(), cfg, &out)
	return code, out.String()
}

func TestCmdArgParsing(t *testing.T) {
	if code := Cmd(context.Background(), []string{"--bogus"}); code != 2 {
		t.Fatalf("--bogus=%d want 2", code)
	}
	if code := Cmd(context.Background(), []string{"-h"}); code != 0 {
		t.Fatalf("-h=%d want 0", code)
	}
	if code := Cmd(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("--help=%d want 0", code)
	}
}

func TestRunCheckClean(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config, cleanK0sYAML())
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
	if code != 0 {
		t.Fatalf("exit=%d want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "check-k0s-drift: OK") {
		t.Fatalf("missing OK line:\n%s", out)
	}
}

func TestRunCheckFindings(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	// Removed flag + a bogus extra key inside the otherwise-clean set.
	write(t, config,
		cleanK0sYAML("concurrent-service-syncs", "bogus-extra-flag"))
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
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
		"not in expected set: concurrent-service-syncs") {
		t.Fatalf("removed flag double-counted as extra:\n%s", out)
	}
}

func TestRunCheckMissingKey(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  controllerManager:\n    extraArgs: {}\n")
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "missing on node:") ||
		!strings.Contains(out, "kube-api-qps") {
		t.Fatalf("missing-key line absent:\n%s", out)
	}
}

func TestRunCheckUnreadable(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	// Missing file → unreadable drift.
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
	if code != 1 || !strings.Contains(out, "DRIFT") {
		t.Fatalf("missing file: exit=%d:\n%s", code, out)
	}
	// Unparseable → same finding.
	write(t, config, "  {not: [valid: yaml\n")
	code, out = driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
	if code != 1 || !strings.Contains(out, "DRIFT") {
		t.Fatalf("unparseable: exit=%d:\n%s", code, out)
	}
}

func TestRunCheckNotAController(t *testing.T) {
	dir := t.TempDir()
	// No unit file → the gate skips the check entirely (worker
	// nodes carry a differently-shaped k0s.yaml — running there
	// would report phantom missing-key drift).
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   filepath.Join(dir, "k0s.yaml"),
		UnitFile:     filepath.Join(dir, "k0scontroller.service"),
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
		RemovedFlags: []string{"concurrent-service-syncs"},
	})
	if code != 0 {
		t.Fatalf("exit=%d want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "not a k0s controller") {
		t.Fatalf("missing skip line:\n%s", out)
	}
}

func TestRunCheckCustomSets(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config,
		"spec:\n  controllerManager:\n    extraArgs:\n      a: \"1\"\n      dead-flag: \"2\"\n")
	code, out := driftCLI(t, k0sconfig.K0sDriftConfig{
		ConfigFile:   config,
		UnitFile:     unit,
		ExpectedKeys: []string{"a", "b"},
		RemovedFlags: []string{"dead-flag"},
	})
	if code != 1 {
		t.Fatalf("exit=%d want 1:\n%s", code, out)
	}
	got := out
	if !strings.Contains(got, "'dead-flag'") {
		t.Fatalf("custom removed flag not flagged:\n%s", got)
	}
	// "a" present → only "b" is missing.
	if !strings.Contains(got, "missing on node: b") {
		t.Fatalf("missing-key b absent:\n%s", got)
	}
	// The default removed flag must not fire when overridden.
	if strings.Contains(got, "concurrent-service-syncs") {
		t.Fatalf("default removed flag leaked:\n%s", got)
	}
}

// TestSplitCSV: trimming + empty-element drop; empty input yields an
// empty NON-nil slice — "flag provided empty" must be distinguishable
// from "flag absent" (nil).
func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a , b,,c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("split=%v want [a b c]", got)
	}
	got = splitCSV("")
	if got == nil || len(got) != 0 {
		t.Fatalf("empty split=%#v want empty non-nil", got)
	}
}

// TestCmdEndToEndFlags: Cmd's flag wiring — provided --config /
// --unit-file / --expected-keys / --removed-flags reach the scan,
// and the report's exit code is the process contract (0 clean,
// 1 drift). Output goes to os.Stdout by design; only the code is
// asserted.
func TestCmdEndToEndFlags(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config, cleanK0sYAML())

	// Clean: the pinned expected set + default removed flag → 0.
	code := Cmd(context.Background(), []string{
		"--config", config,
		"--unit-file", unit,
		"--expected-keys", strings.Join(k0sconfig.DefaultExpectedKCMArgs, ","),
		"--removed-flags", "concurrent-service-syncs",
	})
	if code != 0 {
		t.Fatalf("clean run exit=%d want 0", code)
	}

	// Drift: an extra key the provided expected set doesn't know → 1.
	write(t, config, cleanK0sYAML("bogus-extra-flag"))
	code = Cmd(context.Background(), []string{
		"--config", config,
		"--unit-file", unit,
		"--expected-keys", strings.Join(k0sconfig.DefaultExpectedKCMArgs, ","),
		"--removed-flags", "concurrent-service-syncs",
	})
	if code != 1 {
		t.Fatalf("drift run exit=%d want 1", code)
	}
}

// TestCmdProvidedEmptyFlags: --expected-keys= (explicit empty) is
// NOT the same as absent — provided-vs-absent decides whether the
// repo-pinned default applies. An explicitly empty expected set
// turns every pinned key into an extra-key finding → drift.
func TestCmdProvidedEmptyFlags(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	config := filepath.Join(dir, "k0s.yaml")
	write(t, unit, "[Unit]\n")
	write(t, config, cleanK0sYAML())

	code := Cmd(context.Background(), []string{
		"--config", config,
		"--unit-file", unit,
		"--expected-keys=",
		"--removed-flags=",
	})
	if code != 1 {
		t.Fatalf("explicit-empty expected set exit=%d want 1 (drift)", code)
	}
}

// TestRunCheckCanceledCtx: a cancelled context short-circuits before
// the scan — the ops runtime-error exit, not a drift verdict.
func TestRunCheckCanceledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	code := runCheck(ctx, k0sconfig.K0sDriftConfig{
		ConfigFile:   "/nonexistent/k0s.yaml",
		UnitFile:     "/nonexistent/k0scontroller.service",
		ExpectedKeys: k0sconfig.DefaultExpectedKCMArgs,
	}, &out)
	if code != 1 {
		t.Fatalf("canceled ctx exit=%d want 1", code)
	}
}
