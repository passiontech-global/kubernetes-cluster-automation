// phase1_fixes_test.go — regression tests for envx.Knob{Name, Resolve},
// const expressions, binary computed keys, and range-var reassignment.
package envdoc

import (
	"path/filepath"
	"testing"
)

func TestScanTreeKnobStructConstExprAndRangeReassign(t *testing.T) {
	root := t.TempDir()
	envxDir := filepath.Join(root, "envxlib")
	fixtureEnvx(t, envxDir)
	modRoot := filepath.Join(root, "mod")

	writeFile(t, filepath.Join(modRoot, "cmd", "app", "main.go"), `package main

import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

const (
	prefix = "MY_APP_"
	fullKey = prefix + "RATIO"
	aliasKey = fullKey
)

func main() {
	_ = envx.Getenv(aliasKey, "")
	_ = envx.Knob{
		Name: "KNOB_RESOLVE_ENV",
		Resolve: func(k string) {
			_ = envx.Getenv(k, "1")
		},
	}
	envx.Apply([]envx.Knob{
		{Name: "SLICE_KNOB_ENV", Resolve: func(k string) {
			_ = envx.Getenv(k, "1")
		}},
		{"UNKEYED_KNOB_ENV", func(k string) {
			_ = envx.Getenv(k, "1")
		}},
	})
	for _, k := range []string{"SHADOW_SAFE_ENV"} {
		if true {
			k := dynName()
			k = dynName()
			_ = k
		}
		_ = envx.Getenv(k, "")
	}
	for _, k := range []string{"REASSIGNED_ENV"} {
		k = dynName()
		_ = envx.Getenv(k, "")
	}
	_ = envx.Getenv("DYN_" + dynName(), "")
}

func dynName() string { return "X" }
`)

	res, err := ScanTree(Options{
		Root:    modRoot,
		EnvxDir: envxDir,
	})
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	for _, want := range []string{
		"MY_APP_RATIO",
		"KNOB_RESOLVE_ENV",
		"SLICE_KNOB_ENV",
		"UNKEYED_KNOB_ENV",
		"SHADOW_SAFE_ENV",
	} {
		if _, ok := res.Referenced[want]; !ok {
			t.Errorf("Referenced missing %q (got %v)", want, res.Referenced)
		}
	}
	if len(res.Unresolved) != 2 {
		t.Fatalf("Unresolved = %v (count=%d), want 2 (reassigned range var + computed binary expr)", res.Unresolved, len(res.Unresolved))
	}
}
