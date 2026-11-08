// scan_test.go — unit tests for the envdoc AST passes: contract
// collection, the source walk, the wiring.go gates table, and the
// small expression helpers they share. Everything runs against a
// synthetic module tree built in a temp dir, so no test depends on
// the shape of the real repo (the honesty test in internal/envdoc
// already covers that end to end).
package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testImportPath = envnamesImportPath

// writeModule lays down a fake node-host-agent module tree: root is
// the module root; files maps "internal/envnames/x.go"-style rel
// paths to source. Parent dirs are created as needed.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root
}

// contractFixture is the contract CollectContract produces for the
// envnames package written by contractFiles.
func contractFixture() Contract {
	return Contract{
		ByConst: map[string]string{
			"EnvEnableSweeper": "NODE_HOST_AGENT_ENABLE_SWEEPER",
			"EnvProcRoot":      "NODE_HOST_AGENT_PROC_ROOT",
		},
		Values: map[string]bool{
			"NODE_HOST_AGENT_ENABLE_SWEEPER": true,
			"NODE_HOST_AGENT_PROC_ROOT":      true,
		},
		Declared: map[string]bool{
			"EnvEnableSweeper":    true,
			"EnvProcRoot":         true,
			"DefaultSweepBaseDir": true,
		},
	}
}

// contractFiles is a minimal envnames package exercising the const
// block carry-forward and the non-env-const skip.
func contractFiles() map[string]string {
	return map[string]string{
		"internal/envnames/envnames.go": `package envnames

const (
	EnvEnableSweeper = "NODE_HOST_AGENT_ENABLE_SWEEPER"
	// bare row repeats the previous expression
	EnvProcRoot = "NODE_HOST_AGENT_PROC_ROOT"
)

// NotEnv is a non-string const — collected as Declared, never env-valued.
const NotEnv = 42

// DefaultSweepBaseDir is a string const without the NODE_HOST_AGENT_ shape.
const DefaultSweepBaseDir = "/var/openebs/local"
`,
	}
}

func TestCollectContract(t *testing.T) {
	root := writeModule(t, contractFiles())
	c, err := CollectContract(root)
	if err != nil {
		t.Fatalf("CollectContract: %v", err)
	}
	want := contractFixture()
	if len(c.ByConst) != len(want.ByConst) {
		t.Fatalf("ByConst = %v, want %v", c.ByConst, want.ByConst)
	}
	for k, v := range want.ByConst {
		if c.ByConst[k] != v {
			t.Errorf("ByConst[%q] = %q, want %q", k, c.ByConst[k], v)
		}
	}
	if !c.Values["NODE_HOST_AGENT_ENABLE_SWEEPER"] || !c.Values["NODE_HOST_AGENT_PROC_ROOT"] {
		t.Errorf("Values missing expected entries: %v", c.Values)
	}
	if c.Values["/var/openebs/local"] {
		t.Errorf("Values collected a non-contract literal: %v", c.Values)
	}
	for k := range want.Declared {
		if !c.Declared[k] {
			t.Errorf("Declared missing %q (const name not recorded)", k)
		}
	}
	if !c.Declared["NotEnv"] {
		t.Errorf("Declared missing non-string const NotEnv")
	}
}

func TestCollectContractSkipsTestFiles(t *testing.T) {
	files := contractFiles()
	files["internal/envnames/envnames_fake_test.go"] = `package envnames

const EnvEnableSweeper = "NODE_HOST_AGENT_ENABLE_FAKE_TEST_ONLY"
`
	root := writeModule(t, files)
	c, err := CollectContract(root)
	if err != nil {
		t.Fatalf("CollectContract: %v", err)
	}
	if c.ByConst["EnvEnableSweeper"] != "NODE_HOST_AGENT_ENABLE_SWEEPER" {
		t.Errorf("_test.go file leaked into contract: ByConst = %v", c.ByConst)
	}
}

func TestCollectContractRejectsNonEnvPrefixedConst(t *testing.T) {
	root := writeModule(t, map[string]string{
		"internal/envnames/envnames.go": `package envnames

const SweepBaseDir = "NODE_HOST_AGENT_SWEEP_BASE_DIR"
`,
	})
	_, err := CollectContract(root)
	if err == nil {
		t.Fatal("CollectContract accepted an env-valued const without the Env* prefix")
	}
	if !strings.Contains(err.Error(), "SweepBaseDir") {
		t.Errorf("error does not name the offending const: %v", err)
	}
}

func TestCollectContractMissingDir(t *testing.T) {
	_, err := CollectContract(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("CollectContract succeeded with no internal/envnames dir")
	}
}

func TestScanSource(t *testing.T) {
	files := contractFiles()
	files["cmd/agent/main.go"] = `package main

import (
	envnames "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

var _ = envnames.EnvProcRoot

const stray = "NODE_HOST_AGENT_STRAY_LITERAL"
const dup = "NODE_HOST_AGENT_PROC_ROOT"

var unresolved = envnames.EnvNoSuchThing
var nonEnv = envnames.DefaultSweepBaseDir
`
	files["internal/other/knob.go"] = `package other

import (
	envnames "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

var Raw = "NODE_HOST_AGENT_RAW_LITERAL"

var Ref = envnames.EnvEnableSweeper
`
	root := writeModule(t, files)

	res, err := ScanSource(root, contractFixture())
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}

	if got := res.Referenced["NODE_HOST_AGENT_PROC_ROOT"]; !strings.HasPrefix(got, "cmd/agent/main.go:") {
		t.Errorf("Referenced[NODE_HOST_AGENT_PROC_ROOT] = %q, want a cmd/agent/main.go:NN site", got)
	}
	if got := res.Referenced["NODE_HOST_AGENT_ENABLE_SWEEPER"]; !strings.HasPrefix(got, "internal/other/knob.go:") {
		t.Errorf("Referenced[NODE_HOST_AGENT_ENABLE_SWEEPER] = %q, want an internal/other/knob.go:NN site", got)
	}

	// Unresolved: EnvNoSuchThing has no contract const and is not
	// declared at all; DefaultSweepBaseDir is declared but not
	// env-valued — neither dupes nor straggles.
	if len(res.Unresolved) != 1 || !strings.Contains(res.Unresolved[0], "EnvNoSuchThing") {
		t.Errorf("Unresolved = %v, want exactly the EnvNoSuchThing site", res.Unresolved)
	}

	// Every raw contract literal is a straggler — including the one
	// inside the dup const decl, which is recorded as both a dup
	// declaration and a raw literal use site.
	if len(res.Stragglers) != 3 {
		t.Fatalf("Stragglers = %v, want the three raw literals", res.Stragglers)
	}
	for _, s := range res.Stragglers {
		if !strings.Contains(s, "NODE_HOST_AGENT_STRAY_LITERAL") &&
			!strings.Contains(s, "NODE_HOST_AGENT_RAW_LITERAL") &&
			!strings.Contains(s, `("NODE_HOST_AGENT_PROC_ROOT")`) {
			t.Errorf("unexpected straggler %q", s)
		}
	}

	// Any const decl carrying a contract-shaped literal outside
	// envnames is a dup — the stray const (unknown var) as well as the
	// one duplicating an existing contract value.
	if len(res.DupDecls) != 2 {
		t.Fatalf("DupDecls = %v, want the stray and dup const sites", res.DupDecls)
	}
	joined := strings.Join(res.DupDecls, "; ")
	if !strings.Contains(joined, "(stray)") || !strings.Contains(joined, "(dup)") {
		t.Errorf("DupDecls = %v, want sites naming both consts", res.DupDecls)
	}
}

func TestScanSourceSkipsExcludedDirsAndTests(t *testing.T) {
	files := contractFiles()
	// envnames' own literals and a stray in envdoc must not surface.
	files["internal/envnames/more.go"] = `package envnames

const Fake = "NODE_HOST_AGENT_FAKE_IN_CONTRACT"
`
	files["internal/envdoc/leak.go"] = `package envdoc

var Fake = "NODE_HOST_AGENT_FAKE_IN_ENVDOC"
`
	files["internal/other/x_test.go"] = `package other

var Fake = "NODE_HOST_AGENT_FAKE_IN_TEST"
`
	files["cmd/agent/main.go"] = "package main\n"
	root := writeModule(t, files)

	res, err := ScanSource(root, contractFixture())
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(res.Stragglers) != 0 {
		t.Errorf("Stragglers = %v, want none (envnames/envdoc/_test.go excluded)", res.Stragglers)
	}
}

func TestScanSourceRejectsDotImport(t *testing.T) {
	files := contractFiles()
	files["internal/other/bad.go"] = `package other

import . "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"

var Ref = EnvProcRoot
`
	files["cmd/agent/main.go"] = "package main\n"
	root := writeModule(t, files)
	_, err := ScanSource(root, contractFixture())
	if err == nil {
		t.Fatal("ScanSource accepted a dot import of envnames")
	}
	if !strings.Contains(err.Error(), "dot-imports") {
		t.Errorf("error does not mention the dot import: %v", err)
	}
}

func TestScanSourceMissingDirs(t *testing.T) {
	root := writeModule(t, contractFiles()) // no cmd/, no internal/other
	if _, err := ScanSource(root, contractFixture()); err == nil {
		t.Fatal("ScanSource succeeded without cmd/ and internal/ walk roots")
	}
}

func parseSrc(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "t.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return fset, f
}

func TestImportLocalName(t *testing.T) {
	const ip = testImportPath
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"plain", `package p; import "` + ip + `"`, "envnames"},
		{"aliased", `package p; import en "` + ip + `"`, "en"},
		{"blank", `package p; import _ "` + ip + `"`, ""},
		{"dot", `package p; import . "` + ip + `"`, "."},
		{"absent", `package p; import "fmt"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, f := parseSrc(t, tc.src)
			if got := importLocalName(f, ip); got != tc.want {
				t.Errorf("importLocalName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScanGates(t *testing.T) {
	files := contractFiles()
	files["cmd/agent/wiring.go"] = `package agent

import (
	envnames "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

type Descriptor struct {
	Name    string
	EnvFlag string
	Default string
}

var registry = []Descriptor{
	// a comment between rows must not forge or split a row
	{
		Name:    "sweeper",
		EnvFlag: envnames.EnvEnableSweeper,
		Default: onOff(w.defKube),
	},
	{
		Name:    "janitor",
		EnvFlag: envnames.EnvProcRoot,
	},
	{
		Name:    "legacy",
		EnvFlag: envnames.EnvUnknownGate, // unresolved const, kept verbatim
		Default: envx.ModeOn,
	},
	{
		Name:    "literal",
		EnvFlag: "NODE_HOST_AGENT_ENABLE_LITERAL",
	},
}

var notGates = []Descriptor{{Name: "other-slice"}}
`
	root := writeModule(t, files)
	gates, err := ScanGates(root, contractFixture())
	if err != nil {
		t.Fatalf("ScanGates: %v", err)
	}
	want := []Gate{
		{Name: "sweeper", EnvFlag: "NODE_HOST_AGENT_ENABLE_SWEEPER", Default: "onOff(w.defKube)"},
		{Name: "janitor", EnvFlag: "NODE_HOST_AGENT_PROC_ROOT", Default: ""},
		{Name: "legacy", EnvFlag: "EnvUnknownGate", Default: "envx.ModeOn"},
		{Name: "literal", EnvFlag: "NODE_HOST_AGENT_ENABLE_LITERAL", Default: ""},
		// ScanGates collects every []Descriptor literal in the file,
		// so this second registry appears as a gateless row too.
		{Name: "other-slice", EnvFlag: "", Default: ""},
	}
	if len(gates) != len(want) {
		t.Fatalf("ScanGates returned %d gates (%v), want %d", len(gates), gates, len(want))
	}
	for i, g := range gates {
		if g != want[i] {
			t.Errorf("gate[%d] = %+v, want %+v", i, g, want[i])
		}
	}
}

func TestScanGatesMissingFile(t *testing.T) {
	root := writeModule(t, contractFiles())
	if _, err := ScanGates(root, contractFixture()); err == nil {
		t.Fatal("ScanGates succeeded without cmd/agent/wiring.go")
	}
}

func TestFlagVar(t *testing.T) {
	c := contractFixture()
	_, f := parseSrc(t, `package p

import en "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"

var (
	a = en.EnvProcRoot
	b = en.EnvMissing
	c = "NODE_HOST_AGENT_LITERAL"
	d = fn()
	e = pkg.EnvNotMine
)
`)
	specs := f.Decls[1].(*ast.GenDecl).Specs
	if len(specs) != 5 {
		t.Fatalf("fixture changed: %d specs", len(specs))
	}
	for _, spec := range specs {
		vs := spec.(*ast.ValueSpec)
		if len(vs.Names) != 1 {
			t.Fatalf("fixture changed: %d names in a spec", len(vs.Names))
		}
		name := vs.Names[0].Name
		expr := vs.Values[0]
		switch name {
		case "a":
			got := flagVar(expr, c)
			if got != "NODE_HOST_AGENT_PROC_ROOT" {
				t.Errorf("flagVar(resolved selector) = %q", got)
			}
		case "b":
			got := flagVar(expr, c)
			if got != "EnvMissing" {
				t.Errorf("flagVar(unresolved selector) = %q, want the bare selector name", got)
			}
		case "c":
			got := flagVar(expr, c)
			if got != "NODE_HOST_AGENT_LITERAL" {
				t.Errorf("flagVar(string literal) = %q", got)
			}
		case "d":
			got := flagVar(expr, c)
			if got != "" {
				t.Errorf("flagVar(call) = %q, want empty", got)
			}
		case "e":
			got := flagVar(expr, c)
			if got != "EnvNotMine" {
				t.Errorf("flagVar(other-pkg selector) = %q, want the selector name", got)
			}
		}
	}
	if got := flagVar(nil, c); got != "" {
		t.Errorf("flagVar(nil) = %q, want empty", got)
	}
}

func TestSourceSlice(t *testing.T) {
	src := []byte("package p\n\nvar x = onOff(w.defKube) + y")
	fset, f := parseSrc(t, string(src))
	expr := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0]
	if got := sourceSlice(fset, src, expr); got != "onOff(w.defKube) + y" {
		t.Errorf("sourceSlice = %q, want the exact source text", got)
	}
}

func TestUnquote(t *testing.T) {
	_, f := parseSrc(t, `package p

var (
	a = "value"
	b = 'r'
	c = fn()
)
`)
	specs := f.Decls[0].(*ast.GenDecl).Specs
	if len(specs) != 3 {
		t.Fatalf("fixture changed: %d specs", len(specs))
	}
	if s, ok := unquote(specs[0].(*ast.ValueSpec).Values[0]); !ok || s != "value" {
		t.Errorf("unquote(string) = %q, %v", s, ok)
	}
	if _, ok := unquote(specs[1].(*ast.ValueSpec).Values[0]); ok {
		t.Error("unquote accepted a char literal")
	}
	if _, ok := unquote(specs[2].(*ast.ValueSpec).Values[0]); ok {
		t.Error("unquote accepted a call expression")
	}
	if _, ok := unquote(nil); ok {
		t.Error("unquote accepted nil")
	}
}
