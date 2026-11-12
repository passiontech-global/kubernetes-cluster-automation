package envdoc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is the fixture helper — creates dir + file with content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureEnvx writes a minimal envx package: the Getenv/Gate anchors
// EnvxHelpers requires plus one *Knob-style `name` constructor and
// one lenient `key` getter.
func fixtureEnvx(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "envx.go"), `package envx

func Getenv(key, def string) string { return def }
func Gate(key string, defaultOn bool) bool { return defaultOn }
func Int(key string, def int) int { return def }
`)
	// The helpers live in a SECOND file on purpose: the derived set
	// must span every non-test .go file in EnvxDir, not just
	// envx.go — this is what keeps the envx/knobs.go split covered.
	writeFile(t, filepath.Join(dir, "knobs.go"), `package envx

func StringKnob(name string) {}
`)
}

// fixtureRoot writes a module tree exercising every collection
// path: literal/const/range-bound keys, unresolved identifiers,
// raw os reads, a GateEnv registry row and the envdoc self-skip.
func fixtureRoot(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "cmd", "app", "main.go"), `package main

import (
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const literalKey = "CONST_KEY_NAME"

func getKeys() []string { return nil }

func main() {
	// Literal first args — collected verbatim.
	_ = envx.Getenv("LITERAL_KEY", "d")
	_ = envx.Int("OTHER_LITERAL", 0)
	// Package const key — resolved through the const table.
	_ = envx.Getenv(literalKey, "d")
	// Range-bound variable inside its own loop body — covered by the
	// literals recorded at the RangeStmt.
	for _, key := range []string{"RANGE_KEY_ONE", "RANGE_KEY_TWO"} {
		_ = os.Getenv(key)
	}
	// A local var that is NOT a const and NOT range-bound — the
	// scanner cannot name it.
	dynamic := "DYNAMIC"
	_ = envx.Getenv(dynamic, "d")
	// Raw os.Getenv — AllowRawOS decides collect-vs-report.
	_ = os.Getenv("RAW_LITERAL_KEY")
	// The range leak this scanner fixes: key is bound ONLY inside
	// the loop above; this use is a different identifier and must
	// land on Unresolved, not inherit the loop's coverage.
	key := "OUTER_KEY_VAR"
	_ = os.Getenv(key)
	// Shadowing: the inner non-literal range rebinds key, so its
	// body is NOT covered; the outer literal binding resumes after.
	for _, key := range []string{"SHADOW_OUTER"} {
		for _, key := range getKeys() {
			_ = os.Getenv(key)
		}
		_ = os.Getenv(key)
	}
}
`)
	writeFile(t, filepath.Join(root, "internal", "registry", "mods.go"), `package registry

import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

var rows = []struct {
	Name    string
	GateEnv string
}{
	{Name: "mod", GateEnv: "GATE_ENV_NAME"},
}

var _ = envx.Getenv
`)
	// The envdoc package dir itself must never feed the scan — a
	// stray literal here would fake a knob.
	writeFile(t, filepath.Join(root, "internal", "envdoc", "envdoc_test.go"), `package envdoc

const sneaky = "SNEAKY_KEY"
`)
}

func scanFixture(t *testing.T, allowRawOS bool) Result {
	t.Helper()
	root := t.TempDir()
	envxDir := filepath.Join(root, "envxlib")
	fixtureEnvx(t, envxDir)
	modRoot := filepath.Join(root, "mod")
	fixtureRoot(t, modRoot)
	res, err := ScanTree(Options{
		Root:        modRoot,
		EnvxDir:     envxDir,
		AllowRawOS:  allowRawOS,
		RegistryDir: "internal/registry",
		SkipDir:     func(rel string) bool { return rel == "internal/envdoc" },
	})
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	return res
}

func TestEnvxHelpersSpansAllFiles(t *testing.T) {
	dir := t.TempDir()
	fixtureEnvx(t, dir)
	helpers, err := EnvxHelpers(dir)
	if err != nil {
		t.Fatalf("EnvxHelpers: %v", err)
	}
	for _, want := range []string{"Getenv", "Gate", "Int", "StringKnob"} {
		if !helpers[want] {
			t.Fatalf("helpers missing %s (got %v)", want, helpers)
		}
	}
}

func TestEnvxHelpersFailsLoudly(t *testing.T) {
	// An empty dir and a dir whose envx lost its anchors must both
	// error — silently reduced coverage is worse than no coverage.
	if _, err := EnvxHelpers(t.TempDir()); err == nil {
		t.Fatal("EnvxHelpers on empty dir: want error")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "envx.go"), "package envx\nfunc Nope(key string) {}\n")
	if _, err := EnvxHelpers(dir); err == nil {
		t.Fatal("EnvxHelpers without Getenv/Gate anchors: want error")
	}
}

func TestScanTreeCollectsAllKeyShapes(t *testing.T) {
	res := scanFixture(t, true)

	for _, want := range []string{
		"LITERAL_KEY", "OTHER_LITERAL", "CONST_KEY_NAME",
		"RANGE_KEY_ONE", "RANGE_KEY_TWO", "RAW_LITERAL_KEY",
		"GATE_ENV_NAME", "SHADOW_OUTER",
	} {
		if _, ok := res.Referenced[want]; !ok {
			t.Errorf("Referenced missing %s (got %v)", want, res.Referenced)
		}
	}
	// The envdoc dir's own literal must not leak in.
	if _, ok := res.Referenced["SNEAKY_KEY"]; ok {
		t.Error("Skipped dir contributed SNEAKY_KEY")
	}

	// Exactly three unresolvable sites: the `dynamic` var, the
	// post-loop `key` (range leak — the fix under test), and the
	// inner shadowed `key`.
	if len(res.Unresolved) != 3 {
		t.Fatalf("Unresolved = %v, want exactly 3 entries", res.Unresolved)
	}
	for _, u := range res.Unresolved {
		if !strings.Contains(u, "main.go") {
			t.Errorf("Unresolved entry %q not rooted at main.go", u)
		}
	}
	if len(res.RawReads) != 0 {
		t.Fatalf("AllowRawOS=true must not report RawReads: %v", res.RawReads)
	}
}

func TestScanTreeRawReadsDenied(t *testing.T) {
	res := scanFixture(t, false)
	// Every raw os.Getenv call site is reported — the fixture has
	// five: the literal read, the post-loop ident, the covered
	// in-loop read, the shadowed inner read and the covered outer
	// read. Denied mode reports CALL SITES, never keys.
	if len(res.RawReads) != 5 {
		t.Fatalf("RawReads = %v, want 5 entries", res.RawReads)
	}
	for _, r := range res.RawReads {
		if !strings.Contains(r, "main.go:") {
			t.Errorf("RawReads entry %q not rooted at main.go", r)
		}
	}
	// Raw reads bypass addKey entirely in denied mode, so only the
	// envx-helper `dynamic` ident lands on Unresolved.
	if len(res.Unresolved) != 1 {
		t.Fatalf("Unresolved = %v, want exactly 1 entry", res.Unresolved)
	}
	// And the literal raw key is NOT doc-collected — it is banned,
	// not documented.
	if _, ok := res.Referenced["RAW_LITERAL_KEY"]; ok {
		t.Error("denied raw read leaked into Referenced")
	}
}

func TestPackageStringConstsBareRows(t *testing.T) {
	// A bare const row repeats the previous expression — B must
	// resolve to A's literal, and non-string rows contribute
	// nothing.
	src := `package p

const (
	A = "FIRST_KEY"
	B
	C = "SECOND_KEY"
	D = 42
)
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := PackageStringConsts([]*ast.File{f})
	if consts["A"] != "FIRST_KEY" || consts["B"] != "FIRST_KEY" ||
		consts["C"] != "SECOND_KEY" {
		t.Fatalf("PackageStringConsts = %v", consts)
	}
	if _, ok := consts["D"]; ok {
		t.Fatal("non-string const row leaked into the table")
	}
}
