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

func TestScanTreeRangeDynamicElements(t *testing.T) {
	root := t.TempDir()
	envxDir := filepath.Join(root, "envxlib")
	fixtureEnvx(t, envxDir)
	modRoot := filepath.Join(root, "mod")
	writeFile(t, filepath.Join(modRoot, "main.go"), `package main

import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

func dynKey() string { return "X" }

func main() {
	// A literal with ONLY dynamic elements feeding an env read —
	// the loop var can never be named: Unresolved.
	for _, k := range []string{dynKey()} {
		_ = envx.Getenv(k, "")
	}
	// A mixed literal feeding an env read — the var MIGHT carry the
	// dynamic element: still Unresolved.
	for _, k := range []string{"MIXED_STATIC", dynKey()} {
		_ = envx.Getenv(k, "")
	}
	// The same dynamic element in a loop whose body NEVER reads env
	// — nothing to resolve, no Unresolved (the pre-split scanner
	// flagged this eagerly).
	for _, p := range []string{"TCP", dynKey()} {
		_ = p
	}
	// Map literal: keys cover the key binding, values the value
	// binding — a dynamic key used as env name is Unresolved while
	// the static-key loop stays clean.
	for k := range map[string]string{dynKey(): "v"} {
		_ = envx.Getenv(k, "")
	}
	for k := range map[string]string{"MAP_KEY_OK": dynKey()} {
		_ = envx.Getenv(k, "")
	}
}
`)
	res, err := ScanTree(Options{Root: modRoot, EnvxDir: envxDir})
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	// Static elements still record as env reads.
	for _, want := range []string{"MIXED_STATIC", "TCP", "MAP_KEY_OK"} {
		if _, ok := res.Referenced[want]; !ok {
			t.Errorf("Referenced missing %s", want)
		}
	}
	// Exactly three unresolvable env-key uses: the dyn-only loop,
	// the mixed loop, and the dynamic map key. The non-env loop and
	// the static map key contribute nothing.
	if len(res.Unresolved) != 3 {
		t.Fatalf("Unresolved = %v, want exactly 3 entries", res.Unresolved)
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

func scanSingleFile(t *testing.T, src string, allowRawOS bool) Result {
	t.Helper()
	root := t.TempDir()
	envxDir := filepath.Join(root, "envxlib")
	fixtureEnvx(t, envxDir)
	modRoot := filepath.Join(root, "mod")
	writeFile(t, filepath.Join(modRoot, "main.go"), src)
	res, err := ScanTree(Options{
		Root:       modRoot,
		EnvxDir:    envxDir,
		AllowRawOS: allowRawOS,
	})
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	return res
}

func TestScanTreeDotImportOS(t *testing.T) {
	src := `package main

import . "os"

func main() {
	_ = Getenv("DOT_GETENV")
	_, _ = LookupEnv("DOT_LOOKUP")
	_ = ExpandEnv("$DOT_EXPAND")
}
`
	denied := scanSingleFile(t, src, false)
	if len(denied.RawReads) != 3 {
		t.Fatalf("AllowRawOS=false RawReads = %v, want 3 entries", denied.RawReads)
	}
	if len(denied.Referenced) != 0 {
		t.Fatalf("AllowRawOS=false Referenced = %v, want empty", denied.Referenced)
	}

	allowed := scanSingleFile(t, src, true)
	if len(allowed.RawReads) != 0 {
		t.Fatalf("AllowRawOS=true RawReads = %v, want empty", allowed.RawReads)
	}
	for _, want := range []string{"DOT_GETENV"} {
		if _, ok := allowed.Referenced[want]; !ok {
			t.Errorf("AllowRawOS=true Referenced missing %s (got %v)", want, allowed.Referenced)
		}
	}
	// LookupEnv key is also collected verbatim.
	if _, ok := allowed.Referenced["DOT_LOOKUP"]; !ok {
		t.Errorf("AllowRawOS=true Referenced missing DOT_LOOKUP (got %v)", allowed.Referenced)
	}
	// ExpandEnv("$DOT_EXPAND") does not match ^[A-Z][A-Z0-9_]*$, test with literal key too.
	src2 := `package main

import . "os"

func main() {
	_ = Getenv("DOT_GETENV")
	_, _ = LookupEnv("DOT_LOOKUP")
	_ = ExpandEnv("DOT_EXPAND")
}
`
	allowed2 := scanSingleFile(t, src2, true)
	for _, want := range []string{"DOT_GETENV", "DOT_LOOKUP", "DOT_EXPAND"} {
		if _, ok := allowed2.Referenced[want]; !ok {
			t.Errorf("Referenced missing %s (got %v)", want, allowed2.Referenced)
		}
	}
}

func TestScanTreeBlankAndMultiImports(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "blank then default os",
			src: `package main
import (
	_ "os"
	"os"
)
func main() { _ = os.Getenv("BLANK_THEN_DEFAULT") }
`,
			want: []string{"BLANK_THEN_DEFAULT"},
		},
		{
			name: "blank then aliased os",
			src: `package main
import (
	_ "os"
	myos "os"
)
func main() { _ = myos.Getenv("BLANK_THEN_ALIAS") }
`,
			want: []string{"BLANK_THEN_ALIAS"},
		},
		{
			name: "blank then dot os",
			src: `package main
import (
	_ "os"
	. "os"
)
func main() { _ = Getenv("BLANK_THEN_DOT") }
`,
			want: []string{"BLANK_THEN_DOT"},
		},
		{
			name: "dot and aliased os together",
			src: `package main
import (
	. "os"
	myos "os"
)
func main() {
	_ = Getenv("MULTI_DOT")
	_ = myos.Getenv("MULTI_ALIAS")
}
`,
			want: []string{"MULTI_DOT", "MULTI_ALIAS"},
		},
		{
			name: "blank then default and aliased envx",
			src: `package main
import (
	_ "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	myenvx "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)
func main() {
	_ = envx.Getenv("ENVX_DEFAULT", "")
	_ = myenvx.Getenv("ENVX_ALIAS", "")
}
`,
			want: []string{"ENVX_DEFAULT", "ENVX_ALIAS"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanSingleFile(t, tc.src, true)
			for _, w := range tc.want {
				if _, ok := res.Referenced[w]; !ok {
					t.Errorf("Referenced missing %s (got %v)", w, res.Referenced)
				}
			}
			if len(res.Unresolved) != 0 {
				t.Errorf("unexpected Unresolved: %v", res.Unresolved)
			}
		})
	}

	// Blank-only import of os must not flag a local struct/var named os.
	blankOnly := `package main
import _ "os"
type fakeOS struct{}
func (fakeOS) Getenv(s string) string { return s }
func main() {
	var os fakeOS
	_ = os.Getenv("SHOULD_NOT_MATCH")
}
`
	res := scanSingleFile(t, blankOnly, false)
	if len(res.RawReads) != 0 || len(res.Referenced) != 0 {
		t.Fatalf("blank-only os matched local var: raw=%v ref=%v", res.RawReads, res.Referenced)
	}
}

func TestScanTreeRangeAndLocalShadowing(t *testing.T) {
	// 1. Dynamic range variable shadowing package const must be Unresolved
	//    and must NOT falsely record PKG_CONST.
	dynRangeShadow := `package main
import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
const k = "PKG_CONST"
func getKeys() []string { return nil }
func main() {
	for _, k := range getKeys() {
		_ = envx.Getenv(k, "")
	}
}
`
	res := scanSingleFile(t, dynRangeShadow, false)
	if _, ok := res.Referenced["PKG_CONST"]; ok {
		t.Fatalf("dynamic range shadowing package const falsely recorded PKG_CONST")
	}
	if len(res.Unresolved) != 1 {
		t.Fatalf("Unresolved = %v, want 1", res.Unresolved)
	}

	// 2. Literal range variable shadowing package const resolves to loop
	//    literals only, NOT PKG_CONST.
	litRangeShadow := `package main
import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
const k = "PKG_CONST"
func main() {
	for _, k := range []string{"LOOP_ONLY"} {
		_ = envx.Getenv(k, "")
	}
}
`
	res = scanSingleFile(t, litRangeShadow, false)
	if _, ok := res.Referenced["LOOP_ONLY"]; !ok {
		t.Fatalf("Referenced missing LOOP_ONLY: %v", res.Referenced)
	}
	if _, ok := res.Referenced["PKG_CONST"]; ok {
		t.Fatalf("literal range shadowing package const falsely recorded PKG_CONST")
	}
	if len(res.Unresolved) != 0 {
		t.Fatalf("Unresolved = %v, want 0", res.Unresolved)
	}

	// 3. Local shadowing forms (param, var, :=, local const, if init,
	//    inner := inside literal range, shadowed const inside range literal,
	//    switch case block scoping, and RHS-before-LHS in :=).
	localShadows := `package main
import (
	"os"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)
const k = "PKG_CONST"
const rhsKey = "RHS_PKG_CONST"
const unshadowed = "UNSHADOWED_CONST"
func dyn() string { return "" }
type fakeOS struct{}
func (fakeOS) Getenv(s string) string { return s }

func byParam(k string) {
	_ = envx.Getenv(k, "")
}

func byLocalDecls() {
	var k = dyn()
	_ = envx.Getenv(k, "")
}

func byShortDeclAndIf() {
	if k := dyn(); k != "" {
		_ = envx.Getenv(k, "")
	}
	k := dyn()
	_ = envx.Getenv(k, "")
}

func byLocalConst() {
	const k = "LOCAL_ONLY"
	_ = envx.Getenv(k, "")
}

func byInnerShadowInsideRange() {
	for _, k := range []string{"OUTER_LOOP"} {
		k := dyn()
		_ = envx.Getenv(k, "")
	}
}

func byShadowedRangeLitElem() {
	k := dyn()
	for _, x := range []string{k} {
		_ = envx.Getenv(x, "")
	}
}

func rhsBeforeLHS() {
	rhsKey := envx.Getenv(rhsKey, "")
	_ = envx.Getenv(rhsKey, "")
}

func switchCaseBlocks(x int) {
	switch x {
	case 1:
		unshadowed := dyn()
		_ = envx.Getenv(unshadowed, "")
	case 2:
		_ = envx.Getenv(unshadowed, "")
	}
}

func shadowOS(os fakeOS) {
	_ = os.Getenv("FAKE_OS_KEY")
}
`
	res = scanSingleFile(t, localShadows, false)
	if _, ok := res.Referenced["PKG_CONST"]; ok {
		t.Fatalf("local declarations falsely resolved PKG_CONST: %v", res.Referenced)
	}
	if _, ok := res.Referenced["RHS_PKG_CONST"]; !ok {
		t.Fatalf("RHS of rhsKey := envx.Getenv(rhsKey, \"\") missed RHS_PKG_CONST: %v", res.Referenced)
	}
	if _, ok := res.Referenced["UNSHADOWED_CONST"]; !ok {
		t.Fatalf("case 2 unshadowed const missed UNSHADOWED_CONST: %v", res.Referenced)
	}
	if _, ok := res.Referenced["OUTER_LOOP"]; !ok {
		t.Fatalf("outer range literal element OUTER_LOOP missing: %v", res.Referenced)
	}
	if len(res.RawReads) != 0 {
		t.Fatalf("shadowed os param triggered RawReads: %v", res.RawReads)
	}
	// Expected Unresolved sites:
	// 1. byParam: k
	// 2. byLocalDecls: k
	// 3. byShortDeclAndIf (if): k
	// 4. byShortDeclAndIf (:=): k
	// 5. byLocalConst: k
	// 6. byInnerShadowInsideRange: k
	// 7. byShadowedRangeLitElem: x
	// 8. rhsBeforeLHS (2nd call): rhsKey
	// 9. switchCaseBlocks (case 1): unshadowed
	if len(res.Unresolved) != 9 {
		t.Fatalf("Unresolved = %v (count=%d), want 9", res.Unresolved, len(res.Unresolved))
	}
}
