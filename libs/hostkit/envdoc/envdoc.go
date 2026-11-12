// Package envdoc is the shared AST scanner behind the env-coverage
// tests that keep each app's env.md honest. Both
// apps/webhook-dispatcher and apps/node-automation-controller used to
// carry ~850 lines of near-identical go/ast walking in their
// internal/envdoc test packages; this package is the single
// implementation they now call.
//
// The scan collects every env-var name the module source can read:
//
//   - first arguments of envx helper calls (the lenient String/Bool/
//     Int family AND the strict Getenv*/Gate/*Knob set — the helper
//     set is derived by parsing the envx package's own sources, so a
//     new getter joins the scan the moment it lands);
//   - string literals inside `for _, k := range []string{...}` loops
//     whose bound variables feed an env read (the required-var check
//     shape);
//   - package-level string consts used as the key argument;
//   - GateEnv: "NAME" composite-literal fields inside the registry
//     dir (the module registration gates);
//   - raw os.Getenv/LookupEnv/ExpandEnv call sites — either collected
//     as ordinary env reads (AllowRawOS, the dispatcher's
//     required-var check) or reported on RawReads for the caller to
//     fail on (the controller bans raw reads outright).
//
// Range-bound variables are tracked with a proper AST scope stack —
// a `key` bound by `for _, key := range []string{...}` counts as
// covered ONLY inside that loop's body, so a same-named identifier
// elsewhere in the file can no longer leak coverage (and a
// non-literal range binding correctly shadows an outer literal one).
//
// Stdlib-only like the rest of libs/hostkit (depguard:
// hostkit-is-leaf).
package envdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// EnvxImportPath is the import path whose first-arg-is-an-env-key
// helpers the scan recognizes — whatever local name a scanned file
// binds it to resolves through the file's import decl, so an aliased
// import cannot evade the scan.
const EnvxImportPath = "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

// envNameRE restricts collected string literals to tokens that look
// like env-var names — ALL_CAPS with digits/underscores — so ordinary
// string arguments never feed the coverage set.
var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// rawEnvReadNames are the os package members that pull values from
// the process environment — each one bypasses the envx helper layer.
var rawEnvReadNames = map[string]bool{
	"Getenv":    true,
	"LookupEnv": true,
	"ExpandEnv": true,
}

// Options configures one ScanTree run.
type Options struct {
	// Root is the module root the walk starts at; every position in
	// the result is rendered relative to it.
	Root string
	// EnvxDir is the directory holding the envx package sources —
	// EVERY *.go non-test file in it is parsed for the helper set
	// (envx.go AND knobs.go after the split), so moving helpers
	// between files cannot shrink coverage.
	EnvxDir string
	// AllowRawOS collects raw os.Getenv/LookupEnv/ExpandEnv first
	// args as ordinary env reads instead of reporting them on
	// Result.RawReads — true for the dispatcher (its required-var
	// check reads env this way on purpose), false for the
	// controller (raw reads are banned).
	AllowRawOS bool
	// RegistryDir, when non-empty, is the directory whose
	// `GateEnv: "NAME"` composite-literal fields are collected as
	// env reads (the module registration gates).
	RegistryDir string
	// SkipDir, when non-nil, is consulted with each directory's
	// slash-separated path relative to Root ("internal/envdoc") —
	// return true to prune the walk there.
	SkipDir func(rel string) bool
}

// Result is one ScanTree run's output.
type Result struct {
	// Referenced maps each env-var name to "rel/file.go:line" of one
	// use site — the failure-message payload for undocumented knobs.
	Referenced map[string]string
	// Unresolved lists "rel/file.go:line (ident)" sites whose env
	// key is an identifier that is neither a package-level string
	// const nor a range variable bound to a recorded literal — the
	// scanner cannot name the key, so the caller must fail on it.
	Unresolved []string
	// RawReads lists "rel/file.go:line" sites of raw
	// os.Getenv/LookupEnv/ExpandEnv calls seen while AllowRawOS was
	// false — each is an env read invisible to doc coverage.
	RawReads []string
}

// ScanTree walks every directory under opts.Root (pruned by
// opts.SkipDir), parses each directory's non-test .go files, and
// collects every env-var name the sources can read into a Result.
// Every failure is returned as an error — a coverage scan that
// quietly finds nothing is worse than no scan.
func ScanTree(opts Options) (Result, error) {
	res := Result{Referenced: map[string]string{}}
	helpers, err := EnvxHelpers(opts.EnvxDir)
	if err != nil {
		return res, err
	}

	rootAbs, err := filepath.Abs(opts.Root)
	if err != nil {
		return res, fmt.Errorf("envdoc: abs root %s: %w", opts.Root, err)
	}
	envxDirAbs, err := filepath.Abs(opts.EnvxDir)
	if err != nil {
		return res, fmt.Errorf("envdoc: abs envx dir %s: %w", opts.EnvxDir, err)
	}
	registryAbs := ""
	if opts.RegistryDir != "" {
		if registryAbs, err = filepath.Abs(filepath.Join(rootAbs, opts.RegistryDir)); err != nil {
			return res, fmt.Errorf("envdoc: abs registry dir %s: %w", opts.RegistryDir, err)
		}
	}

	// Collect every directory under Root — the module's whole Go
	// surface (cmd/*, internal/*, …); *_test.go files and the
	// envdoc test package itself contribute nothing.
	var dirs []string
	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(rootAbs, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash != "." && opts.SkipDir != nil && opts.SkipDir(relSlash) {
			return filepath.SkipDir
		}
		dirs = append(dirs, path)
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("envdoc: walk %s: %w", rootAbs, err)
	}

	// site renders a position Root-relative so failure messages read
	// like every other path in the repo.
	site := func(fset *token.FileSet, pos token.Pos) string {
		p := fset.Position(pos)
		rel, err := filepath.Rel(rootAbs, p.Filename)
		if err != nil {
			rel = p.Filename
		}
		return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), p.Line)
	}

	record := func(fset *token.FileSet, value string, pos token.Pos) {
		if !envNameRE.MatchString(value) {
			return
		}
		if _, seen := res.Referenced[value]; seen {
			return
		}
		res.Referenced[value] = site(fset, pos)
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return res, fmt.Errorf("envdoc: read dir %s: %w", dir, err)
		}

		fset := token.NewFileSet()
		var files []*ast.File
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				return res, fmt.Errorf("envdoc: parse %s: %w", filepath.Join(dir, name), err)
			}
			files = append(files, f)
		}
		if len(files) == 0 {
			continue
		}

		consts := PackageStringConsts(files)
		dirAbs, err := filepath.Abs(dir)
		if err != nil {
			return res, fmt.Errorf("envdoc: abs dir %s: %w", dir, err)
		}
		inRegistry := registryAbs != "" && dirAbs == registryAbs
		inEnvx := dirAbs == envxDirAbs

		for _, f := range files {
			s := &fileScan{
				fset:       fset,
				res:        &res,
				consts:     consts,
				inEnvx:     inEnvx,
				inRegistry: inRegistry,
				allowRawOS: opts.AllowRawOS,
				helpers:    helpers,
				site:       site,
				record:     record,
			}
			s.envxName, s.envxDot = importLocalName(f, EnvxImportPath)
			s.osName, _ = importLocalName(f, "os")
			ast.Walk(&rangeVisitor{s: s}, f)
		}
	}

	return res, nil
}

// rangeFrame is one RangeStmt's binding scope on the AST stack: the
// body positions an identifier must sit inside for the binding to
// apply, the loop variable names, and whether the ranged expression
// was a composite literal (only then are its string elements env
// keys the scanner recorded).
type rangeFrame struct {
	body  *ast.BlockStmt
	names map[string]bool
	cover bool
}

// fileScan carries one file's scan state: import aliases, the
// package const table, the registry/envx directory flags and the
// live range-binding stack.
type fileScan struct {
	fset       *token.FileSet
	res        *Result
	consts     map[string]string
	envxName   string
	envxDot    bool
	osName     string
	inEnvx     bool
	inRegistry bool
	allowRawOS bool
	helpers    map[string]bool
	site       func(fset *token.FileSet, pos token.Pos) string
	record     func(fset *token.FileSet, value string, pos token.Pos)
	stack      []*rangeFrame
}

// rangeVisitor is the ast.Visitor Walk drives. It exists so a
// RangeStmt's frame can be pushed on entry and popped on exit —
// ast.Inspect has no exit hook, and a file-level variable set (the
// bug this replaces) let a loop variable's coverage leak onto
// same-named identifiers anywhere later in the file. `pushed`
// records whether THIS node's inspect pushed a frame, so a
// RangeStmt binding no identifiers cannot pop an outer frame.
type rangeVisitor struct {
	s      *fileScan
	pushed bool
}

func (v *rangeVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		// Walk calls Visit(nil) on the visitor a node returned after
		// that node's children — pop the frame THIS node pushed.
		if v.pushed && len(v.s.stack) > 0 {
			v.s.stack = v.s.stack[:len(v.s.stack)-1]
		}
		return nil
	}
	pushed := v.s.inspect(n)
	return &rangeVisitor{s: v.s, pushed: pushed}
}

// inspect handles the node types the scan cares about and reports
// whether it pushed a range frame (RangeStmt with bound identifiers).
// Called for every node in preorder (before its children).
func (s *fileScan) inspect(n ast.Node) bool {
	switch e := n.(type) {
	case *ast.RangeStmt:
		return s.scanRange(e)
	case *ast.CallExpr:
		s.scanCall(e)
	case *ast.KeyValueExpr:
		if s.inRegistry {
			if key, ok := e.Key.(*ast.Ident); ok && key.Name == "GateEnv" {
				s.addKey(e.Value, e.Pos())
			}
		}
	}
	return false
}

// scanRange records the string literals of a `for ... range
// []string{...}` composite literal as env reads, then pushes the
// loop variables' binding frame so identifiers inside the body
// resolve as covered — and only there. Reports whether a frame was
// pushed (a RangeStmt binding no identifiers pushes none).
func (s *fileScan) scanRange(e *ast.RangeStmt) bool {
	cl, isLit := e.X.(*ast.CompositeLit)
	if isLit {
		for _, elt := range cl.Elts {
			lit, ok := elt.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if v, err := strconv.Unquote(lit.Value); err == nil {
				s.record(s.fset, v, e.Pos())
			}
		}
	}
	names := map[string]bool{}
	for _, id := range []ast.Expr{e.Key, e.Value} {
		if ident, ok := id.(*ast.Ident); ok {
			names[ident.Name] = true
		}
	}
	if len(names) == 0 {
		return false
	}
	s.stack = append(s.stack, &rangeFrame{body: e.Body, names: names, cover: isLit})
	return true
}

// scanCall resolves env-reading call sites: raw os.Getenv-family
// reads (collected or reported per AllowRawOS) and envx helper calls
// (qualified or dot-imported, alias resolved from this file's
// imports).
func (s *fileScan) scanCall(e *ast.CallExpr) {
	if len(e.Args) == 0 {
		return
	}
	if isRawEnvRead(e, s.osName) {
		if s.allowRawOS {
			s.addKey(e.Args[0], e.Pos())
		} else {
			s.res.RawReads = append(s.res.RawReads, s.site(s.fset, e.Pos()))
		}
		return
	}
	if !isEnvCall(e, s.envxName, s.envxDot, s.inEnvx, s.helpers) {
		return
	}
	s.addKey(e.Args[0], e.Pos())
}

// addKey records a literal env key, resolves a package-level string
// const, accepts a range variable bound to a recorded literal inside
// its loop body, and reports anything else as unresolved — an env
// key the scanner cannot name is one docs/env.md cannot be checked
// against. Keys written as arbitrary other expressions (a field
// read, a concatenation, a call result) are ignored rather than
// flagged.
func (s *fileScan) addKey(expr ast.Expr, pos token.Pos) {
	switch k := expr.(type) {
	case *ast.BasicLit:
		if k.Kind != token.STRING {
			return
		}
		if v, err := strconv.Unquote(k.Value); err == nil {
			s.record(s.fset, v, pos)
		}
	case *ast.Ident:
		if v, ok := s.consts[k.Name]; ok {
			s.record(s.fset, v, pos)
			return
		}
		if s.rangeCovered(k.Name, k.Pos()) {
			// Bound to a []string literal already recorded at the
			// RangeStmt — the keys are covered.
			return
		}
		// An identifier that is neither a string const nor a
		// recorded range variable — the scanner cannot name the key.
		s.res.Unresolved = append(s.res.Unresolved,
			fmt.Sprintf("%s (%s)", s.site(s.fset, pos), k.Name))
	default:
		// Selector, concatenation, call result — a computed key.
	}
}

// rangeCovered reports whether ident sits inside the body of the
// innermost range frame binding it AND that frame's ranged
// expression was a composite literal (whose string elements were
// already recorded as env reads). Walking the stack top-down finds
// the innermost binding first, so a non-literal inner range
// correctly shadows an outer literal one.
func (s *fileScan) rangeCovered(name string, pos token.Pos) bool {
	for i := len(s.stack) - 1; i >= 0; i-- {
		f := s.stack[i]
		if !f.names[name] {
			continue
		}
		if pos <= f.body.Pos() || pos >= f.body.End() {
			continue
		}
		return f.cover
	}
	return false
}
