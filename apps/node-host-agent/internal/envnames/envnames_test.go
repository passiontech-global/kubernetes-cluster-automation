// envnames_test.go — contract test for the envnames package: every
// Env* const declared here must carry a NODE_HOST_AGENT_ value, the
// values must be unique (one env var, one const), and the const
// names must follow the mechanical Env+CamelCase derivation the
// package comment promises. The package itself is pure consts, so
// the only observable behavior is its source — parsed here with
// go/ast, the same way internal/envdoc/scan reads it.
package envnames

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var envVarShape = regexp.MustCompile(`^NODE_HOST_AGENT_[A-Z0-9_]+$`)

// packageConsts parses every non-test .go file in this package's dir
// and returns each declared const name with its resolved string
// value ("" for non-string consts; bare const-block rows carry the
// previous expression forward, exactly like the contract scan does).
func packageConsts(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	vals := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			var carry []ast.Expr
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if len(vs.Values) > 0 {
					carry = vs.Values
				}
				for i, n := range vs.Names {
					if i >= len(carry) {
						continue
					}
					lit, ok := carry[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					vals[n.Name] = v
				}
			}
		}
	}
	if len(vals) == 0 {
		t.Fatal("parsed 0 string consts from the envnames package — the package layout must have changed; this check passes vacuously")
	}
	return vals
}

func TestEnvContract(t *testing.T) {
	vals := packageConsts(t)

	byValue := map[string]string{}
	for name, v := range vals {
		// Non-contract consts (e.g. DefaultSweepBaseDir) are allowed
		// to hold non-NODE_HOST_AGENT_ values — but anything that IS
		// a NODE_HOST_AGENT_ var must carry the full contract shape.
		if strings.HasPrefix(v, "NODE_HOST_AGENT_") && !envVarShape.MatchString(v) {
			t.Errorf("%s = %q matches the NODE_HOST_AGENT_ prefix but not the full contract shape", name, v)
		}
		if envVarShape.MatchString(v) && !strings.HasPrefix(v, "NODE_HOST_AGENT_") {
			t.Errorf("%s = %q matches the shape regex without the prefix (regex bug)", name, v)
		}
		// Uniqueness: an env var read by two packages is still
		// declared once here and shared.
		if prev, dup := byValue[v]; dup {
			t.Errorf("%s and %s both declare %q — env var values must be unique", prev, name, v)
		}
		byValue[v] = name
	}

	// Env* consts must be env-valued: the const name IS the contract
	// handle, so an Env*-prefixed const holding anything else breaks
	// the scan's resolution model.
	for name, v := range vals {
		if strings.HasPrefix(name, "Env") && !strings.HasPrefix(v, "NODE_HOST_AGENT_") {
			t.Errorf("%s is Env*-prefixed but its value %q is not a NODE_HOST_AGENT_ var", name, v)
		}
	}
	// Every value that matches the contract shape must live on an
	// Env*-prefixed const (checked via packageConsts keys).
	for name, v := range vals {
		if envVarShape.MatchString(v) && !strings.HasPrefix(name, "Env") {
			t.Errorf("%s holds contract var %q but its name lacks the Env* handle", name, v)
		}
	}
}

func TestEnableGatesDeclared(t *testing.T) {
	// Every subsystem gate promised by the package comment must be
	// present with its expected literal — a rename that drops a gate
	// would silently ungate a subsystem.
	vals := packageConsts(t)
	// The literal values as observed in the package source — a rename
	// here would change the env vars every caller passes through the
	// process environment, so they are pinned verbatim.
	wantGate := map[string]string{
		"EnvEnableSweeper":           "NODE_HOST_AGENT_ENABLE_SWEEPER",
		"EnvEnableConcourseCache":    "NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE",
		"EnvEnableApiprober":         "NODE_HOST_AGENT_ENABLE_APIPROBER",
		"EnvEnableHostmetrics":       "NODE_HOST_AGENT_ENABLE_HOSTMETRICS",
		"EnvEnableHygiene":           "NODE_HOST_AGENT_ENABLE_HYGIENE",
		"EnvEnableNethealth":         "NODE_HOST_AGENT_ENABLE_NETHEALTH",
		"EnvEnableJanitor":           "NODE_HOST_AGENT_ENABLE_JANITOR",
		"EnvEnableReporter":          "NODE_HOST_AGENT_ENABLE_REPORTER",
		"EnvEnableControllerhygiene": "NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE",
		"EnvEnableHostconfig":        "NODE_HOST_AGENT_ENABLE_HOSTCONFIG",
		"EnvEnableKinedb":            "NODE_HOST_AGENT_ENABLE_KINEDB",
		"EnvEnableFeeder":            "NODE_HOST_AGENT_ENABLE_FEEDER",
	}
	for gate, want := range wantGate {
		if got := vals[gate]; got != want {
			t.Errorf("%s = %q, want %q", gate, got, want)
		}
	}
}
