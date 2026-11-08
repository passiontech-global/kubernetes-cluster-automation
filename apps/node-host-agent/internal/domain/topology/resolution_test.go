// resolution_test.go — coverage for the Vars accessors' unset /
// None mapping (StrDef) and int coercion (Int) over lazily-resolved
// vars, including a template var pulled through the resolution path.
package topology

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

func testVars(t *testing.T) *Vars {
	t.Helper()
	raw := jinja.NewOMap()
	raw.Set("plain", "hello")
	raw.Set("empty", "")
	raw.Set("none_str", "None")
	raw.Set("nil_val", nil)
	raw.Set("num", int64(45670))
	raw.Set("num_str", "1300")
	raw.Set("num_bad", "1.1.1.1")
	raw.Set("template", "{{ plain }}-world")
	return &Vars{
		raw:       raw,
		extra:     map[string]any{},
		resolved:  map[string]any{},
		resolving: map[string]bool{},
		env:       NewEnv(t.TempDir(), nil),
	}
}

// TestStrDef: the empty/None unset sentinel maps onto def; any real
// rendering — including "None" spelled inside a longer string — is
// returned as-is.
func TestStrDef(t *testing.T) {
	v := testVars(t)
	cases := []struct{ name, def, want string }{
		{"plain", "dflt", "hello"},
		{"empty", "dflt", "dflt"},
		{"none_str", "dflt", "dflt"},
		{"nil_val", "dflt", "dflt"},
		{"unset_var", "dflt", "dflt"},
		{"template", "dflt", "hello-world"},
	}
	for _, c := range cases {
		if got := v.StrDef(c.name, c.def); got != c.want {
			t.Errorf("StrDef(%q)=%q want %q", c.name, got, c.want)
		}
	}
}

// TestInt: numeric types coerce, numeric strings parse (base-10),
// non-numeric and unset values fail closed to 0.
func TestInt(t *testing.T) {
	v := testVars(t)
	cases := []struct {
		name string
		want int64
	}{
		{"num", 45670},
		{"num_str", 1300},
		{"num_bad", 0},
		{"unset_var", 0},
		{"nil_val", 0},
	}
	for _, c := range cases {
		if got := v.Int(c.name); got != c.want {
			t.Errorf("Int(%q)=%d want %d", c.name, got, c.want)
		}
	}
}

// TestGet: a var resolves once and caches; the same *Vars view
// returns the resolved value on repeat reads.
func TestGet(t *testing.T) {
	v := testVars(t)
	first := v.Get("template")
	if s, ok := first.(string); !ok || s != "hello-world" {
		t.Fatalf("Get(template)=%#v want \"hello-world\"", first)
	}
	if got := v.Get("template"); got != first {
		t.Fatalf("second Get returned %#v, want cached %#v", got, first)
	}
	if v.Errors() != nil {
		t.Fatalf("unexpected resolution errors: %v", v.Errors())
	}
}
