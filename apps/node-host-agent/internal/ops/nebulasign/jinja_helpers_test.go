// jinja_helpers_test.go — the jinja value coercions behind vars-file
// reads: jstr/omStr/omList/jstrMap (strOf/strMap/omStr/omBool shims —
// these coerce bool → "true" where hubsync's copies drop it).
package nebulasign

import (
	"reflect"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

func TestJstr(t *testing.T) {
	for name, tc := range map[string]struct {
		in   any
		want string
	}{
		"string":     {in: "abc", want: "abc"},
		"int64":      {in: int64(-42), want: "-42"},
		"float64":    {in: 1.5, want: "1.5"},
		"float int":  {in: 2.0, want: "2"},
		"bool true":  {in: true, want: "true"},
		"bool false": {in: false, want: ""},
		"nil":        {in: nil, want: ""},
		"other":      {in: []any{1}, want: ""},
	} {
		if got := jstr(tc.in); got != tc.want {
			t.Fatalf("%s: jstr(%v)=%q want %q", name, tc.in, got, tc.want)
		}
	}
}

func TestOmStrOmList(t *testing.T) {
	m := jinja.NewOMap()
	m.Set("s", "v")
	m.Set("n", int64(7))
	m.Set("b", true)
	m.Set("l", []any{"x", "y"})
	m.Set("jl", &jinja.List{V: []any{"p", "q"}})

	if got := omStr(m, "s"); got != "v" {
		t.Fatalf("omStr(s)=%q", got)
	}
	if got := omStr(m, "n"); got != "7" {
		t.Fatalf("omStr(n)=%q want int coercion", got)
	}
	if got := omStr(m, "missing"); got != "" {
		t.Fatalf("omStr(missing)=%q want empty", got)
	}

	if got := omList(m, "l"); !reflect.DeepEqual(got, []any{"x", "y"}) {
		t.Fatalf("omList(l)=%v", got)
	}
	if got := omList(m, "jl"); !reflect.DeepEqual(got, []any{"p", "q"}) {
		t.Fatalf("omList(jl)=%v want List.V", got)
	}
	if got := omList(m, "s"); got != nil {
		t.Fatalf("omList(non-list)=%v want nil", got)
	}
	if got := omList(m, "missing"); got != nil {
		t.Fatalf("omList(missing)=%v want nil", got)
	}
}

func TestJstrMap(t *testing.T) {
	m := jinja.NewOMap()
	m.Set("host", "node-a")
	m.Set("port", int64(22))
	m.Set("flag", false)

	got := jstrMap(m)
	want := map[string]string{"host": "node-a", "port": "22", "flag": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("jstrMap=%v want %v", got, want)
	}

	// Non-OMap input → empty map, never nil-map panics downstream.
	if got := jstrMap("nope"); len(got) != 0 {
		t.Fatalf("jstrMap(non-omap)=%v want empty", got)
	}
	if got := jstrMap(nil); len(got) != 0 {
		t.Fatalf("jstrMap(nil)=%v want empty", got)
	}
}
