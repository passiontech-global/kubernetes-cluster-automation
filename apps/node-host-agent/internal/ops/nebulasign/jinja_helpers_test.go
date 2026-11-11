// jinja_helpers_test.go — the jinja value coercion behind the
// bare-relay-entry read (jstr — the omStr/omList/jstrMap shims are
// gone; their map-level semantics live on *jinja.OMap's typed
// getters, tested in libs/jinja).
package nebulasign

import (
	"encoding/json"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

func TestJstr(t *testing.T) {
	for name, tc := range map[string]struct {
		in   any
		want string
	}{
		"string":      {in: "abc", want: "abc"},
		"int":         {in: 7, want: "7"},
		"int64":       {in: int64(-42), want: "-42"},
		"uint64":      {in: uint64(18446744073709551615), want: "18446744073709551615"},
		"json.Number": {in: json.Number("8080"), want: "8080"},
		"float64":     {in: 1.5, want: "1.5"},
		"float int":   {in: 2.0, want: "2"},
		"bool true":   {in: true, want: "true"},
		"bool false":  {in: false, want: ""},
		"nil":         {in: nil, want: ""},
		"list":        {in: []any{1}, want: ""},
		"map":         {in: map[string]any{"a": 1}, want: ""},
		"omap":        {in: jinja.NewOMap(), want: ""},
		"jlist":       {in: &jinja.List{V: []any{"p"}}, want: ""},
	} {
		if got := jstr(tc.in); got != tc.want {
			t.Fatalf("%s: jstr(%v)=%q want %q", name, tc.in, got, tc.want)
		}
	}
}
