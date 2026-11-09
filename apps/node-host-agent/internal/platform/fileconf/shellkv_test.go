// shellkv_test.go — the bash-`source`d KEY=VALUE grammar behind
// watchdogconf and the apiprober guard conf: comments, export
// prefixes, quote removal and the word-boundary `#` rule.
package fileconf

import (
	"reflect"
	"testing"
)

func TestParseShellKV(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "empty",
			in:   "",
			want: map[string]string{},
		},
		{
			name: "comments blanks and export",
			in: "# leading comment\n" +
				"\n" +
				"   \n" +
				"export FOO=bar\n" +
				"  export   SPACED = value with spaces  \n",
			want: map[string]string{
				"FOO":    "bar",
				"SPACED": "value with spaces",
			},
		},
		{
			name: "lines without = and empty keys skipped",
			in:   "NOEQUALS\n=novalue\n   =alsonovalue\nOK=yes",
			want: map[string]string{"OK": "yes"},
		},
		{
			name: "first = splits key from value",
			in:   "EQ=a=b=c",
			want: map[string]string{"EQ": "a=b=c"},
		},
		{
			name: "quoted values",
			in:   "D=\"double quoted\"\nS='single quoted'\nN=\"a # b\"\n",
			want: map[string]string{
				"D": "double quoted",
				"S": "single quoted",
				"N": "a # b",
			},
		},
		{
			name: "inline comments",
			in:   "A=foo # trailing\nB=foo#bar\nC=foo #bar baz\n",
			want: map[string]string{
				"A": "foo",
				"B": "foo#bar",
				"C": "foo",
			},
		},
		{
			name: "comment right after a quoted value",
			in:   "Q=\"a b\" # note\nR='x y'#tail",
			want: map[string]string{
				"Q": "a b",
				"R": "x y#tail",
			},
		},
		{
			name: "hash at value start is a comment",
			in:   "H=#not-a-value\nI= # also empty",
			want: map[string]string{
				"H": "",
				"I": "",
			},
		},
		{
			name: "quote chars consumed per word",
			in:   "MIX=\"a\"#tail\nNEST='\"inner\"'",
			want: map[string]string{
				"MIX":  "a#tail",
				"NEST": "inner",
			},
		},
		{
			name: "unquoted value keeps inner spaces",
			in:   "LIST=one two three",
			want: map[string]string{"LIST": "one two three"},
		},
		{
			name: "last duplicate key wins",
			in:   "K=first\nK=second",
			want: map[string]string{"K": "second"},
		},
		{
			name: "unicode value preserved",
			in:   "U=café-✓",
			want: map[string]string{"U": "café-✓"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseShellKV(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseShellKV(%q)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseValueEdge — the word-boundary `#` rule and quote
// consumption on shapes the table above does not reach.
func TestParseValueEdge(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want string
	}{
		// '#' glued to a word stays literal; at a fresh word it
		// opens the comment.
		{"a#b", "a#b"},
		{"a #b", "a"},
		{"a  \t#b", "a"},
		// Quotes open mid-value too — bash quote removal is per
		// word, not per value.
		{`a"b c"d`, "ab cd"},
		{`pre 'quoted' post`, "pre quoted post"},
		// An unclosed quote swallows the rest literally.
		{`"unclosed`, "unclosed"},
		// Surrounding-quote strip only fires on the final scalar —
		// quotes nested inside the other kind survive parseValue and
		// are removed by parseScalar.
		{`'"x"'`, "x"},
		{`"it's"`, "it's"},
	} {
		if got := parseScalar(parseValue(tc.val)); got != tc.want {
			t.Errorf("parse(%q)=%q want %q", tc.val, got, tc.want)
		}
	}
}
