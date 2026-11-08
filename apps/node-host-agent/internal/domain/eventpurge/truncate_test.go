// truncate_test.go — the error-message truncation helper: byte-slice
// at n only when the string is longer, otherwise unchanged.
package eventpurge

import "testing"

func TestTruncate(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exact!", 6, "exact!"},
		{"longer than n", 6, "longer"},
		{"anything", 0, ""},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.s, c.n); got != c.want {
			t.Errorf("truncate(%q,%d)=%q want %q", c.s, c.n, got, c.want)
		}
	}
}
