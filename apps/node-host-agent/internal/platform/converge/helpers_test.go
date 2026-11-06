// helpers_test.go — table tests for DefStr (the ansible-vars "None"
// sentinel) and ContainsSS membership.
package converge

import "testing"

func TestDefStr(t *testing.T) {
	for _, tc := range []struct {
		v, d, want string
	}{
		{"", "dflt", "dflt"},
		// The null an ansible vars file emits counts as unset.
		{"None", "dflt", "dflt"},
		{"val", "dflt", "val"},
		// Only exact "None" is the sentinel — lowercase is a value.
		{"none", "dflt", "none"},
		{"NONE", "dflt", "NONE"},
		{"val", "", "val"},
		{"", "", ""},
	} {
		if got := DefStr(tc.v, tc.d); got != tc.want {
			t.Errorf("DefStr(%q, %q) = %q, want %q", tc.v, tc.d, got, tc.want)
		}
	}
}

func TestContainsSS(t *testing.T) {
	for _, tc := range []struct {
		l    []string
		s    string
		want bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "z", false},
		{[]string{"a"}, "a", true},
		{[]string{}, "a", false},
		{nil, "a", false},
		// Substrings do not count — exact element match only.
		{[]string{"abc"}, "b", false},
		{[]string{"abc"}, "abc", true},
		{[]string{""}, "", true},
	} {
		if got := ContainsSS(tc.l, tc.s); got != tc.want {
			t.Errorf("ContainsSS(%v, %q) = %v, want %v", tc.l, tc.s, got, tc.want)
		}
	}
}
