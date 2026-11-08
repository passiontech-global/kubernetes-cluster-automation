// helpers_test.go — table tests for DefStr (the ansible-vars "None"
// sentinel).
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
