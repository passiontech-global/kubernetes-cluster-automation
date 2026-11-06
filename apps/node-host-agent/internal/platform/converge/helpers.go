// helpers.go — the small pure helpers shared across converge groups:
// the ansible-vars "None" sentinel default and slice membership.
package converge

// DefStr returns d when v is unset — "" or the "None" an ansible vars
// file emits for a null.
func DefStr(v, d string) string {
	if v == "" || v == "None" {
		return d
	}
	return v
}

// ContainsSS reports whether s is in l (a string-slice membership
// test, pre-1.21 slices.Contains shape kept for parity with the
// ported call sites).
func ContainsSS(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
