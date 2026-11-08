// helpers.go — the small pure helpers shared across converge groups:
// the ansible-vars "None" sentinel default. (Slice membership is
// stdlib slices.Contains — no local wrapper.)
package converge

// DefStr returns d when v is unset — "" or the "None" an ansible vars
// file emits for a null.
func DefStr(v, d string) string {
	if v == "" || v == "None" {
		return d
	}
	return v
}
