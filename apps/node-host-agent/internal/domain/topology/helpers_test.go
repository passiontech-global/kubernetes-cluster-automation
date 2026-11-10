// helpers_test.go — LastOctet: the trailing-quad derivation every
// marker_octet fallback shares (ops/nebulasign uses the same
// function). A no-dot input returns itself, not "".
package topology

import "testing"

func TestLastOctet(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.42", "42"},
		{"192.168.1.1", "1"},
		{"10.0.0.042", "042"}, // literal trailing quad — no int normalize
		{"nodots", "nodots"},  // no dot → the input itself
		{"10.0.0.", ""},       // trailing dot → empty quad
		{"", ""},
	} {
		if got := LastOctet(tc.in); got != tc.want {
			t.Errorf("LastOctet(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}
