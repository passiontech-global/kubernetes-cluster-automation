// shell_test.go — table tests for the `sh -c` interpolation gates:
// the charset/shape predicates that decide which vars-derived values
// may land inside host shell commands.
package converge

import "testing"

func TestSHToken(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		// Empty is allowed — it cannot inject (see the *Req gates
		// for slots where empty is still wrong).
		{"", true},
		// IPs, CIDRs, netdev names, paths, key=value all fit.
		{"10.0.0.8", true},
		{"10.0.0.0/8", true},
		{"fd00::1", true},
		{"eth0", true},
		{"mesh-table_1", true},
		{"/etc/nftables.conf", true},
		{"key=value", true},
		{"user@host", true},
		{"a,b:c", true},
		{"x%y", true},
		// Injection shapes never fit: whitespace, quotes, command
		// substitution, and the shell metacharacters.
		{"a b", false},
		{"a\tb", false},
		{"a\nb", false},
		{"'x'", false},
		{`"x"`, false},
		{"$(id)", false},
		{"`id`", false},
		{"a;rm -rf /", false},
		{"a|b", false},
		{"a&b", false},
		{"a>b", false},
		{"a<b", false},
		{"a*b", false},
		{"a?b", false},
		{"(a)", false},
		{"a[b]", false},
		{"a{b}", false},
		{"a$b", false},
		{"a!b", false},
		{"a#b", false},
		{"\\", false},
		{"~", false},
		{"^", false},
	} {
		if got := SHToken(tc.in); got != tc.want {
			t.Errorf("SHToken(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSHIPCIDR(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"10.0.0.8", true},
		{"10.0.0.0/8", true},
		{"0.0.0.0/0", true},
		{"255.255.255.255/32", true},
		{"fd00::1", true},
		{"fd00::/64", true},
		{"fe80::1%eth0", true}, // netip accepts zones
		// Charset-safe but not an IP/CIDR — the netip parse rejects.
		{"eth0", false},
		{"10.0.0.0/33", false},
		{"999.1.2.3", false},
		{"10.0.0.256", false},
		{"10.0.0.0/8x", false},
		{"fd00::1/129", false},
		{"10.0.0.0.1", false},
		// Injection shapes fail the parse too.
		{"10.0.0.1;id", false},
		{"$(id)", false},
		{"10.0.0.0 /8", false},
	} {
		if got := SHIPCIDR(tc.in); got != tc.want {
			t.Errorf("SHIPCIDR(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSHMarkerBase(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"172.29.0", true},
		{"10.200.3", true},
		{"0.0.0", true},
		// A full IPv4 addr is NOT a base: appending ".0" overflows.
		{"172.29.0.1", false},
		// Two octets short of a base — "172.29.0" is not an addr.
		{"172.29", false},
		{"300.1.2", false},
		{"10.0.0.0/8", false},
		{"abc", false},
		{"fd00::", false},
		{"1.2.3;id", false},
	} {
		if got := SHMarkerBase(tc.in); got != tc.want {
			t.Errorf("SHMarkerBase(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSHPort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"1", true},
		{"53", true},
		{"443", true},
		{"65535", true},
		{"080", true}, // leading zeros still parse to a valid port
		{"+80", true}, // Atoi accepts a leading sign
		// Boundaries and non-numeric shapes.
		{"0", false},
		{"65536", false},
		{"-1", false},
		{"-65535", false},
		{"99999", false},
		{"80a", false},
		{"8_0", false},
		{" 80", false},
		{"80 ", false},
		{"8.0", false},
		{"80;id", false},
		{"$(id)", false},
	} {
		if got := SHPort(tc.in); got != tc.want {
			t.Errorf("SHPort(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The *Req gates add the required-slot check on top of the base
// gate: empty passes the base predicate but must fail the Req one.
func TestSHIPCIDRReq(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"10.0.0.8", true},
		{"10.0.0.0/8", true},
		{"", false},
		{"eth0", false},
		{"10.0.0.1;id", false},
	} {
		if got := SHIPCIDRReq(tc.in); got != tc.want {
			t.Errorf("SHIPCIDRReq(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSHPortReq(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"443", true},
		{"65535", true},
		{"", false},
		{"0", false},
		{"abc", false},
	} {
		if got := SHPortReq(tc.in); got != tc.want {
			t.Errorf("SHPortReq(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
