// group_gomemlimit_extra_test.go — parseByteSize scale coverage:
// every suffix family (K/M/G/T and iB/GB forms) and the overflow
// refusal the regex+ParseFloat pair exists for.
package hostconfig

import (
	"strings"
	"testing"
)

// TestParseByteSizeScales — suffix handling the happy-path table
// tests miss: bare K, the T tier, GiB/GB spellings, and the digit
// bomb that overflows ParseFloat.
func TestParseByteSizeScales(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"1024", 1024, true},
		{"1K", 1 << 10, true},
		{"16MiB", 16 << 20, true},
		{"5GB", 5 << 30, true},
		{"2900MiB", 2900 << 20, true},
		{"1T", 1 << 40, true},
		{"2TiB", 2 << 40, true},
		{"0", 0, true},
		{" 12GiB ", 12 << 30, true},
		{"1.5G", 1610612736, true},
		// The i-without-B spellings ("Mi", "Gi") and garbage do not
		// match the size grammar at all.
		{"16Mi", 0, false},
		{"12Gi", 0, false},
		{"1.2.3", 0, false},
		{"", 0, false},
	} {
		got, ok := parseByteSize(tc.in)
		if ok != tc.ok {
			t.Errorf("parseByteSize(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	// float rounding: 1.5G is exact.
	if got, _ := parseByteSize("1.5G"); got != 1610612736 {
		t.Errorf("parseByteSize(1.5G) = %d, want 1610612736", got)
	}
	// A digit bomb parses as a huge float64 — the contract only
	// refuses non-matching shapes, so assert it does not reject.
	if _, ok := parseByteSize(strings.Repeat("9", 30) + "G"); !ok {
		t.Error("parseByteSize refused a matching huge size")
	}
	// Beyond float64's range ParseFloat errors (ErrRange): refused.
	if got, ok := parseByteSize(strings.Repeat("9", 400) + "G"); ok || got != 0 {
		t.Errorf("parseByteSize(10^400 G) = %d ok=%v, want refused", got, ok)
	}
}
