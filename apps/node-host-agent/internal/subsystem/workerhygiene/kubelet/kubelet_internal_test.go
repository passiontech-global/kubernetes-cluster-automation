// kubelet_internal_test.go — package-internal coverage for the
// unexported kubelet.go helpers the external kubelet_test suites
// only reach through full Cycles: the grep -cE journal-line counter
// and the ip-dashed host transform.
package kubelet

import (
	"regexp"
	"testing"
)

// countMatchingLines is grep -cE parity: LINES matching re, not
// occurrences — a line carrying two signatures still counts once,
// and a final line without a trailing newline still counts.
func TestCountMatchingLines(t *testing.T) {
	re := stallJournalRe
	for _, tc := range []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"no match", "alpha\nbeta\ngamma\n", 0},
		{"single", `node "w1" not found` + "\n", 1},
		{"two lines", "noise\nnode \"w1\" not found\nnode \"w2\" not found\n", 2},
		{"two matches one line", `node "w1" not found and not registered yet` + "\n", 1},
		{"no trailing newline", "noise\nnode \"w1\" not found", 1},
		{"blank lines skipped", "\n\nnode \"w1\" not found\n\n", 1},
	} {
		if got := countMatchingLines(re, tc.in); got != tc.want {
			t.Errorf("%s: countMatchingLines = %d, want %d", tc.name, got, tc.want)
		}
	}
	// A non-matching regexp over the same input counts nothing.
	if got := countMatchingLines(regexp.MustCompile(`zzz`), "node \"w1\" not found\n"); got != 0 {
		t.Fatalf("non-matching re counted %d", got)
	}
}

// dashedHost maps "ip[:port]" to the watchdog file suffix ip-dashed —
// state-apiserver-backend-stale-<dashed> keying parity with
// apiprober's dashedIP.
func TestDashedHost(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"10.0.0.1:6443", "10-0-0-1"},
		{"10.0.0.1", "10-0-0-1"},                // no port — SplitHostPort fails, no ':' chop
		{"hub1:6443", "hub1"},                   // hostname:port
		{"hub1", "hub1"},                        // bare hostname
		{"[::1]:6443", "::1"},                   // bracketed v6 keeps colons (no dots to dash)
		{"10.0.0.1:6443:9090", "10-0-0-1:6443"}, // unparseable → last-colon chop
	} {
		if got := dashedHost(tc.in); got != tc.want {
			t.Errorf("dashedHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
