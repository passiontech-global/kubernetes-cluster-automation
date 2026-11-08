// check_test.go — the Check contract helpers: CountMatches mirrors
// `grep -cE` over the one canonical name tables' consumers.
package cdeps_test

import (
	"regexp"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func TestCountMatches(t *testing.T) {
	re := regexp.MustCompile(`^error`)
	text := "error one\nok line\nerror two\nsuberror three\n\n"
	if got := cdeps.CountMatches(re, text); got != 2 {
		t.Fatalf("CountMatches=%d want 2", got)
	}
	if got := cdeps.CountMatches(re, ""); got != 0 {
		t.Fatalf("CountMatches on empty=%d want 0", got)
	}
	if got := cdeps.CountMatches(re, "no matches here\n"); got != 0 {
		t.Fatalf("CountMatches clean text=%d want 0", got)
	}
	// No trailing newline on the last line still counts.
	if got := cdeps.CountMatches(re, "error tail"); got != 1 {
		t.Fatalf("CountMatches unterminated tail=%d want 1", got)
	}
	// A mid-text regex behaves like grep -E (substring match).
	anySub := regexp.MustCompile("SIG13")
	if got := cdeps.CountMatches(anySub, "x SIG13 y\nz\nSIG13\n"); got != 2 {
		t.Fatalf("substring CountMatches=%d want 2", got)
	}
}
