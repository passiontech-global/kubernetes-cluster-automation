// cmd_test.go — purge-events flag layer: usage-exit-2 paths (flag
// parse errors + malformed cutoffs), the positional-cutoff scan
// incl. `--flag value` skipping, and the missing-PKI runtime exit.
// No live apiserver needed.

package evpurge

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func TestCmdArgParsing(t *testing.T) {
	// Flag-parse errors and malformed cutoffs are usage errors —
	// they exit 2 before any TLS/dial work.
	for _, args := range [][]string{
		{"--bogus"},
		{"--workers=notanint"},
		{"--before"},                   // value flag missing its argument
		{"not-a-timestamp"},            // positional cutoff
		{"--before=not-a-timestamp"},   // flag cutoff
		{"--", "not-a-timestamp"},      // `--` then positional
		{"--ca", "/tmp/x", "not-a-ts"}, // `--flag value`: the value is
		// skipped by the positional scan, not eaten as the cutoff
	} {
		if code := Cmd(context.Background(), args); code != 2 {
			t.Fatalf("Cmd(%v)=%d want 2", args, code)
		}
	}
	// -h/--help exit 0 — flag.ErrHelp is a clean exit, not a usage
	// error.
	for _, h := range []string{"-h", "--help"} {
		if code := Cmd(context.Background(), []string{h}); code != 0 {
			t.Fatalf("Cmd(%s)=%d want 0", h, code)
		}
	}
}

func TestCmdMissingPKI(t *testing.T) {
	// A valid cutoff reaches eventpurge.Run, which fails building
	// the client on the missing CA → runtime exit 1. Covers the
	// positional and --before cutoff spellings, and proves
	// `--ca <value>` in space-separated form is consumed as the
	// flag's value (otherwise the path would become the cutoff → 2).
	// NB: no `--` case here — `--` also terminates flag.Parse, so a
	// trailing --ca would land in positionals, never apply, and
	// DefaultCA() could resolve a real k0s CA on a controller host.
	dir := t.TempDir()
	ca := filepath.Join(dir, "no-such-ca.crt")
	for _, args := range [][]string{
		{"--ca=" + ca, "2026-08-23T04:27:00Z"},
		{"--ca", ca, "2026-08-23T04:27:00Z"},
		{"--before=2026-08-23T04:27:00Z", "--ca=" + ca},
	} {
		if code := Cmd(context.Background(), args); code != 1 {
			t.Fatalf("Cmd(%v)=%d want 1", args, code)
		}
	}
}

// The positional-cutoff scan works on a clone — the compacting
// appends must not corrupt the caller's slice (which aliases the
// os.Args backing array in production).
func TestCmdDoesNotMutateArgs(t *testing.T) {
	for _, args := range [][]string{
		// Positional first: without the clone the compaction shifts
		// the flag left over it inside the shared backing array.
		{"2026-08-23T04:27:00Z", "--ca=/nonexistent/ca.crt"},
		// The `--` branch drops the element after it in place.
		{"--", "not-a-timestamp", "--ca=/nonexistent/ca.crt"},
	} {
		want := slices.Clone(args)
		if code := Cmd(context.Background(), args); code != 1 && code != 2 {
			t.Fatalf("Cmd(%v)=%d want 1 or 2", args, code)
		}
		if !slices.Equal(args, want) {
			t.Fatalf("args mutated in place: got %v want %v", args, want)
		}
	}
}
