// cmd_test.go — rescue-etcd flag layer: usage-exit-2 paths, the
// -h/--help clean exit, and the runtime-failure exit on a missing
// k0s dir (no live etcd needed).

package etcdrescue

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCmdArgParsing(t *testing.T) {
	for _, args := range [][]string{
		{"--bogus"},
		{"--force-offline=notabool"}, // bool flag rejects non-bool values
		{"--endpoint"},               // value flag missing its argument
	} {
		if code := Cmd(context.Background(), args); code != 2 {
			t.Fatalf("Cmd(%v)=%d want 2", args, code)
		}
	}
	// -h/--help exit 0 — flag.ErrHelp is a clean exit, not a usage
	// error (a user asking for usage must not fail CI/wrappers).
	for _, h := range []string{"-h", "--help"} {
		if code := Cmd(context.Background(), []string{h}); code != 0 {
			t.Fatalf("Cmd(%s)=%d want 0", h, code)
		}
	}
}

func TestCmdMissingK0sDir(t *testing.T) {
	// A missing k0s dir → the etcdctl exec fails on the very first
	// endpoint status → runtime failure exit 1. A trailing
	// positional is tolerated by flag.Parse (not a usage error), so
	// it must reach the same runtime failure.
	code := Cmd(context.Background(), []string{
		"--k0s-dir=" + filepath.Join(t.TempDir(), "no-such"),
		"ignored-positional",
	})
	if code != 1 {
		t.Fatalf("Cmd(missing k0s-dir)=%d want 1", code)
	}
}
