// kinecheckdb_test.go — check-kine-db flag layer: usage-exit-2
// paths, the -h/--help clean exit, and the check-failure exit
// against a dead stack (no live podman/postgres needed).

package kinecheckdb

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCmdArgParsing(t *testing.T) {
	for _, args := range [][]string{
		{"--bogus"},
		{"--env-file"}, // value flag missing its argument
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

func TestCmdDeadStack(t *testing.T) {
	// A dead stack must exit 1: a nonexistent runtime binary fails
	// every container exec fast, the wire probe to an unused port is
	// refused, and the missing .env drops the creds — every check
	// FAILs without touching a real docker/podman socket.
	code := Cmd(context.Background(), []string{
		"--env-file=" + filepath.Join(t.TempDir(), "no-such.env"),
		"--wire-addr=127.0.0.1:1",
		"--runtime=nha-test-no-such-runtime",
	})
	if code != 1 {
		t.Fatalf("Cmd(dead stack)=%d want 1", code)
	}
}
