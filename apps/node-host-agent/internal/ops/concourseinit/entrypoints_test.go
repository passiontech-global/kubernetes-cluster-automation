package concourseinit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
)

// TestCmd: -h is a clean exit, a bad flag is a usage error, and a
// runtime failure (missing --runc-source binary) is opsx.ExitRuntime.
func TestCmd(t *testing.T) {
	ctx := context.Background()
	if code := Cmd(ctx, []string{"-h"}); code != opsx.ExitOK {
		t.Fatalf("-h exit=%d want %d", code, opsx.ExitOK)
	}
	if code := Cmd(ctx, []string{"--bogus"}); code != opsx.ExitUsage {
		t.Fatalf("bad flag exit=%d want %d", code, opsx.ExitUsage)
	}
	work := t.TempDir()
	code := Cmd(ctx, []string{
		"--work-dir", work,
		"--runc-dir", t.TempDir(),
		"--runc-source", filepath.Join(work, "no-such-runc"),
	})
	if code != opsx.ExitRuntime {
		t.Fatalf("missing runc source exit=%d want %d", code, opsx.ExitRuntime)
	}
}

// TestRunRuncWrapper: with the real DefaultRuncReal absent, exec
// fails with ENOENT and the wrapper returns exit 1 — the only
// observable non-exec return. (The seam-level success/failure matrix
// lives in the runRuncWrapper tests.)
func TestRunRuncWrapper(t *testing.T) {
	if _, err := os.Stat(DefaultRuncReal); err == nil {
		t.Skipf("%s exists on this host — exec would replace the image",
			DefaultRuncReal)
	}
	argv := []string{"runc", "create", "--bundle", "/no/such/bundle"}
	if code := RunRuncWrapper(argv, nil); code != 1 {
		t.Fatalf("RunRuncWrapper=%d want 1 (exec ENOENT)", code)
	}
	// RuncWrapper is argv[0]/os.Environ wrapping — same outcome.
	if code := RuncWrapper(); code != 1 {
		t.Fatalf("RuncWrapper=%d want 1", code)
	}
}

// TestBtrfsDeleteSubvol: the show guard fails for a plain directory
// (not a subvolume — or no btrfs binary at all), so the delete never
// runs and the error is returned for the caller to discard.
func TestBtrfsDeleteSubvol(t *testing.T) {
	if err := btrfsDeleteSubvol(context.Background(),
		t.TempDir()); err == nil {
		t.Fatal("plain dir want show-guard error")
	}
}
