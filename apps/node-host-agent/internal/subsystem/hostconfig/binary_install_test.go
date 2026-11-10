// binary_install_test.go — the deb-path install hook contract: a
// failed apt install must fail the flow (ok=false) with the counted
// per-site line, exactly like the untar path's installErr — callers
// gating daemon restarts on ok must never proceed onto a stale
// daemon.
package hostconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDebInstallFailureFailsTheFlow(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	// A staged deb matching the pin skips the download — the failure
	// under test is the install hook itself.
	local := filepath.Join(t.TempDir(), "haproxy.deb")
	if err := os.WriteFile(local, []byte("deb-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("deb-bytes"))
	changed, ok := c.installManagedBinary(managedBinarySpec{
		name:     "T12",
		artifact: "deb",
		staged:   local,
		sum:      hex.EncodeToString(sum[:]),
		probe:    func(*cyc) bool { return false },
		install: func(*cyc, string) error {
			return errors.New("apt-get boom")
		},
		installErr: func(c *cyc, _ string, err error) {
			c.err("T12: haproxy deb install failed", "error", err)
		},
	})
	if ok {
		t.Fatal("failed deb install must report ok=false")
	}
	if changed {
		t.Fatal("failed deb install must not report changed")
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want 1 (one counted installErr line)", c.errs)
	}
}
