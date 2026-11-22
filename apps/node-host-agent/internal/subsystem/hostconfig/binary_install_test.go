// binary_install_test.go — the deb-path install hook contract: a
// failed apt install must fail the flow (ok=false) with the counted
// per-site line, exactly like the untar path's installErr — callers
// gating daemon restarts on ok must never proceed onto a stale
// daemon.
package hostconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func makeTestTarGz(t *testing.T, member, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: member, Mode: 0o755, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestInstallManagedBinaryHashToUntarTOCTOU verifies that swapping the
// staged tarball on disk between staged-hash verification and extraction
// is caught by same-fd UntarInstallVerified (never extracting evil bytes).
func TestInstallManagedBinaryHashToUntarTOCTOU(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	goodTgz := makeTestTarGz(t, "tool", "good-binary")
	evilTgz := makeTestTarGz(t, "tool", "pwned-binary")
	sum := sha256.Sum256(goodTgz)

	dlDir := t.TempDir()
	local := filepath.Join(dlDir, "tool.tgz")
	if err := os.WriteFile(local, goodTgz, 0o644); err != nil {
		t.Fatal(err)
	}

	changed, ok := c.installManagedBinary(managedBinarySpec{
		name:            "T5b",
		artifact:        "tool tgz",
		staged:          local,
		sum:             hex.EncodeToString(sum[:]),
		refuseBadStaged: true,
		stagingDirMode:  0o700,
		probe:           func(*cyc) bool { return false },
		prepare: func(*cyc) bool {
			// Attacker overwrites local after stagedOK passed!
			if err := os.WriteFile(local, evilTgz, 0o644); err != nil {
				t.Fatal(err)
			}
			return true
		},
		member: "tool",
		dest:   "/usr/local/bin/tool",
		mode:   0o755,
		installErr: func(c *cyc, local string, err error) {
			c.err("T5b: tool install failed", "file", local, "error", err)
		},
	})
	if ok || changed {
		t.Fatalf("installManagedBinary = (%v, %v), want (false, false)", changed, ok)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want 1", c.errs)
	}
	if hostExists(r, "/usr/local/bin/tool") {
		t.Fatal("tampered binary was installed despite same-fd verification")
	}
}
