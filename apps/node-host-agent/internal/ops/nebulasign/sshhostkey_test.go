// sshhostkey_test.go — known_hosts host-key verification for the
// nebula-sign fetch: a known_hosts file next to the SSH key pins the
// hosts it lists; its absence keeps the tolerant dial.
package nebulasign

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func writeKnownHosts(t *testing.T, keyPath string, lines ...string) {
	t.Helper()
	kh := filepath.Join(filepath.Dir(keyPath), "known_hosts")
	if err := os.WriteFile(kh, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(kh) })
}

// A known_hosts file listing host:22 pins that host: the presented
// key verifies; a different key and an unlisted host both reject.
func TestKnownHostsVerifyPinsListedHost(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	hostKey := genHostKey(t)
	otherKey := genHostKey(t)
	line := string(ssh.MarshalAuthorizedKey(hostKey))
	writeKnownHosts(t, keyPath, "127.0.0.1 "+line, "hub-b "+line)

	verify, err := knownHostsVerify(keyPath)
	if err != nil || verify == nil {
		t.Fatalf("verify==nil:%v err=%v — want verifier", verify == nil, err)
	}
	if err := verify("127.0.0.1", hostKey); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := verify("127.0.0.1", otherKey); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if err := verify("hub-unlisted", hostKey); err == nil {
		t.Fatal("unlisted host accepted")
	}
}

// No known_hosts next to the key → no verifier, the documented
// tolerant parity for infra VMs whose keys rotate on rebuild.
func TestKnownHostsVerifyAbsent(t *testing.T) {
	verify, err := knownHostsVerify(
		filepath.Join(t.TempDir(), "id_ed25519"))
	if err != nil || verify != nil {
		t.Fatalf("verify!=nil:%v err=%v — want nil,nil", verify != nil, err)
	}
}

// An unparseable known_hosts fails the fetch closed — never a
// silent fallback to the tolerant dial.
func TestKnownHostsVerifyUnparseable(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeKnownHosts(t, keyPath, "not a known_hosts line")
	if _, err := knownHostsVerify(keyPath); err == nil {
		t.Fatal("expected parse error")
	}
}
