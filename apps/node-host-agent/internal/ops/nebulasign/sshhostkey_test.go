// sshhostkey_test.go — known_hosts host-key verification for the
// nebula-sign fetch: a known_hosts file next to the SSH key pins the
// hosts it lists; its absence fails closed unless the operator
// passes --insecure-ignore-host-key.
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
	writeKnownHosts(t, keyPath,
		"127.0.0.1 "+line,
		"[::1]:22 "+line,
		"[bastion]:2222 "+line,
		"hub-b "+line,
	)

	verify, err := knownHostsVerify(keyPath, false)
	if err != nil || verify == nil {
		t.Fatalf("verify==nil:%v err=%v — want verifier", verify == nil, err)
	}
	if err := verify("127.0.0.1", hostKey); err != nil {
		t.Fatalf("pinned bare host rejected: %v", err)
	}
	if err := verify("127.0.0.1:22", hostKey); err != nil {
		t.Fatalf("pinned host:22 rejected: %v", err)
	}
	if err := verify("[::1]:22", hostKey); err != nil {
		t.Fatalf("pinned [::1]:22 rejected: %v", err)
	}
	if err := verify("bastion:2222", hostKey); err != nil {
		t.Fatalf("pinned bastion:2222 rejected: %v", err)
	}
	if err := verify("127.0.0.1:22", otherKey); err == nil {
		t.Fatal("mismatched key accepted for host:22")
	}
	if err := verify("127.0.0.1", otherKey); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if err := verify("hub-unlisted:22", hostKey); err == nil {
		t.Fatal("unlisted host accepted")
	}
}

// No known_hosts next to the key fails CLOSED by default — the
// tolerant dial only survives under the explicit insecure opt-out.
func TestKnownHostsVerifyAbsent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if _, err := knownHostsVerify(keyPath, false); err == nil {
		t.Fatal("absent known_hosts want fail-closed error")
	}
	verify, err := knownHostsVerify(keyPath, true)
	if err != nil || verify != nil {
		t.Fatalf("verify!=nil:%v err=%v — want nil,nil under insecure",
			verify != nil, err)
	}
}

// An unparseable known_hosts fails the fetch closed — never a
// silent fallback to the tolerant dial.
func TestKnownHostsVerifyUnparseable(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeKnownHosts(t, keyPath, "not a known_hosts line")
	if _, err := knownHostsVerify(keyPath, true); err == nil {
		t.Fatal("expected parse error")
	}
}
