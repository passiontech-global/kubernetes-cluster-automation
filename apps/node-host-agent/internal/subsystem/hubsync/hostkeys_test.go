// hostkeys_test.go — host-key trust policy coverage: spec parsing,
// pin-map/wildcard precedence, known_hosts enforcement, TOFU
// first-seen recording + changed-key hard block.
package hubsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func testPolicy(t *testing.T, spec, kh, tofu string, insecure bool) *hostKeyPolicy {
	t.Helper()
	return newHostKeyPolicy(spec, kh, tofu, 0, insecure, nil)
}

func TestParseHostKeySpec(t *testing.T) {
	// Single pin — incl. base64 '=' padding that must NOT be read
	// as a host= separator.
	pins, single := parseHostKeySpec("SHA256:abc=")
	if pins != nil || single != "SHA256:abc=" {
		t.Fatalf("single pin: pins=%v single=%q", pins, single)
	}
	// Per-host map with wildcard.
	pins, single = parseHostKeySpec(
		"node-a=SHA256:AAA,node-b=SHA256:BBB,*=SHA256:CCC")
	if single != "" || pins["node-a"] != "SHA256:AAA" ||
		pins["node-b"] != "SHA256:BBB" || pins["*"] != "SHA256:CCC" {
		t.Fatalf("map: pins=%v single=%q", pins, single)
	}
	// Malformed member → whole spec stays a single pin (fail closed,
	// never widens trust).
	pins, single = parseHostKeySpec("node-a=SHA256:AAA,bogus")
	if pins != nil || single == "" {
		t.Fatalf("malformed: pins=%v single=%q", pins, single)
	}
	if _, single := parseHostKeySpec(""); single != "" {
		t.Fatal("empty spec must yield empty single")
	}
	if _, single := parseHostKeySpec("   "); single != "" {
		t.Fatal("blank spec must yield empty single")
	}
}

func TestVerifySinglePin(t *testing.T) {
	key := testHostKey(t)
	fp := ssh.FingerprintSHA256(key)
	p := testPolicy(t, fp, "", "", false)
	if err := p.verify("10.0.0.1", key); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	other := testHostKey(t)
	if err := p.verify("10.0.0.1", other); err == nil {
		t.Fatal("wrong key accepted under single pin")
	}
}

func TestVerifyPinMapAndWildcard(t *testing.T) {
	keyA := testHostKey(t)
	keyB := testHostKey(t)
	fpA := ssh.FingerprintSHA256(keyA)
	fpB := ssh.FingerprintSHA256(keyB)
	p := testPolicy(t,
		"node-a="+fpA+",*="+fpB, "", "", false)
	// Exact host hit.
	if err := p.verify("NODE-A", keyA); err != nil {
		t.Fatalf("map hit rejected (case-insensitive): %v", err)
	}
	// Wildcard covers the rest.
	if err := p.verify("10.0.0.9", keyB); err != nil {
		t.Fatalf("wildcard pin rejected: %v", err)
	}
	// node-a under wildcard key must fail — its own pin wins.
	if err := p.verify("node-a", keyB); err == nil {
		t.Fatal("wildcard overrode the per-host pin")
	}
	// Unpinned-by-map host with a third key: no tofu/kh/insecure →
	// hard reject.
	if err := p.verify("other", testHostKey(t)); err == nil {
		t.Fatal("unpinned host accepted with no trust source")
	}
}

func TestVerifyTOFUFirstSeenThenBlocksChange(t *testing.T) {
	dir := t.TempDir()
	tofu := filepath.Join(dir, "hubsync_known_hosts")
	p := testPolicy(t, "", "", tofu, false)
	key1 := testHostKey(t)
	// First contact records + accepts.
	if err := p.verify("10.0.0.5", key1); err != nil {
		t.Fatalf("first contact rejected: %v", err)
	}
	if _, err := os.Stat(tofu); err != nil {
		t.Fatalf("tofu file not created: %v", err)
	}
	st, err := os.Stat(tofu)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tofu perms = %v, want 0600", st.Mode().Perm())
	}
	// Same key re-verified → accepted from the file.
	if err := p.verify("10.0.0.5", key1); err != nil {
		t.Fatalf("known key rejected: %v", err)
	}
	// Changed key → hard block (MITM).
	key2 := testHostKey(t)
	if err := p.verify("10.0.0.5", key2); err == nil ||
		!strings.Contains(err.Error(), "changed since first trust") {
		t.Fatalf("changed key err=%v, want hard block", err)
	}
	// A different host gets its own first-seen entry.
	if err := p.verify("10.0.0.6", key2); err != nil {
		t.Fatalf("second host first contact rejected: %v", err)
	}
	// The tofu file stays parseable by the stock knownhosts pkg.
	cb, err := knownhosts.New(tofu)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("10.0.0.6:22", hostPortAddr("10.0.0.6:22"), key2); err != nil {
		t.Fatalf("tofu entry not readable by knownhosts: %v", err)
	}
}

func TestVerifyKnownHostsEnforced(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	key := testHostKey(t)
	// Operator file in standard known_hosts format.
	if err := os.WriteFile(kh,
		[]byte(knownhosts.Line([]string{"vm-a"}, key)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, "", kh, "", false)
	if err := p.verify("vm-a", key); err != nil {
		t.Fatalf("known_hosts key rejected: %v", err)
	}
	if err := p.verify("vm-a", testHostKey(t)); err == nil {
		t.Fatal("known_hosts mismatch accepted")
	}
	// Unlisted host falls through — no tofu/insecure → reject.
	if err := p.verify("vm-b", key); err == nil {
		t.Fatal("unlisted host accepted without tofu")
	}
	// With tofu configured the unlisted host gets first-seen trust.
	tofu := filepath.Join(dir, "hubsync_known_hosts")
	p2 := testPolicy(t, "", kh, tofu, false)
	if err := p2.verify("vm-b", key); err != nil {
		t.Fatalf("unlisted host tofu rejected: %v", err)
	}
}

func TestVerifyInsecureLastResort(t *testing.T) {
	key := testHostKey(t)
	p := testPolicy(t, "", "", "", true)
	if err := p.verify("anything", key); err != nil {
		t.Fatalf("insecure accept failed: %v", err)
	}
	// No sources at all → hard reject naming both env knobs.
	p2 := testPolicy(t, "", "", "", false)
	err := p2.verify("anything", key)
	if err == nil || !strings.Contains(err.Error(),
		"NODE_HOST_AGENT_HUBSYNC_SSH_HOST_KEY_FINGERPRINT") {
		t.Fatalf("no-source err=%v, want fail-closed naming the pin env", err)
	}
}

func TestActiveGate(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	// Nothing configured → inactive (fail closed before dial).
	if testPolicy(t, "", "", "", false).active() {
		t.Fatal("empty policy must be inactive")
	}
	// known_hosts path set but file absent → still inactive.
	if testPolicy(t, "", kh, "", false).active() {
		t.Fatal("absent known_hosts must not activate")
	}
	if err := os.WriteFile(kh, []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !testPolicy(t, "", kh, "", false).active() {
		t.Fatal("present known_hosts must activate")
	}
	if !testPolicy(t, "", "", filepath.Join(dir, "s"), false).active() {
		t.Fatal("tofu path must activate")
	}
	if !testPolicy(t, "", "", "", true).active() {
		t.Fatal("insecure must activate")
	}
}
