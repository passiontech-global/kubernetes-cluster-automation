package pagecache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDropOnOpenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(p, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	Drop(f) // must not panic / must be callable on a regular file
}

func TestReadFileReturnsContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	want := []byte("hello pagecache")
	if err := os.WriteFile(p, want, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("ReadFile = %q, want %q", got, want)
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Fatalf("ReadFile missing err = %v, want ENOENT", err)
	}
}

func TestSha256FileMatchesDigest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	payload := make([]byte, 3<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := Sha256File(p)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("Sha256File = %s, want %s", sum, hex.EncodeToString(want[:]))
	}
	if _, err := Sha256File(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Fatalf("Sha256File missing err = %v, want ENOENT", err)
	}
}
