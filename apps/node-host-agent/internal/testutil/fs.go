// fs.go — the temp-file fixture helpers every suite carried as a
// private writeFile/readFile: MkdirAll + WriteFile + t.Fatal, and the
// read-back for assertions. 0644 content, 0755 parents — fixtures
// that need other modes keep their own os.WriteFile.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteFile plants content at path, creating parent dirs. Fatal on error.
func WriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ReadFile returns path's content as a string. Fatal on error.
func ReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
