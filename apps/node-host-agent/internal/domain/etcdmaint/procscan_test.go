// procscan_test.go — procZombie: the /proc/<pid>/stat state field
// is read from after the LAST ')' so comm with spaces/parens cannot
// shift it.
package etcdmaint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcZombie(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"zombie", "4242 (etcd) Z 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", true},
		{"running", "4242 (etcd) S 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", false},
		{
			// comm containing spaces and parens: the state field
			// must be taken after the last ')'.
			"tricky-comm",
			"4242 (etcd (deleted)) R 1 1 0 0 -1 0 0 0 0 0\n",
			false,
		},
		{"tricky-comm-zombie", "4242 (etcd (deleted)) Z 1 1 0 0\n", true},
		{"empty", "", false},
		{"no-paren", "4242 etcd S 1\n", false},
		{"state-only", "4242 (etcd) Z", true},
	}
	for _, c := range cases {
		if got := procZombie(write(c.name, c.content)); got != c.want {
			t.Errorf("procZombie(%s)=%v want %v", c.name, got, c.want)
		}
	}
	if procZombie(filepath.Join(dir, "does-not-exist")) {
		t.Error("missing stat file must read as not-zombie")
	}
}
