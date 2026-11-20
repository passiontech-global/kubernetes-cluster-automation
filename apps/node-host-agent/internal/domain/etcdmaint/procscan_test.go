// procscan_test.go — procZombie: the /proc/<pid>/stat state field
// is read from after the LAST ')' so comm with spaces/parens cannot
// shift it.
package etcdmaint

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

func TestProcZombie(t *testing.T) {
	root := t.TempDir()
	r := &rescuer{proc: procfs.New(root)}
	write := func(pid int, content string) {
		t.Helper()
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"),
			[]byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		pid     int
		content string
		want    bool
	}{
		{"zombie", 101, "101 (etcd) Z 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", true},
		{"running", 102, "102 (etcd) S 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", false},
		{
			// comm containing spaces and parens: the state field
			// must be taken after the last ')'.
			"tricky-comm",
			103,
			"103 (etcd (deleted)) R 1 1 0 0 -1 0 0 0 0 0\n",
			false,
		},
		{"tricky-comm-zombie", 104, "104 (etcd (deleted)) Z 1 1 0 0\n", true},
		{"empty", 105, "", false},
		{"no-paren", 106, "106 etcd S 1\n", false},
		{"state-only", 107, "107 (etcd) Z", true},
	}
	for _, c := range cases {
		write(c.pid, c.content)
		if got := r.procZombie(c.pid); got != c.want {
			t.Errorf("procZombie(%s)=%v want %v", c.name, got, c.want)
		}
	}
	if r.procZombie(99999) {
		t.Error("missing stat file must read as not-zombie")
	}
}

func TestFindEtcdProcessSkipsDZAndCapturesLiveArgs(t *testing.T) {
	root := t.TempDir()
	writeProc := func(pid int, stat, cmdline string) {
		t.Helper()
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if stat != "" {
			if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const etcdBin = "/fake/k0s/bin/etcd"
	// PID 100 is in D-state and must be skipped even though cmdline matches.
	writeProc(100, "100 (etcd) D 1 1 0 0\n", etcdBin+"\x00--name=wedged\x00")
	// PID 150 is in Z-state and must be skipped.
	writeProc(150, "150 (etcd) Z 1 1 0 0\n", etcdBin+"\x00--name=zombie\x00")
	// PID 200 is healthy S-state with an interior empty arg preserved.
	writeProc(200, "200 (etcd) S 1 1 0 0\n", etcdBin+"\x00--name\x00\x00--data-dir=/var/lib/etcd\x00")

	r := &rescuer{
		proc:    procfs.New(root),
		etcdBin: etcdBin,
		cfg:     Config{ProcRoot: root},
	}
	pid, args, err := r.findEtcdProcess()
	if err != nil {
		t.Fatalf("findEtcdProcess: %v", err)
	}
	if pid != 200 {
		t.Fatalf("pid = %d, want 200 (D/Z-state PIDs must be skipped)", pid)
	}
	if len(args) != 3 || args[0] != "--name" || args[1] != "" || args[2] != "--data-dir=/var/lib/etcd" {
		t.Fatalf("args = %q, want [--name \"\" --data-dir=/var/lib/etcd]", args)
	}
}
