package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestFileJoinsUnderRoot(t *testing.T) {
	fs := New("/host/proc")
	if got, want := fs.File(4242), filepath.Join("/host/proc", "4242"); got != want {
		t.Fatalf("File(4242) = %q, want %q", got, want)
	}
	if got, want := fs.File(4242, "stat"), filepath.Join("/host/proc", "4242", "stat"); got != want {
		t.Fatalf("File(4242, stat) = %q, want %q", got, want)
	}
	if got, want := fs.File(4242, "task", "99", "comm"),
		filepath.Join("/host/proc", "4242", "task", "99", "comm"); got != want {
		t.Fatalf("File(4242, task, 99, comm) = %q, want %q", got, want)
	}
}

func TestPIDsListsNumericDirsInFilenameOrder(t *testing.T) {
	root := t.TempDir()
	// Dirs that count.
	mkDir(t, filepath.Join(root, "1234"))
	mkDir(t, filepath.Join(root, "42"))
	// Dirs that don't: non-numeric names and one that overflows Atoi.
	mkDir(t, filepath.Join(root, "self"))
	mkDir(t, filepath.Join(root, "99999999999999999999"))
	// Files never count, even numeric-named ones.
	writeFile(t, filepath.Join(root, "987"), "")
	writeFile(t, filepath.Join(root, "meminfo"), "x")

	pids, err := New(root).PIDs()
	if err != nil {
		t.Fatal(err)
	}
	// os.ReadDir order is filename order — "1234" sorts before "42",
	// so callers must not assume numeric order.
	if want := []int{1234, 42}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("PIDs = %v, want %v", pids, want)
	}

	// An empty-but-readable root is an empty list, not an error.
	if pids, err := New(t.TempDir()).PIDs(); err != nil || len(pids) != 0 {
		t.Fatalf("PIDs on empty root = %v, %v", pids, err)
	}
}

func TestPIDsMissingRootErrors(t *testing.T) {
	pids, err := New(filepath.Join(t.TempDir(), "gone")).PIDs()
	if err == nil {
		t.Fatal("unreadable root must surface the read error, not 'no processes'")
	}
	if pids != nil {
		t.Fatalf("PIDs on error = %v, want nil", pids)
	}
}

func TestCmdlineSplitsNulSeparatedArgv(t *testing.T) {
	fs := New(t.TempDir())
	writeFile(t, fs.File(1, "cmdline"), "agent\x00--root=/host/proc\x00")
	if got, want := fs.Cmdline(1), []string{"agent", "--root=/host/proc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Cmdline = %v, want %v", got, want)
	}
	// No trailing NUL still splits.
	writeFile(t, fs.File(2, "cmdline"), "a\x00b")
	if got, want := fs.Cmdline(2), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Cmdline = %v, want %v", got, want)
	}
	if got := fs.Cmdline(3); got != nil {
		t.Fatalf("missing cmdline = %v, want nil", got)
	}
}

func TestEnvValue(t *testing.T) {
	fs := New(t.TempDir())
	writeFile(t, fs.File(1, "environ"), "HOME=/root\x00FOO=bar\x00FOOBAR=x\x00EMPTY=\x00")
	for _, tc := range []struct {
		key, want string
	}{
		{"HOME", "/root"},
		{"FOO", "bar"},
		{"FOOBAR", "x"},
		{"EMPTY", ""},   // present-but-empty reads same as absent
		{"MISSING", ""}, // absent
		{"FOO_B", ""},   // not a prefix of FOO= / FOOBAR=
	} {
		if got := fs.EnvValue(1, tc.key); got != tc.want {
			t.Errorf("EnvValue(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
	// Key "FOO" must not match entry "FOOBAR=x" — the '=' anchors it.
	writeFile(t, fs.File(2, "environ"), "FOOBAR=x\x00")
	if got := fs.EnvValue(2, "FOO"); got != "" {
		t.Errorf("EnvValue(FOO) matched FOOBAR=x: %q", got)
	}
	if got := fs.EnvValue(3, "FOO"); got != "" {
		t.Errorf("missing environ: EnvValue = %q, want \"\"", got)
	}
}

func TestStatParsesPostCommFields(t *testing.T) {
	fs := New(t.TempDir())
	// comm itself contains spaces AND parens — every field must be
	// read after the LAST ')'.
	writeFile(t, fs.File(99, "stat"), "99 (weird (name) x) R 7 8\n")
	st, ok := fs.Stat(99)
	if !ok {
		t.Fatal("Stat ok=false on valid stat")
	}
	if st.Comm != "weird (name) x" || !st.HasComm {
		t.Fatalf("Comm = %q HasComm=%v, want %q,true", st.Comm, st.HasComm, "weird (name) x")
	}
	if want := []string{"R", "7", "8"}; !reflect.DeepEqual(st.Fields, want) {
		t.Fatalf("Fields = %v, want %v", st.Fields, want)
	}
}

func TestStatMalformed(t *testing.T) {
	fs := New(t.TempDir())
	for i, content := range []string{
		"1 no-parens S 2", // no ')' at all
		"1 (cmd)",         // nothing after the ')'
		"1 (cmd)   \n",    // only whitespace after the ')'
	} {
		writeFile(t, fs.File(100+i, "stat"), content)
		if _, ok := fs.Stat(100 + i); ok {
			t.Errorf("stat %q parsed as ok", content)
		}
	}
	// Misordered parens: fields still parse, but no valid comm.
	writeFile(t, fs.File(200, "stat"), "200 )bad( S 2")
	st, ok := fs.Stat(200)
	if !ok {
		t.Fatal("misordered parens must still yield fields")
	}
	if st.HasComm {
		t.Fatal("first '(' after last ')' must not set HasComm")
	}
	// Unreadable file.
	if _, ok := fs.Stat(300); ok {
		t.Fatal("Stat on missing file returned ok")
	}
}

func TestLive(t *testing.T) {
	fs := New(t.TempDir())
	writeFile(t, fs.File(100, "stat"), "100 (z) Z 1")
	writeFile(t, fs.File(200, "stat"), "200 (s) S 1")
	mkDir(t, fs.File(300)) // pid dir with no stat — fail-open case

	var lastPid int
	var lastSig syscall.Signal
	probe := func(pid int, sig syscall.Signal) error {
		lastPid, lastSig = pid, sig
		return nil
	}
	dead := func(int, syscall.Signal) error { return errors.New("esrch") }

	// Non-positive pids are dead without ever probing.
	for _, pid := range []int{0, -1, -4242} {
		if fs.Live(pid, probe) {
			t.Fatalf("Live(%d) = true", pid)
		}
	}
	if lastPid != 0 {
		t.Fatal("killFn invoked for a non-positive pid")
	}
	// kill -0 failure is dead regardless of stat content.
	if fs.Live(100, dead) {
		t.Fatal("kill -0 failure must read as dead")
	}
	// Zombie state is dead even though kill -0 succeeds.
	if fs.Live(100, probe) {
		t.Fatal("zombie must read as dead")
	}
	if lastPid != 100 || lastSig != syscall.Signal(0) {
		t.Fatalf("killFn got pid=%d sig=%d, want pid=100 sig=0", lastPid, lastSig)
	}
	if !fs.Live(200, probe) {
		t.Fatal("running proc must read as live")
	}
	// Unreadable stat after a successful probe fails open (live) —
	// callers must not force-kill on uncertainty.
	if !fs.Live(300, probe) {
		t.Fatal("missing stat after kill -0 must read as live")
	}
}

func TestPPID(t *testing.T) {
	fs := New(t.TempDir())
	writeFile(t, fs.File(1, "stat"), "1 (bash) S 1234 9 10")
	if got, ok := fs.PPID(1); !ok || got != 1234 {
		t.Fatalf("PPID = %d,%v, want 1234,true", got, ok)
	}
	writeFile(t, fs.File(2, "stat"), "2 (x) S")     // no field 4
	writeFile(t, fs.File(3, "stat"), "3 (x) S abc") // unparseable ppid
	writeFile(t, fs.File(4, "stat"), "4 (x) S -1")  // negative ppid
	for _, pid := range []int{2, 3, 4, 5 /* stat missing */} {
		if got, ok := fs.PPID(pid); ok {
			t.Errorf("PPID(%d) = %d,true, want ok=false", pid, got)
		}
	}
}

func TestAge(t *testing.T) {
	fs := New(t.TempDir())
	dir := fs.File(77)
	mkDir(t, dir)
	mtime := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(dir, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if got := fs.Age(77, mtime.Add(90*time.Second)); got != 90*time.Second {
		t.Fatalf("Age = %v, want 90s", got)
	}
	if got := fs.Age(78, mtime.Add(90*time.Second)); got != 0 {
		t.Fatalf("Age on missing pid dir = %v, want 0", got)
	}
}

func TestUptimeSeconds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "uptime"), "12345.67 89012.34\n")
	if got, err := New(root).UptimeSeconds(); err != nil || got != 12345.67 {
		t.Fatalf("UptimeSeconds = %v,%v, want 12345.67,nil", got, err)
	}
	if _, err := New(t.TempDir()).UptimeSeconds(); err == nil {
		t.Fatal("missing uptime file must error")
	}
}

func TestPIDAgeSeconds(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	// 20 post-comm fields; Fields[19]=starttime=1000 jiffies.
	writeFile(t, fs.File(42, "stat"),
		"42 (agent) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 1000")
	writeFile(t, filepath.Join(root, "uptime"), "100.00 400.00")

	// clkTck 100 → start = 10s after boot, uptime 100s → age 90s.
	got, err := fs.PIDAgeSeconds(42, 100)
	if err != nil || got != 90 {
		t.Fatalf("PIDAgeSeconds = %v,%v, want 90,nil", got, err)
	}

	// Stat jiffies ahead of uptime clamps to 0, never negative.
	writeFile(t, filepath.Join(root, "uptime"), "5.0 0.0")
	if got, err := fs.PIDAgeSeconds(42, 100); err != nil || got != 0 {
		t.Fatalf("negative age = %v,%v, want clamped 0,nil", got, err)
	}
}

func TestPIDAgeSecondsBadInput(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	writeFile(t, fs.File(2, "stat"), "2 no paren") // no ')'
	writeFile(t, fs.File(3, "stat"), "3 (x) S 1 2")
	writeFile(t, fs.File(4, "stat"),
		"4 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 1000")
	writeFile(t, fs.File(5, "stat"),
		"5 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 junk")
	for _, pid := range []int{1 /* missing */, 2 /* bad */, 3 /* short */, 5 /* bad starttime */} {
		if _, err := fs.PIDAgeSeconds(pid, 100); err == nil {
			t.Errorf("PIDAgeSeconds(%d) = nil error on bad stat", pid)
		}
	}
	// Valid stat but no uptime file still errors.
	if _, err := fs.PIDAgeSeconds(4, 100); err == nil {
		t.Error("PIDAgeSeconds with missing uptime = nil error")
	}
}

func TestFindByComm(t *testing.T) {
	root := t.TempDir()
	fs := New(root)
	writeFile(t, fs.File(50, "comm"), "other\n")
	writeFile(t, fs.File(100, "comm"), "target\n") // trailing newline trimmed
	writeFile(t, fs.File(200, "comm"), "target")
	mkDir(t, fs.File(300)) // pid dir with no comm file — skipped

	// Both 100 and 200 match — lowest pid wins (pgrep|head -1 parity).
	if got := fs.FindByComm("target"); got != 100 {
		t.Fatalf("FindByComm = %d, want lowest pid 100", got)
	}
	if got := fs.FindByComm("absent"); got != 0 {
		t.Fatalf("FindByComm(absent) = %d, want 0", got)
	}
	if got := New(filepath.Join(t.TempDir(), "gone")).FindByComm("target"); got != 0 {
		t.Fatalf("FindByComm on unreadable root = %d, want 0", got)
	}
}
