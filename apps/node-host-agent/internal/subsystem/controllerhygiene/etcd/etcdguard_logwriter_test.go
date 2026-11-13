// etcdguard_logwriter_test.go — in-package coverage for the
// guardLogWriter io.Writer adapter: newline framing, blank-line skip,
// partial-line buffering until flush, and the "etcdguard: " prefix on
// every watchdog log line. External tests can't reach the unexported
// type; it needs only a Deps with a Store pointed at a temp log file.
package etcd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func newLogWriter(t *testing.T) (*guardLogWriter, string) {
	t.Helper()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "watchdog.log")
	d := &cdeps.Deps{State: hoststate.New(dir, logFile, nil, nil)}
	return &guardLogWriter{d: d}, logFile
}

func logFileLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing appended yet — no log file created
		}
		t.Fatalf("read log: %v", err)
	}
	var lines []string
	for l := range strings.SplitSeq(strings.TrimRight(string(b), "\n"), "\n") {
		// Strip the "<rfc3339> " prefix — the message text is the
		// contract under test.
		if i := strings.IndexByte(l, ' '); i >= 0 {
			l = l[i+1:]
		}
		lines = append(lines, l)
	}
	return lines
}

func TestGuardLogWriterFramesLines(t *testing.T) {
	w, logFile := newLogWriter(t)

	// One Write carrying two complete lines: both land with the
	// prefix, and the full input length is reported.
	n, err := w.Write([]byte("first line\nsecond line\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("first line\nsecond line\n") {
		t.Fatalf("Write = %d, want full input length", n)
	}
	lines := logFileLines(t, logFile)
	if len(lines) != 2 ||
		lines[0] != "etcdguard: first line" ||
		lines[1] != "etcdguard: second line" {
		t.Fatalf("lines = %q, want two prefixed entries", lines)
	}

	// Blank lines are dropped, not logged.
	if _, err := w.Write([]byte("\n\n")); err != nil {
		t.Fatalf("Write blank: %v", err)
	}
	if got := logFileLines(t, logFile); len(got) != 2 {
		t.Fatalf("blank lines logged: %q", got)
	}
}

func TestGuardLogWriterBuffersPartialUntilFlush(t *testing.T) {
	w, logFile := newLogWriter(t)

	// A stream ending without '\n' must NOT reach the log yet.
	if _, err := w.Write([]byte("no trailing newline")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := logFileLines(t, logFile); len(got) != 0 {
		t.Fatalf("partial line logged before flush: %q", got)
	}

	// flush emits the trailing partial line exactly once.
	w.flush()
	if got := logFileLines(t, logFile); len(got) != 1 ||
		got[0] != "etcdguard: no trailing newline" {
		t.Fatalf("post-flush lines = %q, want the partial line", got)
	}

	// A second flush is a no-op — the buffer was reset.
	w.flush()
	if got := logFileLines(t, logFile); len(got) != 1 {
		t.Fatalf("double flush logged again: %q", got)
	}
}
