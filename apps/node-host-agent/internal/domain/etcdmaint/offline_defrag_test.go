// offline_defrag_test.go — the production TempEtcd impl: Kill is
// the script's `kill "$STANDALONE"` (SIGTERM) and Wait reaps with a
// killGracePeriod → SIGKILL escalation. Exercised against the test
// binary itself as the fake etcd (GO_WANT_HELPER_PROCESS).
package etcdmaint

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHelperProcess is not a test — it is the fake standalone etcd
// the tempEtcdProc tests spawn. "term" keeps the default SIGTERM
// disposition (dies on Kill); "ignore" ignores SIGTERM so Wait must
// escalate to SIGKILL. GO_WANT_HELPER_READY names a file the helper
// touches once its signal disposition is armed — without the
// handshake a Kill racing process startup would land before
// signal.Ignore ran and the "ignore" case would die on SIGTERM.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("GO_WANT_HELPER_PROCESS")
	if mode == "" {
		return
	}
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
	}
	if ready := os.Getenv("GO_WANT_HELPER_READY"); ready != "" {
		_ = os.WriteFile(ready, []byte("1"), 0o600)
	}
	// A bare select{} trips the runtime's all-goroutines-asleep
	// deadlock detector — sleep keeps a timer pending instead.
	time.Sleep(time.Hour)
}

// startTempProc spawns the helper as a tempEtcdProc with a real log
// file — the same shape startTempEtcdExec returns — and blocks until
// the helper reports its signal disposition armed.
func startTempProc(t *testing.T, mode string) *tempEtcdProc {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	ready := filepath.Join(t.TempDir(), "ready")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS="+mode,
		"GO_WANT_HELPER_READY="+ready)
	log, err := os.CreateTemp(t.TempDir(), "etcd-standalone-*.log")
	if err != nil {
		t.Fatal(err)
	}
	p := &tempEtcdProc{cmd: cmd, log: log}
	if err := cmd.Start(); err != nil {
		t.Fatalf("helper start: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatal("helper never reported ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTempEtcdProcKillWait(t *testing.T) {
	// Kill on a never-started cmd is a no-op, not an error.
	idle := &tempEtcdProc{cmd: &exec.Cmd{}}
	if err := idle.Kill(); err != nil {
		t.Fatalf("Kill on nil Process=%v want nil", err)
	}

	// SIGTERM-killed helper: Wait reaps immediately — nowhere near
	// the killGracePeriod escalation.
	p := startTempProc(t, "term")
	start := time.Now()
	if err := p.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := p.Wait(); err == nil {
		t.Fatal("Wait on SIGTERM-killed process returned nil error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Wait took %v — escalation path should not fire", d)
	}
}

func TestTempEtcdProcWaitEscalatesToSIGKILL(t *testing.T) {
	// A process ignoring SIGTERM forces the killGracePeriod
	// escalation: Wait must SIGKILL and still reap.
	p := startTempProc(t, "ignore")
	if err := p.Kill(); err != nil { // SIGTERM — ignored by the helper
		t.Fatalf("Kill: %v", err)
	}
	start := time.Now()
	err := p.Wait()
	if err == nil {
		t.Fatal("Wait on SIGKILLed process returned nil error")
	}
	if d := time.Since(start); d < killGracePeriod-2*time.Second {
		t.Fatalf("Wait returned after %v — escalation fired early", d)
	}
}
