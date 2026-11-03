package hostconfig

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
)

type fakeRunner struct{ calls []string }

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "systemctl":
		if len(args) > 0 && args[0] == "is-active" {
			return "inactive", nil
		}
		if len(args) > 0 && args[0] == "show" {
			return "inactive", nil
		}
		return "", nil
	case "sysctl":
		return "bbr\nfq", nil
	}
	return "", nil
}

func newTestReconciler(t *testing.T, varsDir string) *Reconciler {
	t.Helper()
	r, err := New(Config{
		Enabled:            true,
		NodeName:           "node-b",
		HostRoot:           t.TempDir(),
		VarsDir:            varsDir,
		NebulaCertsDir:     t.TempDir(),
		WatchdogScriptsDir: t.TempDir(),
		Runner:             &fakeRunner{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAtomicWriteIdempotent(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	ch, err := r.writeManaged("/etc/test.conf", []byte("hello"), 0o644)
	if err != nil || !ch {
		t.Fatal("first write should change")
	}
	ch, _ = r.writeManaged("/etc/test.conf", []byte("hello"), 0o644)
	if ch {
		t.Fatal("same content should not change")
	}
	ch, _ = r.writeManaged("/etc/test.conf", []byte("world"), 0o644)
	if !ch {
		t.Fatal("new content should change")
	}
	b, _ := os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/test.conf"))
	if string(b) != "world" {
		t.Fatal("content mismatch")
	}
	if sha256.Sum256(b) != sha256.Sum256([]byte("world")) {
		t.Fatal("bad hash")
	}
	// tmp file must not linger
	if _, err := os.Stat(filepath.Join(r.cfg.HostRoot, "etc/test.conf.hostconfig.tmp")); !os.IsNotExist(err) {
		t.Fatal("tmp file lingered")
	}
}

func TestModePreserved(t *testing.T) {
	r := newTestReconciler(t, t.TempDir())
	os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755)
	p := filepath.Join(r.cfg.HostRoot, "etc/x.conf")
	os.WriteFile(p, []byte("old"), 0o600)
	if ch, _ := r.writeManaged("/etc/x.conf", []byte("new"), 0o644); !ch {
		t.Fatal("expected change")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v not preserved", st.Mode())
	}
}

func TestPinUnpinHosts(t *testing.T) {
	vars := t.TempDir()
	os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte("node-b: {name: b, ip: 10.0.0.1, site: s1}\n"), 0o644)
	os.WriteFile(filepath.Join(vars, "defaults.yaml"), []byte("cp_endpoint: api.test.internal\n"), 0o644)
	os.WriteFile(filepath.Join(vars, "cluster.yaml"), []byte("{}\n"), 0o644)
	r := newTestReconciler(t, vars)
	os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755)
	os.WriteFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644)
	topo, err := topology.Load(topology.Config{VarsDir: vars, NodeName: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	c := &cyc{r: r, ctx: context.Background(), t: topo}
	c.pinHosts()
	b, _ := os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"))
	if !strings.Contains(string(b), "127.0.0.1 api.test.internal") {
		t.Fatalf("hosts not pinned:\n%s", b)
	}
	c.unpinHosts()
	b, _ = os.ReadFile(filepath.Join(r.cfg.HostRoot, "etc/hosts"))
	if strings.Contains(string(b), "api.test.internal") {
		t.Fatal("pin not removed")
	}
}

// TestDirWatcherPollChangedEdge: Poll seeds the baseline without
// firing, latches one edge per fingerprint move, and Changed consumes
// it exactly once — without re-hashing the dirs on the main loop.
func TestDirWatcherPollChangedEdge(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}, Period: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Poll(ctx)

	deadline := time.Now().Add(5 * time.Second)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}

	waitFor("Poll first scan", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.polled
	})
	if w.Changed() {
		t.Fatal("Changed fired on the freshly-seeded baseline")
	}

	// A file appearing between polls must surface as exactly one edge.
	if err := os.WriteFile(filepath.Join(dir, "vars.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("dirty latch", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.dirty
	})
	if !w.Changed() {
		t.Fatal("Changed lost the poll-latched edge")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for one edge")
	}
}

// TestDirWatcherChangedWithoutPoll: the pre-Poll fallback — Changed
// compares a fresh fingerprint against the last snapshot when Poll
// never ran (unit tests calling Changed directly).
func TestDirWatcherChangedWithoutPoll(t *testing.T) {
	dir := t.TempDir()
	w := &DirWatcher{Dirs: []string{dir}}
	if !w.Changed() {
		t.Fatal("first Changed should report a difference vs empty baseline")
	}
	if w.Changed() {
		t.Fatal("second Changed without file modifications should be false")
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !w.Changed() {
		t.Fatal("Changed missed the new file without Poll")
	}
	if w.Changed() {
		t.Fatal("Changed fired twice for the same file without Poll")
	}
}
