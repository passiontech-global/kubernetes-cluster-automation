package hostconfig

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
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
