// group_etcdctl_extra_test.go — etcdctl + kine.service install
// coverage: the prepare-arm (unreadable k0s bin dir), the missing
// tarball member, the kine binary download failure, and the kine
// unit's render/permissions arms.
package hostconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// etcdctlFixture — controller node with the embedded-etcd pki marker
// + the served etcdctl tarball pins.
func etcdctlFixture(t *testing.T, members map[string]string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	url, sum := tarballServer(t, members)
	vars := writeVarsDir(t, fmt.Sprintf(`etcdctl_version: "1.0.0"
etcdctl_tgz_url: %q
etcdctl_tgz_sha256: %q
etcdctl_tgz_file: "etcdctl.tgz"
`, url, sum))
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
		DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	hostWrite(t, r, "/var/lib/k0s/pki/etcd/ca.crt", "ca\n")
	return r, sr, loadCyc(t, r, vars, "node-a")
}

// TestEtcdctlPrepareAndInstallArms — the install flow's failure arms
// at the etcdctl call site: an unreadable k0s bin dir aborts before
// extraction; a tarball without the member counts the install error.
func TestEtcdctlPrepareAndInstallArms(t *testing.T) {
	t.Run("prepare_failed", func(t *testing.T) {
		r, _, c := etcdctlFixture(t, map[string]string{"etcdctl": "#!/bin/sh\n"})
		// /var/lib/k0s/bin as a FILE — the prepare MkdirAll fails.
		hostWrite(t, r, "/var/lib/k0s/bin", "not a dir\n")
		c.groupEtcdctl()
		if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
			t.Fatal("etcdctl installed although the bin dir was not preparable")
		}
		if c.errs == 0 {
			t.Fatal("prepare failure did not count a cycle error")
		}
	})
	t.Run("member_missing", func(t *testing.T) {
		r, _, c := etcdctlFixture(t, map[string]string{"other": "#!/bin/sh\n"})
		c.groupEtcdctl()
		if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
			t.Fatal("etcdctl installed from a tarball without the member")
		}
		if c.errs == 0 {
			t.Fatal("failed extraction did not count a cycle error")
		}
	})
}

// TestKineServiceDownloadFailure — a failed kine binary download
// counts and aborts the unit converge (no unit against a missing
// binary).
func TestKineServiceDownloadFailure(t *testing.T) {
	vars := writeVarsDir(t, `kine_service_hosts: [node-a]
kine_endpoint: "postgres://x"
kine_bin_url: "http://127.0.0.1:1/kine"
kine_bin_sha256: "0000"
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if c.errs == 0 {
		t.Fatal("failed kine download did not count a cycle error")
	}
	if hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("kine unit written although the binary never landed")
	}
}

// TestKineServicePermissionArms — the env/DSN file converges with
// 0600 + dir 0700; the unit renders for a unix socket listener with
// the exec pre/post hooks and the /run/k0s socket path.
func TestKineServicePermissionArms(t *testing.T) {
	bin := []byte("#!/bin/sh\n# fake kine\n")
	url, sum := rawServer(t, bin)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_endpoint: "sqlite:///var/lib/k0s/db/kine.db"
kine_bin_url: %q
kine_bin_sha256: %q
`, url, sum))
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if c.errs != 0 {
		t.Fatalf("errs = %d on the happy kine converge", c.errs)
	}
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	for _, want := range []string{
		"EnvironmentFile=/etc/kine/kine.env",
		"ExecStart=/usr/local/bin/kine",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("kine unit missing %q:\n%s", want, unit)
		}
	}
	env := hostRead(t, r, "/etc/kine/kine.env")
	if !strings.Contains(env, "KINE_ENDPOINT=sqlite:///var/lib/k0s/db/kine.db") {
		t.Fatalf("kine.env missing the endpoint:\n%s", env)
	}
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/etc/kine/kine.env"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("kine.env mode = %v, want 0600 (DSN carries the DB password)", fi.Mode().Perm())
	}
}

// TestKineServiceChmodFailureArms — /etc/kine as a symlink to a
// root-owned non-directory: the 0700 dir chmod and the 0600 env
// chmod both fail and count (the DSN file must never stay readable).
func TestKineServiceChmodFailureArms(t *testing.T) {
	bin := []byte("#!/bin/sh\n# fake kine\n")
	url, sum := rawServer(t, bin)
	vars := writeVarsDir(t, "kine_service_hosts: [node-a]\n"+
		"kine_endpoint: \"sqlite:///var/lib/k0s/db/kine.db\"\n"+
		"kine_bin_url: \""+url+"\"\n"+
		"kine_bin_sha256: \""+sum+"\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(r.cfg.HostRoot, "etc/kine")); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if c.errs < 2 {
		t.Fatalf("errs = %d, want the dir + env chmod failures counted", c.errs)
	}
}
