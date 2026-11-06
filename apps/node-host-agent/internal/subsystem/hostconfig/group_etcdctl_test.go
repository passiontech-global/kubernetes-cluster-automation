// group_etcdctl_test.go — embedded-etcd etcdctl install
// (gate, staged-tgz sha256 verify) and the kine.service
// converge (binary pin, env/unit render, restart-on-change).
package hostconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- etcdctl (embedded-etcd controllers) ----------

// mkTgz builds a real .tar.gz holding member under an etcd-style top
// dir and returns (archive bytes, sha256 hex) — the staged-download
// fixture for etcdctl tests.
func mkTgz(t *testing.T, member, content string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "etcd-v3.7.3-linux-amd64/" + member, Mode: 0o755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))
}

// etcdctlEnv fabricates an embedded-etcd controller: the k0scontroller
// unit + pki/etcd/ca.crt that the groupEtcdctl gate composes (the same
// pair checkEtcdQuota requires).
func etcdctlEnv(t *testing.T, r *Reconciler) {
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Unit]\n")
	hostWrite(t, r, "/var/lib/k0s/pki/etcd/ca.crt", "ca")
}

func etcdctlPins(sum string) string {
	return fmt.Sprintf(`etcdctl_version: "3.7.3"
etcdctl_tgz_url: "https://example.test/etcd.tgz"
etcdctl_tgz_sha256: "%s"
etcdctl_tgz_file: "etcd-v3.7.3-linux-amd64.tar.gz"
`, sum)
}

func TestEtcdctlSkipsNonController(t *testing.T) {
	vars := writeVarsDir(t, etcdctlPins("deadbeef"))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// no k0scontroller.service + no pki — a worker/infra host.
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if len(sr.callsMatching("etcdctl")) > 0 {
		t.Fatalf("etcdctl probed on a non-controller: %v", sr.callsMatching("etcdctl"))
	}
	if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed on a non-controller")
	}
}

func TestEtcdctlSkipsKineHost(t *testing.T) {
	vars := writeVarsDir(t, etcdctlPins("deadbeef"))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// k0scontroller.service exists but no pki/etcd/ca.crt — the
	// kine-split controller shape: not an embedded-etcd host.
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Unit]\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if len(sr.callsMatching("etcdctl")) > 0 || hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed on a kine host (no embedded etcd pki)")
	}
}

func TestEtcdctlVersionMatchSkipsDownload(t *testing.T) {
	vars := writeVarsDir(t, etcdctlPins("deadbeef"))
	sr := &scriptedRunner{
		res: map[string]string{"/var/lib/k0s/bin/etcdctl version": "etcdctl version: 3.7.3"},
	}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	etcdctlEnv(t, r)
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("binary rewritten despite matching etcdctl version")
	}
}

func TestEtcdctlMissingPinsFailsClosed(t *testing.T) {
	// defaults.yaml carries no etcdctl_* vars — fail closed like kine.
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	etcdctlEnv(t, r)
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed without pins")
	}
	entries, _ := os.ReadDir(dl)
	if len(entries) > 0 {
		t.Fatal("download attempted without sha256 pin")
	}
}

func TestEtcdctlInstallsFromStagedTgz(t *testing.T) {
	arc, sum := mkTgz(t, "etcdctl", "fake-etcdctl-binary")
	vars := writeVarsDir(t, etcdctlPins(sum))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	etcdctlEnv(t, r)
	if err := os.WriteFile(filepath.Join(dl, "etcd-v3.7.3-linux-amd64.tar.gz"), arc, 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	bin := filepath.Join(r.cfg.HostRoot, "/var/lib/k0s/bin/etcdctl")
	got, err := os.ReadFile(bin)
	if err != nil || string(got) != "fake-etcdctl-binary" {
		t.Fatalf("etcdctl not installed from staged tgz: %v", err)
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o755 {
		t.Fatalf("etcdctl mode = %v want 0755", fi)
	}
}

func TestEtcdctlStagedShaMismatchRefuses(t *testing.T) {
	arc, _ := mkTgz(t, "etcdctl", "fake-etcdctl-binary")
	vars := writeVarsDir(t, etcdctlPins("00000000"))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	etcdctlEnv(t, r)
	if err := os.WriteFile(filepath.Join(dl, "etcd-v3.7.3-linux-amd64.tar.gz"), arc, 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed despite staged sha256 mismatch")
	}
}

// ---------- Phase 3: kine.service ----------

func TestKineServiceOffByDefault(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	for _, p := range []string{
		"/etc/systemd/system/kine.service", "/etc/kine/kine.env",
		"/usr/local/bin/kine",
	} {
		if hostExists(r, p) {
			t.Fatalf("%s written while node not in kine_service_hosts", p)
		}
	}
	for _, call := range sr.calls {
		if strings.Contains(call, "kine") {
			t.Fatalf("kine touched on unlisted host: %s", call)
		}
	}
}

func TestKineServiceConverge(t *testing.T) {
	bin := []byte("fake-kine-binary")
	sum := sha256.Sum256(bin)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bin)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "%s/kine"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://postgres:pw@db.test.internal:6432/postgres?sslmode=disable"
`, srv.URL, sum))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// wrong-hash binary staged -> must be re-downloaded
	hostWrite(t, r, "/usr/local/bin/kine", "tampered")

	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()

	gotBin, err := os.ReadFile(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/kine"))
	if err != nil || sha256.Sum256(gotBin) != sum {
		t.Fatalf("kine binary not staged/verified: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/kine")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("kine binary mode = %v want 0755", fi)
	}
	env := hostRead(t, r, "/etc/kine/kine.env")
	if !strings.Contains(env, "KINE_ENDPOINT=postgres://postgres:pw@db.test.internal:6432/postgres?sslmode=disable") {
		t.Fatalf("kine.env missing endpoint:\n%s", env)
	}
	if fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "/etc/kine/kine.env")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("kine.env mode = %v want 0600", fi)
	}
	if fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "/etc/kine")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("/etc/kine mode = %v want 0700", fi)
	}
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	for _, want := range []string{
		"Before=k0scontroller.service",
		"MemoryMax=2G",
		"Environment=GOMEMLIMIT=1500MiB",
		"Environment=GOGC=50",
		"OOMScoreAdjust=-500",
		"CPUWeight=2000",
		"EnvironmentFile=/etc/kine/kine.env",
		"ExecStartPre=/usr/bin/mkdir -p /run/k0s",
		"ExecStartPost=/bin/sh -c 'i=0; while [ ! -S /run/k0s/kine.sock ]",
		"ExecStart=/usr/local/bin/kine --listen-address=unix:///run/k0s/kine.sock --metrics-bind-address=:2380",
		"Restart=always",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("kine.service missing %q:\n%s", want, unit)
		}
	}
	if len(sr.callsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not run after unit write")
	}
	if len(sr.callsMatching("systemctl enable kine.service")) == 0 ||
		len(sr.callsMatching("systemctl start kine.service")) == 0 {
		t.Fatal("kine.service not enabled+started")
	}
	// first converge changes binary/env/unit -> restart to activate.
	if len(sr.callsMatching("systemctl restart kine.service")) == 0 {
		t.Fatal("kine.service not restarted after input changes")
	}
}

func TestKineServiceSkipsWithoutBinaryPins(t *testing.T) {
	vars := writeVarsDir(t, `kine_service_hosts: [node-a]
kine_endpoint: "postgres://x"
`)
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit written while the kine binary is unpinned/unverifiable")
	}
	if len(sr.callsMatching("systemctl enable kine.service")) > 0 {
		t.Fatal("kine.service enabled without a verified binary")
	}
}

// defaults.yaml contract: empty kine_endpoint = do not render the
// unit — a kine with no DSN falls back to sqlite on the socket the
// apiserver points at (data loss), so a listed host with an empty
// endpoint fails closed.
func TestKineServiceSkipsEmptyEndpoint(t *testing.T) {
	vars := writeVarsDir(t, `kine_service_hosts: [node-a]
kine_bin_url: "https://example/kine"
kine_bin_sha256: "deadbeef"
kine_endpoint: ""
`)
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if hostExists(r, "/etc/systemd/system/kine.service") || hostExists(r, "/etc/kine/kine.env") {
		t.Fatal("unit/env rendered with empty kine_endpoint")
	}
	if len(sr.callsMatching("systemctl enable kine.service")) > 0 ||
		len(sr.callsMatching("systemctl start kine.service")) > 0 {
		t.Fatal("kine.service enabled/started with empty kine_endpoint")
	}
}

func TestKineServiceIdempotentNoDownload(t *testing.T) {
	bin := []byte("fake-kine-binary")
	sum := sha256.Sum256(bin)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "http://127.0.0.1:1/never-used"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://x"
`, sum))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// correct binary already on host -> no fetch attempt against the
	// (unreachable) URL.
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/kine"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	if !hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit not written on a listed host")
	}
}
