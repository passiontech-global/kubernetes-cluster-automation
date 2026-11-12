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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// no k0scontroller.service + no pki — a worker/infra host.
	c := loadCyc(t, r, vars, "node-b")
	c.groupEtcdctl()
	if len(sr.CallsMatching("etcdctl")) > 0 {
		t.Fatalf("etcdctl probed on a non-controller: %v", sr.CallsMatching("etcdctl"))
	}
	if hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed on a non-controller")
	}
}

func TestEtcdctlSkipsKineHost(t *testing.T) {
	vars := writeVarsDir(t, etcdctlPins("deadbeef"))
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("etcdctl")) > 0 || hostExists(r, "/var/lib/k0s/bin/etcdctl") {
		t.Fatal("etcdctl installed on a kine host (no embedded etcd pki)")
	}
}

func TestEtcdctlVersionMatchSkipsDownload(t *testing.T) {
	vars := writeVarsDir(t, etcdctlPins("deadbeef"))
	sr := newScripted(map[string]string{"/var/lib/k0s/bin/etcdctl version": "etcdctl version: 3.7.3"}, nil)
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
	sr := newScripted(nil, nil)
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
	sr := newScripted(nil, nil)
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
	sr := newScripted(nil, nil)
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
	sr := newScripted(nil, nil)
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
	for _, call := range sr.Calls() {
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
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not run after unit write")
	}
	if len(sr.CallsMatching("systemctl enable kine.service")) == 0 ||
		len(sr.CallsMatching("systemctl start kine.service")) == 0 {
		t.Fatal("kine.service not enabled+started")
	}
	// first converge changes binary/env/unit -> restart to activate.
	if len(sr.CallsMatching("systemctl restart kine.service")) == 0 {
		t.Fatal("kine.service not restarted after input changes")
	}
}

func TestKineServiceSkipsWithoutBinaryPins(t *testing.T) {
	vars := writeVarsDir(t, `kine_service_hosts: [node-a]
kine_endpoint: "postgres://x"
`)
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("systemctl enable kine.service")) > 0 {
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
	sr := newScripted(nil, nil)
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
	if len(sr.CallsMatching("systemctl enable kine.service")) > 0 ||
		len(sr.CallsMatching("systemctl start kine.service")) > 0 {
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
	sr := newScripted(nil, nil)
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

// kineTCPEnv stages a listed kine host with a verified binary and
// the given extra cluster vars, then runs one groupKineService
// converge — the tcp/mTLS fixture. stage runs after the
// reconciler exists but before the converge (host-side file prep).
func kineTCPEnv(t *testing.T, extra string, stage func(*Reconciler)) (*Reconciler, *testutil.FakeRunner) {
	t.Helper()
	bin := []byte("fake-kine-binary")
	sum := sha256.Sum256(bin)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "http://127.0.0.1:1/never-used"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://x"
%s`, sum, extra))
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/usr/local/bin/kine", "fake-kine-binary")
	if stage != nil {
		stage(r)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	return r, sr
}

// Fail-closed mTLS guard: a tcp:// listener on a routable (non-loopback)
// host without all three mTLS cert files must never converge the
// unit — last-good is kept and nothing is enabled/started.
func TestKineServiceTCPNonLoopbackWithoutCertsRefused(t *testing.T) {
	r, sr := kineTCPEnv(t, `kine_listen_address: "tcp://10.0.0.5:2379"
`, nil)
	if hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit written for a non-loopback tcp listener without mTLS certs")
	}
	if hostExists(r, "/etc/kine/kine.env") {
		t.Fatal("kine.env written despite refused converge")
	}
	for _, call := range sr.Calls() {
		if strings.Contains(call, "systemctl enable kine") ||
			strings.Contains(call, "systemctl start kine") {
			t.Fatalf("kine.service started despite refused converge: %s", call)
		}
	}
}

// A partial TLS config (one cert file configured but absent on disk)
// fails closed just like a fully-unset one.
func TestKineServiceTCPNonLoopbackMissingCertOnDiskRefused(t *testing.T) {
	r, sr := kineTCPEnv(t, `kine_listen_address: "tcp://kine.internal:2379"
kine_ca_file: "/etc/kine/pki/ca.crt"
kine_server_cert_file: "/etc/kine/pki/server.crt"
kine_server_key_file: "/etc/kine/pki/missing.key"
`, nil)
	if hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit written while a cert file is missing on disk")
	}
	for _, call := range sr.Calls() {
		if strings.Contains(call, "systemctl enable kine") ||
			strings.Contains(call, "systemctl start kine") {
			t.Fatalf("kine.service started with incomplete mTLS: %s", call)
		}
	}
}

// All three cert files configured AND present on disk → the converge
// proceeds and the unit carries the full mTLS flag set.
func TestKineServiceTCPNonLoopbackWithCertsConverges(t *testing.T) {
	r, sr := kineTCPEnv(t, `kine_listen_address: "tcp://kine.internal:2379"
kine_ca_file: "/etc/kine/pki/ca.crt"
kine_server_cert_file: "/etc/kine/pki/server.crt"
kine_server_key_file: "/etc/kine/pki/server.key"
`, func(r *Reconciler) {
		for _, p := range []string{
			"/etc/kine/pki/ca.crt", "/etc/kine/pki/server.crt", "/etc/kine/pki/server.key",
		} {
			hostWrite(t, r, p, "cert")
		}
	})
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	for _, want := range []string{
		"--ca-file=/etc/kine/pki/ca.crt",
		"--server-cert-file=/etc/kine/pki/server.crt",
		"--server-key-file=/etc/kine/pki/server.key",
		"--listen-address=tcp://kine.internal:2379",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("kine.service missing %q:\n%s", want, unit)
		}
	}
	if len(sr.CallsMatching("systemctl enable kine.service")) == 0 ||
		len(sr.CallsMatching("systemctl start kine.service")) == 0 {
		t.Fatal("kine.service not enabled+started with full mTLS")
	}
}

// Loopback tcp listeners stay unrestricted: no cert requirement, and
// no TLS flags are rendered when the vars are unset.
func TestKineServiceTCPLoopbackNoCertRequirement(t *testing.T) {
	r, sr := kineTCPEnv(t, `kine_listen_address: "tcp://127.0.0.1:2379"
`, nil)
	if !hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit not written for a loopback tcp listener without certs")
	}
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	if strings.Contains(unit, "--ca-file") ||
		strings.Contains(unit, "--server-cert-file") ||
		strings.Contains(unit, "--server-key-file") {
		t.Fatalf("TLS flags rendered on a loopback listener without certs:\n%s", unit)
	}
	if !strings.Contains(unit, "--listen-address=tcp://127.0.0.1:2379") {
		t.Fatalf("loopback listen address not rendered:\n%s", unit)
	}
	if len(sr.CallsMatching("systemctl enable kine.service")) == 0 {
		t.Fatal("kine.service not enabled on loopback listener")
	}
}

// IPv6 loopback is loopback: tcp://[::1]:2379 converges without the
// mTLS cert set exactly like 127.0.0.1 — the bracketed literal must
// not fall into the non-loopback guard.
func TestKineServiceTCPLoopbackV6NoCertRequirement(t *testing.T) {
	r, sr := kineTCPEnv(t, `kine_listen_address: "tcp://[::1]:2379"
`, nil)
	if !hostExists(r, "/etc/systemd/system/kine.service") {
		t.Fatal("unit not written for an IPv6 loopback tcp listener without certs")
	}
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	if !strings.Contains(unit, "--listen-address=tcp://[::1]:2379") {
		t.Fatalf("IPv6 loopback listen address not rendered:\n%s", unit)
	}
	if len(sr.CallsMatching("systemctl enable kine.service")) == 0 {
		t.Fatal("kine.service not enabled on IPv6 loopback listener")
	}
}

// Every kine_* value bound for kine.env or the unit's Exec lines
// passes its sink's charset gate — a refused var keeps last-good
// unit+env and skips even the binary download.
func TestKineServiceUnsafeVarsRefused(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"endpoint newline splices env line",
			"kine_endpoint: \"postgres://x\\nEVIL_INJECTED=1\""},
		{"endpoint quote reopens env quoting",
			"kine_endpoint: \"postgres://x\\\"EVIL=1\""},
		{"listen single-quote breaks wait-loop",
			"kine_listen_address: \"unix:///run/k0s/kine.sock';id;#\""},
		{"listen space splits exec args",
			"kine_listen_address: \"unix:///run/k0s/kine.sock --evil\""},
		{"metrics bind space splits exec args",
			"kine_metrics_bind_address: \":2380 --evil\""},
		{"cert path semicolon",
			"kine_ca_file: \"/etc/kine/ca.crt;id\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := []byte("fake-kine-binary")
			sum := sha256.Sum256(bin)
			vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "http://127.0.0.1:1/never-used"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://x"
%s
`, sum, tc.yaml))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
				VarsDir: vars, Runner: sr}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Verified binary present → the refusal must come from
			// the var gate, not the binary pin path.
			hostWrite(t, r, "/usr/local/bin/kine", "fake-kine-binary")
			c := loadCyc(t, r, vars, "node-a")
			c.groupKineService()
			if hostExists(r, "/etc/systemd/system/kine.service") ||
				hostExists(r, "/etc/kine/kine.env") {
				t.Fatalf("unit/env rendered with unsafe var:\n%s", tc.yaml)
			}
			for _, call := range sr.Calls() {
				if strings.Contains(call, "systemctl enable kine") ||
					strings.Contains(call, "systemctl start kine") {
					t.Fatalf("kine.service started with unsafe var: %s", call)
				}
			}
		})
	}
}
