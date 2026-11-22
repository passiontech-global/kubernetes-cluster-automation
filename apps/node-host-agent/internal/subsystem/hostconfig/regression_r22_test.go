// regression_r22_test.go — R2.2 security regression tests for hostconfig:
// staging dir 0700 tightening (without touching /var/lib/node-watchdog or
// /usr/local/bin) and basename traversal rejection across all 5 artifact groups.
package hostconfig

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStagingDirTightenedTo0700(t *testing.T) {
	t.Run("hubmetrics", func(t *testing.T) {
		deb := []byte("fake-deb")
		sum := sha256.Sum256(deb)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(deb)
		}))
		t.Cleanup(srv.Close)

		vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "1.7.0"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%x"
`, srv.URL, sum))
		sr := newScripted(nil, nil)
		r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
			VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		dlDir := filepath.Join(r.cfg.HostRoot, "/var/lib/node-watchdog/downloads")
		if err := os.MkdirAll(dlDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dlDir, 0o755); err != nil {
			t.Fatal(err)
		}

		c := loadCyc(t, r, vars, "node-a")
		c.groupHubMetricsFW()
		if c.errs != 0 {
			t.Fatalf("errs = %d, want 0", c.errs)
		}
		if fi, err := os.Stat(dlDir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("hubmetrics staging dir mode = %v, want 0700", fi)
		}
	})

	t.Run("etcdctl_DownloadDir", func(t *testing.T) {
		url, sum := tarballServer(t, map[string]string{"etcdctl": "#!/bin/sh\n"})
		vars := writeVarsDir(t, fmt.Sprintf(`etcdctl_version: "1.0.0"
etcdctl_tgz_url: %q
etcdctl_tgz_sha256: %q
etcdctl_tgz_file: "etcdctl.tgz"
`, url, sum))
		sr := newScripted(nil, nil)
		dlDir := filepath.Join(t.TempDir(), "downloads")
		if err := os.MkdirAll(dlDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dlDir, 0o755); err != nil {
			t.Fatal(err)
		}
		r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
			VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
			DownloadDir: dlDir}, nil)
		if err != nil {
			t.Fatal(err)
		}
		hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
		hostWrite(t, r, "/var/lib/k0s/pki/etcd/ca.crt", "ca\n")

		c := loadCyc(t, r, vars, "node-a")
		c.groupEtcdctl()
		if c.errs != 0 {
			t.Fatalf("errs = %d, want 0", c.errs)
		}
		if fi, err := os.Stat(dlDir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("etcdctl DownloadDir mode = %v, want 0700", fi)
		}
	})
}

func TestStagedBasenameTraversalRejectedAcrossAllFiveGroups(t *testing.T) {
	badNames := []struct {
		name string
		val  string
	}{
		{"dotdot_slash", "../evil"},
		{"nested_traversal", "../../etc/cron.d/pwn"},
		{"subdir", "sub/file"},
		{"abs_path", "/abs/file"},
		{"backslash", `a\b`},
		{"dotdot", ".."},
		{"dot", "."},
		{"empty", ""},
		{"nul", "file\x00.tgz"},
	}

	for _, tc := range badNames {
		t.Run("hubmetrics/"+tc.name, func(t *testing.T) {
			url := "http://127.0.0.1:1/nexp.deb"
			if tc.val == "" {
				// Exercise URL basename fallback producing ".."
				url = "http://127.0.0.1:1/.."
			}
			vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "1.7.0"
interdc_nexp_deb_url: %q
interdc_nexp_deb_sha256: "deadbeef"
interdc_nexp_deb_file: %q
`, url, tc.val))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-a")
			c.hubMetricsNodeExporter()
			if c.errs == 0 {
				t.Fatalf("hubmetrics accepted unsafe filename %q", tc.val)
			}
			if len(sr.CallsMatching("apt-get")) != 0 {
				t.Fatalf("apt-get ran on unsafe filename %q: %v", tc.val, sr.Calls())
			}
		})

		t.Run("apilb/"+tc.name, func(t *testing.T) {
			vars := writeVarsDir(t, fmt.Sprintf(`api_lb_enabled: true
api_lb_haproxy_version: "2.8.16"
api_lb_haproxy_deb_url: "http://127.0.0.1:1/haproxy.deb"
api_lb_haproxy_deb_sha256: "deadbeef"
api_lb_haproxy_deb_file: %q
`, tc.val))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				DNSProbe: dnsProbeAnyOK(), TCPProbe: tcpProbeAllOK(), ListenAddrsFn: listenAddrsFake()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			hostWrite(t, r, "/etc/systemd/system/k0sworker.service", "[Service]\n")
			c := loadCyc(t, r, vars, "node-b")
			c.groupAPILB()
			if c.errs == 0 {
				t.Fatalf("apilb accepted unsafe filename %q", tc.val)
			}
			if len(sr.CallsMatching("apt-get")) != 0 {
				t.Fatalf("apt-get ran on unsafe filename %q: %v", tc.val, sr.Calls())
			}
		})

		t.Run("etcdctl/"+tc.name, func(t *testing.T) {
			url := "http://127.0.0.1:1/etcdctl.tgz"
			if tc.val == "" {
				url = "http://127.0.0.1:1/.."
			}
			vars := writeVarsDir(t, fmt.Sprintf(`etcdctl_version: "1.0.0"
etcdctl_tgz_url: %q
etcdctl_tgz_sha256: "deadbeef"
etcdctl_tgz_file: %q
`, url, tc.val))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				DownloadDir: t.TempDir()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
			hostWrite(t, r, "/var/lib/k0s/pki/etcd/ca.crt", "ca\n")
			c := loadCyc(t, r, vars, "node-a")
			c.groupEtcdctl()
			if c.errs == 0 {
				t.Fatalf("etcdctl accepted unsafe filename %q", tc.val)
			}
		})

		t.Run("nebula/"+tc.name, func(t *testing.T) {
			vars := writeVarsDir(t, fmt.Sprintf(`interdc_nebula_version: "1.9.0"
interdc_nebula_tgz_url: "http://127.0.0.1:1/nebula.tgz"
interdc_nebula_tgz_sha256: "deadbeef"
interdc_nebula_tgz_file: %q
`, tc.val))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				DownloadDir: t.TempDir()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			if c.nebulaInstallBinary() {
				t.Fatalf("nebula accepted unsafe filename %q", tc.val)
			}
			if c.errs == 0 {
				t.Fatalf("nebula did not count error for unsafe filename %q", tc.val)
			}
		})

		t.Run("coredns/"+tc.name, func(t *testing.T) {
			vars := writeVarsDir(t, fmt.Sprintf(`interdc_coredns_version: "1.11.1"
interdc_coredns_url: "http://127.0.0.1:1/coredns.tgz"
interdc_coredns_sha256: "deadbeef"
interdc_coredns_tgz: %q
`, tc.val))
			sr := newScripted(nil, nil)
			r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
				VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr,
				DownloadDir: t.TempDir()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := loadCyc(t, r, vars, "node-b")
			if c.corednsInstallBinary() {
				t.Fatalf("coredns accepted unsafe filename %q", tc.val)
			}
			if c.errs == 0 {
				t.Fatalf("coredns did not count error for unsafe filename %q", tc.val)
			}
		})
	}

	if !validStagedBasename("nebula-1.9.0.tar.gz") {
		t.Fatal("validStagedBasename rejected normal filename")
	}
}

func TestDownloadDirPodModeUsesHostRoot(t *testing.T) {
	url, sum := tarballServer(t, map[string]string{"etcdctl": "#!/bin/sh\n"})
	vars := writeVarsDir(t, fmt.Sprintf(`etcdctl_version: "1.0.0"
etcdctl_tgz_url: %q
etcdctl_tgz_sha256: %q
etcdctl_tgz_file: "etcdctl.tgz"
`, url, sum))

	t.Run("pod mode wraps defaultDownloadDir with HostRoot", func(t *testing.T) {
		hostRoot := t.TempDir()
		sr := newScripted(nil, nil)
		r, err := New(Config{
			NodeName:       "node-a",
			HostRoot:       hostRoot,
			VarsDir:        vars,
			NebulaCertsDir: t.TempDir(),
			Runner:         sr,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.cfg.Standalone {
			t.Fatal("expected pod mode (Standalone=false) when HostRoot != /")
		}
		if r.cfg.DownloadDir != defaultDownloadDir {
			t.Fatalf("cfg.DownloadDir = %q, want %q", r.cfg.DownloadDir, defaultDownloadDir)
		}
		wantDir := filepath.Join(hostRoot, "var", "lib", "node-watchdog", "downloads")
		if got := r.downloadDir(); got != wantDir {
			t.Fatalf("downloadDir() = %q, want %q", got, wantDir)
		}
		hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
		hostWrite(t, r, "/var/lib/k0s/pki/etcd/ca.crt", "ca\n")

		c := loadCyc(t, r, vars, "node-a")
		c.groupEtcdctl()
		if c.errs != 0 {
			t.Fatalf("errs = %d, want 0", c.errs)
		}
		if fi, err := os.Stat(wantDir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("pod-mode staging dir = (%v, %v), want mode 0700", fi, err)
		}
		if _, err := os.Stat(filepath.Join(wantDir, "etcdctl.tgz")); err != nil {
			t.Fatalf("staged tarball missing under HostRoot: %v", err)
		}
		if _, err := os.Stat(filepath.Join(hostRoot, "var", "lib", "k0s", "bin", "etcdctl")); err != nil {
			t.Fatalf("installed etcdctl missing under HostRoot: %v", err)
		}
	})

	t.Run("custom DownloadDir outside HostRoot is used verbatim", func(t *testing.T) {
		hostRoot := t.TempDir()
		customDir := filepath.Join(t.TempDir(), "custom-dl")
		sr := newScripted(nil, nil)
		r, err := New(Config{
			NodeName:       "node-a",
			HostRoot:       hostRoot,
			VarsDir:        vars,
			NebulaCertsDir: t.TempDir(),
			DownloadDir:    customDir,
			Runner:         sr,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.downloadDir(); got != customDir {
			t.Fatalf("downloadDir() = %q, want %q", got, customDir)
		}
	})
}
