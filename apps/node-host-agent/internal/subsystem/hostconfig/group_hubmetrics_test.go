// group_hubmetrics_test.go — hub metrics firewall: HUBMETRICS
// iptables rebuild (incl. injected-IP refusal), node-exporter
// textfile drop-in, and the pinned deb download/verify/install.
package hostconfig

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- hub-metrics-fw ----------

func TestHubMetricsFWRenders(t *testing.T) {
	vars := writeVarsDir(t, "hub_metrics_extra_ports: [2380, 2381]\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()

	di := hostRead(t, r, "/etc/systemd/system/prometheus-node-exporter.service.d/textfile.conf")
	if !strings.Contains(di, "--collector.textfile.directory=/var/lib/node-exporter/textfile") {
		t.Fatalf("bad textfile drop-in:\n%s", di)
	}
	calls := sr.CallsMatching("iptables -N HUBMETRICS")
	if len(calls) == 0 {
		t.Fatal("HUBMETRICS rebuild not run")
	}
	script := calls[len(calls)-1]
	for _, want := range []string{
		"iptables -A HUBMETRICS -p tcp -s 10.0.1.10 --dport 9100 -j ACCEPT",
		"iptables -A HUBMETRICS -p tcp -s 10.0.2.20 --dport 9100 -j ACCEPT",
		"iptables -A HUBMETRICS -p tcp -s 172.29.0.0/24 --dport 9100 -j ACCEPT",
		"iptables -A HUBMETRICS -p tcp --dport 9100 -j DROP",
		"iptables -A HUBMETRICS -p tcp --dport 9115 -j DROP",
		"iptables -A HUBMETRICS -p tcp --dport 2380 -j DROP",
		"iptables -A HUBMETRICS -p tcp --dport 2381 -j DROP",
		"iptables -I INPUT 1 -p tcp --dport 2380 -j HUBMETRICS",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("HUBMETRICS script missing %q:\n%s", want, script)
		}
	}
	if len(sr.CallsMatching("systemctl enable prometheus-node-exporter.service")) == 0 ||
		len(sr.CallsMatching("systemctl start prometheus-node-exporter.service")) == 0 {
		t.Fatal("node-exporter not enabled+started")
	}
}

// ---------- hub-metrics-fw: node_exporter deb install ----------

func TestHubMetricsNexpSkipsWhenVersionMatches(t *testing.T) {
	vars := writeVarsDir(t, `interdc_nexp_version: "1.7.0-1ubuntu0.3"
interdc_nexp_deb_url: "http://127.0.0.1:1/never-used.deb"
interdc_nexp_deb_sha256: "deadbeef"
interdc_nexp_deb_file: "nexp.deb"
`)
	// dpkg reports the pinned version already installed → the whole
	// download/verify/install chain must be skipped (ansible `when`).
	sr := newScripted(map[string]string{
		"dpkg-query -W -f=${Status} ${Version} prometheus-node-exporter": "install ok installed 1.7.0-1ubuntu0.3",
	}, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("apt-get install -y /tmp/nexp.deb")) > 0 {
		t.Fatalf("deb install ran despite matching version: %v",
			sr.CallsMatching("apt-get"))
	}
	if len(sr.CallsMatching("systemctl enable prometheus-node-exporter.service")) == 0 {
		t.Fatal("node-exporter not enabled")
	}
}

// TestHubMetricsNexpSkipsNewerVersion — installed NEWER than the pin
// satisfies it (unattended-upgrades/security pocket): no download,
// no apt-get — apt would refuse the downgrade (same exit-100 loop
// class as the T12 haproxy deb fix, incident 2026-11-05).
func TestHubMetricsNexpSkipsNewerVersion(t *testing.T) {
	deb := []byte("fake-deb-payload")
	sum := sha256.Sum256(deb)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(deb)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "1.7.0-1ubuntu0.3"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%x"
`, srv.URL, sum))
	sr := newScripted(map[string]string{
		"dpkg-query -W -f=${Status} ${Version} prometheus-node-exporter": "install ok installed 1.7.0-1ubuntu0.4",
	}, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("apt-get install")) > 0 {
		t.Fatalf("newer node_exporter triggered deb install: %v",
			sr.CallsMatching("apt-get"))
	}
	if len(sr.CallsMatching("dpkg --compare-versions")) == 0 {
		t.Fatal("version compare not run")
	}
}

func TestHubMetricsNexpInstallsPinnedDeb(t *testing.T) {
	deb := []byte("fake-deb-payload")
	sum := sha256.Sum256(deb)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(deb)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "1.7.0-1ubuntu0.3"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%x"
`, srv.URL, sum))
	// dpkg-query empty (package absent) → download → sha256 verify →
	// apt-get install /tmp/<basename> (deb_file defaults to the URL
	// basename, ansible `| basename` parity).
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("apt-get install -y /tmp/nexp.deb")) == 0 {
		t.Fatalf("deb install not invoked: %v", sr.CallsMatching("apt"))
	}
	staged := filepath.Join(r.cfg.HostRoot, "/tmp/nexp.deb")
	got, err := os.ReadFile(staged)
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("staged deb missing/corrupt: %v", err)
	}
}

func TestHubMetricsNexpRejectsBadSHA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "9.9.9"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%s"
`, srv.URL, strings.Repeat("0", 64)))
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("apt-get install")) > 0 {
		t.Fatalf("install ran despite sha256 mismatch: %v", sr.CallsMatching("apt-get"))
	}
}

func TestHubMetricsNexpNoPinsNoOp(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("dpkg-query")) > 0 || len(sr.CallsMatching("apt-get")) > 0 {
		t.Fatalf("deb chain ran without pins: %v", sr.Calls())
	}
}

func TestHubMetricsFWSkipsContainer(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupHubMetricsFW()
	if len(sr.CallsMatching("HUBMETRICS")) > 0 {
		t.Fatal("HUBMETRICS touched on a non-standalone host")
	}
	if hostExists(r, "/etc/systemd/system/prometheus-node-exporter.service.d/textfile.conf") {
		t.Fatal("drop-in written on a non-standalone host")
	}
}

// TestHubMetricsScriptRefusesBadIP — a mesh node ip with shell
// metachars empties the whole HUBMETRICS rebuild (fail closed).
func TestHubMetricsScriptRefusesBadIP(t *testing.T) {
	vars := writeVarsDir(t, "")
	if err := os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte(`node-a:
  name: a
  ip: "10.0.1.10;touch /tmp/pwned"
  site: s1
  hub: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	if s := c.hubMetricsScript(); s != "" {
		t.Fatalf("script rendered with injected ip:\n%s", s)
	}
	if c.errs == 0 {
		t.Fatal("injected node ip not counted")
	}
}
