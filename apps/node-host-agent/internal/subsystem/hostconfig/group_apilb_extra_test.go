// group_apilb_extra_test.go — T12 coverage beyond the pin/cfg
// suite: the rollback branch, kubelet.conf preflight, the haproxy deb
// version-gate arms (compare failure, install failure, fresh install),
// the haproxy -c validate abort, the nftables install failure, the
// 127.0.0.1:6443 probe abort, and the extra-lane/probe helpers' skip
// rules.
package hostconfig

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// apilbFixture — worker node + the LB VIP so the nft block runs.
func apilbFixture(t *testing.T, cluster string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// rawServer — an httptest server serving one raw body; returns its
// URL + hex sha256 for the *_url/_sha256 pins (the deb artifacts are
// plain files, not tarballs).
func rawServer(t *testing.T, body []byte) (url, sum string) {
	t.Helper()
	s := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/artifact", fmt.Sprintf("%x", s)
}

// TestAPILBRollbackUnpinsAndDisables — api_lb_enabled: false stops +
// disables the unit and unpins BOTH marker styles from /etc/hosts;
// cfg/unit files stay on disk for re-enable.
func TestAPILBRollbackUnpinsAndDisables(t *testing.T) {
	vars := writeVarsDir(t, "api_lb_enabled: false\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker\n")
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 prior\n"+
		"# BEGIN api-local-lb managed block\n127.0.0.1 api.test.internal\n# END api-local-lb managed block\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()
	if strings.Contains(hostRead(t, r, "/etc/hosts"), "api-local-lb managed block") {
		t.Fatal("managed block not unpinned on rollback")
	}
	if len(sr.CallsMatching("systemctl disable --now api-local-lb.service")) == 0 {
		t.Fatal("api-local-lb.service not disabled on rollback")
	}
}

// TestAPILBKubeletConfPreflightWarns — a kubelet.conf whose server
// host differs from cp_endpoint warns but still converges (the pin
// checks are the real signal).
func TestAPILBKubeletConfPreflightWarns(t *testing.T) {
	r, sr, c := apilbFixture(t, "")
	hostWrite(t, r, "/var/lib/k0s/kubelet.conf", "clusters:\n- cluster:\n    server: https://static-ip.example:6443\n")
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
	sr.On("timeout 15 bash -c", "ok")
	c.groupAPILB()
	if c.errs != 0 {
		t.Fatalf("preflight mismatch counted an error: %d", c.errs)
	}
	if !hostExists(r, "/etc/haproxy/api-local-lb.cfg") {
		t.Fatal("cfg not converged despite the preflight mismatch")
	}
}

// TestAPILBDebVersionGateArms — the dpkg version gate: a NEWER
// installed haproxy skips the deb flow entirely; a compare-versions
// FAILURE falls through to install (same as mismatch); a failing
// apt-get install counts but does not abort the config converge.
func TestAPILBDebVersionGateArms(t *testing.T) {
	t.Run("newer_installed_skips", func(t *testing.T) {
		_, sr, c := apilbFixture(t, "")
		sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
		sr.On("timeout 15 bash -c", "ok")
		c.groupAPILB()
		if len(sr.CallsMatching("apt-get install")) > 0 {
			t.Fatalf("deb flow ran for a newer installed haproxy: %v", sr.CallsMatching("apt-get"))
		}
	})
	t.Run("compare_failure_installs", func(t *testing.T) {
		deb := []byte("!<arch>\ndebian-binary\n")
		url, sum := rawServer(t, deb)
		_, sr, c := apilbFixture(t, "api_lb_haproxy_deb_url: \""+url+"\"\n"+
			"api_lb_haproxy_deb_sha256: \""+sum+"\"\n")
		sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.16-0ubuntu0.24.04.3")
		sr.FailOn("dpkg --compare-versions", nil)
		sr.On("timeout 15 bash -c", "ok")
		c.groupAPILB()
		if len(sr.CallsMatching("apt-get install -y /var/lib/node-watchdog/haproxy.deb")) == 0 {
			t.Fatal("compare-versions failure did not fall through to the deb install")
		}
		if c.errs != 0 {
			t.Fatalf("errs = %d — compare failure must not count (malformed probe falls back)", c.errs)
		}
	})
}

// TestAPILBHaproxyValidateAborts — `haproxy -c` failing on the
// candidate must abort the group: no unit, no hosts pin, error
// counted.
func TestAPILBHaproxyValidateAborts(t *testing.T) {
	r, sr, c := apilbFixture(t, `api_lb_vip_ip: "203.0.113.14"
`)
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
	sr.FailOn("haproxy -c", nil)
	c.groupAPILB()
	if hostExists(r, "/etc/haproxy/api-local-lb.cfg") {
		t.Fatal("invalid cfg promoted to the live path")
	}
	if hostExists(r, "/etc/hosts") && strings.Contains(hostRead(t, r, "/etc/hosts"), "api-local-lb managed block") {
		t.Fatal("hosts pinned although the LB never validated")
	}
	if c.errs == 0 {
		t.Fatal("failed haproxy validation did not count a cycle error")
	}
}

// TestAPILBNftablesInstallFailure — the nftables apt-get failing
// counts but the DNAT ruleset still deploys (nft -c gate independent).
func TestAPILBNftablesInstallFailure(t *testing.T) {
	r, sr, c := apilbFixture(t, `api_lb_vip_ip: "203.0.113.14"
api_lb_extra_lanes:
  - name: konnectivity
    port: "8132"
`)
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
	sr.FailOn("apt-get install -y nftables", nil)
	sr.On("timeout 15 bash -c", "ok")
	c.groupAPILB()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want exactly the nftables install failure", c.errs)
	}
	nft := hostRead(t, r, "/etc/api-local-dnat.nft")
	for _, want := range []string{
		"ip daddr 203.0.113.14 tcp dport 6443 dnat to 127.0.0.1:6443",
		"ip daddr 203.0.113.14 tcp dport 8132 dnat to 127.0.0.1:8132",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("dnat ruleset missing %q:\n%s", want, nft)
		}
	}
}

// TestAPILBProbeAbortKeepsHostsUnpinned — the LB not answering on
// 127.0.0.1:6443 aborts BEFORE the /etc/hosts pin (pinning against a
// dead LB kills the node's API path).
func TestAPILBProbeAbortKeepsHostsUnpinned(t *testing.T) {
	r, sr, c := apilbFixture(t, "")
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
	sr.FailOn("/dev/tcp/127.0.0.1/6443", nil)
	c.groupAPILB()
	if c.errs == 0 {
		t.Fatal("dead-LB probe did not count a cycle error")
	}
	if hostExists(r, "/etc/hosts") &&
		strings.Contains(hostRead(t, r, "/etc/hosts"), "api-local-lb managed block") {
		t.Fatal("hosts pinned against a dead LB")
	}
}

// TestAPILBExtraLanesSkipAndDedupe — lanes missing name/port and
// non-mapping entries are skipped; a duplicate of :6443 dedupes.
func TestAPILBExtraLanesSkipAndDedupe(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_extra_lanes:
  - name: konnectivity
    port: "8132"
  - name: dupmain
    port: "6443"
  - name: noport
  - port: "9999"
  - just-a-string
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.apiLBDnatPorts()
	if len(got) != 2 || got[0] != "6443" || got[1] != "8132" {
		t.Fatalf("apiLBDnatPorts = %v, want [6443 8132]", got)
	}
}

// TestAPILBProbeReachableSkips — probe backends with missing
// addr/name, unsafe host chars, and bare (portless) addresses are
// handled: refused hosts count, a bare host probes on :6443.
func TestAPILBProbeReachableSkips(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - name: no_addr
  - addr: "10.0.1.10:6443"
  - name: bad_host
    addr: "in jected:1"
    probe: true
  - name: bare
    addr: "10.0.9.9"
    probe: true
`)
	sr := newScripted(map[string]string{
		"timeout 5 bash -c 'cat < /dev/null > /dev/tcp/10.0.9.9/6443'": "ok",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.probeReachable()
	if len(got) != 1 || got[0] != "bare" {
		t.Fatalf("probeReachable = %v, want [bare]", got)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the refused host counted", c.errs)
	}
	if len(sr.CallsMatching("/dev/tcp/10.0.9.9/6443")) == 0 {
		t.Fatal("bare host not probed on the default :6443")
	}
}

// TestAPILBDebDownloadFailureAborts — the haproxy deb download
// failing aborts the whole group (no config converge against a
// missing binary) with the site's counted line.
func TestAPILBDebDownloadFailureAborts(t *testing.T) {
	_, sr, c := apilbFixture(t, `api_lb_haproxy_deb_url: "http://127.0.0.1:1/haproxy.deb"
api_lb_haproxy_deb_sha256: "0000"
api_lb_vip_ip: "203.0.113.14"
`)
	sr.On("timeout 15 bash -c", "ok")
	c.groupAPILB()
	if c.errs == 0 {
		t.Fatal("failed haproxy deb download did not count a cycle error")
	}
	if hostExists(c.r, "/etc/haproxy/api-local-lb.cfg") {
		t.Fatal("haproxy cfg converged although the deb never landed")
	}
}

// TestAPILBDebInstallFailureSkipsSetup — apt-get failing on the
// staged deb counts and skips the LB setup entirely (return), instead
// of configuring an haproxy that never got installed.
func TestAPILBDebInstallFailureSkipsSetup(t *testing.T) {
	deb := []byte("!<arch>\ndebian-binary\n")
	url, sum := rawServer(t, deb)
	_, sr, c := apilbFixture(t, "api_lb_haproxy_deb_url: \""+url+"\"\n"+
		"api_lb_haproxy_deb_sha256: \""+sum+"\"\n")
	sr.On("timeout 15 bash -c", "ok")
	sr.FailOn("apt-get install -y /var/lib/node-watchdog/haproxy.deb", nil)
	c.groupAPILB()
	if c.errs == 0 {
		t.Fatal("failed haproxy deb install did not count a cycle error")
	}
	if hostExists(c.r, "/etc/haproxy/api-local-lb.cfg") {
		t.Fatal("haproxy setup ran although the deb install failed")
	}
}

// TestAPILBMalformedDpkgFieldsInstalls — a dpkg-query reply with fewer
// than four fields cannot carry a version: the gate falls through to
// the install flow rather than trusting the unparseable probe.
func TestAPILBMalformedDpkgFieldsInstalls(t *testing.T) {
	deb := []byte("!<arch>\ndebian-binary\n")
	url, sum := rawServer(t, deb)
	_, sr, c := apilbFixture(t, "api_lb_haproxy_deb_url: \""+url+"\"\n"+
		"api_lb_haproxy_deb_sha256: \""+sum+"\"\n")
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed")
	sr.On("timeout 15 bash -c", "ok")
	c.groupAPILB()
	if len(sr.CallsMatching("apt-get install -y /var/lib/node-watchdog/haproxy.deb")) == 0 {
		t.Fatal("malformed dpkg probe did not fall through to the install")
	}
	if c.errs != 0 {
		t.Fatalf("errs = %d — the malformed probe is a fallback, not a failure", c.errs)
	}
}

// TestAPILBProbeReachableShapeSkips — probe backends that are not
// mappings, or that carry probe:true without addr/name, are skipped.
func TestAPILBProbeReachableShapeSkips(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - just-a-string
  - name: probed_but_addrless
    probe: true
  - addr: "10.0.1.10:6443"
    probe: true
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	if got := c.probeReachable(); len(got) != 0 {
		t.Fatalf("probeReachable = %v, want none", got)
	}
	if c.errs != 0 {
		t.Fatalf("shape skips counted errors: %d", c.errs)
	}
}
