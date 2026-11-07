// group_apilb_test.go — api-local-lb converge: haproxy cfg +
// api-local-dnat.nft candidate staging, /etc/hosts VIP pin,
// probe-filtered backends and extra lanes, deb version gating.
package hostconfig

import (
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// ---------- #1: vendored haproxy template renders for...if ----------

func TestHaproxyTemplateForIfRender(t *testing.T) {
	cluster := `api_lb_vip_ip: "203.0.113.14"
api_lb_backends:
  - name: api_datahub
    addr: "10.0.1.10:6443"
  - name: api_far
    addr: "10.0.2.99:6443"
    probe: true
    backup: true
`
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, map[string]bool{
		// probe for api_far fails -> name NOT in api_lb_probe_reachable
		"/dev/tcp/10.0.2.99/6443": true,
	})
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	cfg, err := r.render("api-local-lb.haproxy.cfg.j2", c.tplCtx())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, "server api_datahub 10.0.1.10:6443 check inter 5s fall 2 rise 2") {
		t.Fatalf("primary backend missing:\n%s", s)
	}
	if strings.Contains(s, "server api_far") {
		t.Fatalf("unreachable probe backend rendered:\n%s", s)
	}
	// and with the probe succeeding the backend shows up with ` backup`
	sr.ClearFails()
	cfg2, err := r.render("api-local-lb.haproxy.cfg.j2", c.tplCtx())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg2), "server api_far 10.0.2.99:6443 check inter 5s fall 2 rise 2 backup") {
		t.Fatalf("reachable probe backend missing backup flag:\n%s", cfg2)
	}
}

// ---------- #2 + #7 + #8 + #9: groupAPILB ----------

func lbVars(t *testing.T) string {
	return writeVarsDir(t, `api_lb_vip_ip: "203.0.113.14"
api_lb_haproxy_version: "2.8.16-0ubuntu0.24.04.3"
api_lb_backends:
  - name: api_datahub
    addr: "10.0.1.10:6443"
  - name: api_far
    addr: "10.0.2.99:6443"
    probe: true
    backup: true
`)
}

func lbRunner() *testutil.FakeRunner {
	return newScripted(map[string]string{
		"dpkg-query -W -f=${Status} ${Version} haproxy": "install ok installed 2.8.16-0ubuntu0.24.04.3",
		"/dev/tcp/10.0.2.99/6443":                       "",
	}, nil)
}

func newLBHost(t *testing.T, vars string, sr *testutil.FakeRunner) *Reconciler {
	t.Helper()
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		DownloadDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/var/lib/k0s/kubelet.conf",
		"clusters:\n- cluster:\n    server: https://api.test.internal:6443\n")
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	return r
}

func TestAPILBPinHostsHappyPath(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()

	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "# BEGIN api-local-lb managed block\n127.0.0.1 api.test.internal\n# END api-local-lb managed block") {
		t.Fatalf("hosts pin missing/ansible marker wrong:\n%s", hosts)
	}
	nft := hostRead(t, r, "/etc/api-local-dnat.nft")
	if !strings.Contains(nft, "table ip api_local_dnat") ||
		!strings.Contains(nft, `meta skuid "haproxy" accept`) ||
		!strings.Contains(nft, "ip daddr 203.0.113.14 tcp dport 6443 dnat to 127.0.0.1:6443") {
		t.Fatalf("bad dnat ruleset:\n%s", nft)
	}
	if hostExists(r, "/etc/nftables.d/api-lb-dnat.nft") ||
		hostExists(r, "/etc/systemd/system/api-lb-dnat.service") {
		t.Fatal("invented separate dnat unit/files must not exist")
	}
	if len(sr.CallsMatching("systemctl disable --now haproxy.service")) == 0 {
		t.Fatal("distro haproxy.service not disabled")
	}
	if len(sr.CallsMatching("nft -c -f /etc/api-local-dnat.nft")) == 0 {
		t.Fatal("nft ruleset not validated")
	}
}

func TestAPILBNoPinWhenProbeFails(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.FailOn("/dev/tcp/127.0.0.1/6443", nil) // LB never listens
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()

	hosts := hostRead(t, r, "/etc/hosts")
	if strings.Contains(hosts, "api.test.internal") {
		t.Fatalf("hosts pinned despite dead LB (ansible assert parity):\n%s", hosts)
	}
}

// ---------- Phase 1.3 + 2: api-local-dnat.nft + haproxy extra lanes ----------

func laneVars(t *testing.T) string {
	return writeVarsDir(t, `api_lb_vip_ip: "203.0.113.14"
api_lb_haproxy_version: "2.8.16-0ubuntu0.24.04.3"
api_lb_backends:
  - name: api_datahub
    addr: "10.0.1.10:6443"
  - name: api_far
    addr: "10.0.2.99:6443"
    probe: true
    backup: true
api_lb_extra_lanes:
  - { name: konnectivity, port: 8132 }
  - { name: k0sjoin, port: 9443 }
`)
}

func TestAPILBExtraLanesNftAndCfg(t *testing.T) {
	vars := laneVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()

	nft := hostRead(t, r, "/etc/api-local-dnat.nft")
	for _, want := range []string{
		"destroy table ip api_local_dnat",
		"type nat hook output priority dstnat; policy accept;",
		`meta skuid "haproxy" accept`,
		"meta skuid 65534 accept",
		"ip daddr 203.0.113.14 tcp dport 6443 dnat to 127.0.0.1:6443",
		"ip daddr 203.0.113.14 tcp dport 8132 dnat to 127.0.0.1:8132",
		"ip daddr 203.0.113.14 tcp dport 9443 dnat to 127.0.0.1:9443",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("dnat ruleset missing %q:\n%s", want, nft)
		}
	}
	cfg := hostRead(t, r, "/etc/haproxy/api-local-lb.cfg")
	for _, want := range []string{
		"frontend konnectivity_local",
		"bind 127.0.0.1:8132",
		"default_backend konnectivity_local_back",
		"backend konnectivity_local_back",
		"server api_datahub 10.0.1.10:8132 check inter 5s fall 2 rise 2",
		"server api_far 10.0.2.99:8132 check inter 5s fall 2 rise 2 backup",
		"frontend k0sjoin_local",
		"bind 127.0.0.1:9443",
		"backend k0sjoin_local_back",
		"server api_datahub 10.0.1.10:9443 check inter 5s fall 2 rise 2",
		"server api_far 10.0.2.99:9443 check inter 5s fall 2 rise 2 backup",
		// main lane still :6443
		"frontend api_local\n    bind 127.0.0.1:6443",
		"server api_datahub 10.0.1.10:6443 check inter 5s fall 2 rise 2",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("haproxy cfg missing %q:\n%s", want, cfg)
		}
	}
}

func TestAPILBExtraLanesProbeFiltered(t *testing.T) {
	vars := laneVars(t)
	sr := lbRunner()
	// api_far probe fails -> filtered out of EVERY lane backend too.
	sr.FailOn("/dev/tcp/10.0.2.99/6443", nil)
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	cfg, err := r.render("api-local-lb.haproxy.cfg.j2", c.tplCtx())
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	for _, bad := range []string{
		"server api_far 10.0.2.99:6443",
		"server api_far 10.0.2.99:8132",
		"server api_far 10.0.2.99:9443",
	} {
		if strings.Contains(s, bad) {
			t.Fatalf("unreachable probe backend rendered in a lane (%q):\n%s", bad, s)
		}
	}
	if !strings.Contains(s, "server api_datahub 10.0.1.10:8132") ||
		!strings.Contains(s, "server api_datahub 10.0.1.10:9443") {
		t.Fatalf("lane backends missing after probe filter:\n%s", s)
	}
}

// TestAPILBRestartsOnUnitDrift — a drifted unit file alone (cfg/nft
// unchanged) must restart api-local-lb; daemon-reload leaves haproxy
// on the OLD unit otherwise.
func TestAPILBRestartsOnUnitDrift(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()
	// Hand-edit the unit out-of-band; nothing else changed.
	hostWrite(t, r, "/etc/systemd/system/api-local-lb.service", "[Unit]\n# hand-edited\n")
	sr.ClearLog()
	c2 := loadCyc(t, r, vars, "node-b")
	c2.groupAPILB()
	if len(sr.CallsMatching("systemctl restart api-local-lb.service")) == 0 {
		t.Fatalf("unit drift did not restart api-local-lb: %v",
			sr.CallsMatching("api-local-lb"))
	}
}

// lbVarsDebStaged — lbVars plus an empty deb sha256 (any staged file
// passes sha256FileOK) so a regression reaches the apt-get call
// instead of dying in downloadFile on the dead "deadbeef" pin.
func lbVarsDebStaged(t *testing.T) string {
	return writeVarsDir(t, `api_lb_vip_ip: "203.0.113.14"
api_lb_haproxy_version: "2.8.16-0ubuntu0.24.04.3"
api_lb_haproxy_deb_sha256: ""
api_lb_backends:
  - name: api_datahub
    addr: "10.0.1.10:6443"
`)
}

func stageHaproxyDeb(t *testing.T, r *Reconciler) {
	t.Helper()
	hostWrite(t, r, "/var/lib/node-watchdog/haproxy.deb", "fake deb")
}

// TestAPILBNewerHaproxySkipsDeb — a host haproxy NEWER than the pin
// (unattended-upgrades/security pocket) satisfies it: dpkg
// --compare-versions ge passes, no deb download, no apt-get install
// (which would fail on the refused downgrade — incident
// 2026-11-05 lanit-cloud-worker-nonprod-05 exit-100 loop).
func TestAPILBNewerHaproxySkipsDeb(t *testing.T) {
	vars := lbVarsDebStaged(t)
	sr := lbRunner()
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.30-0ubuntu0.24.04.2")
	r := newLBHost(t, vars, sr)
	stageHaproxyDeb(t, r)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()
	if len(sr.CallsMatching("apt-get install -y /var/lib/node-watchdog/haproxy.deb")) > 0 {
		t.Fatalf("newer haproxy triggered deb install: %v",
			sr.CallsMatching("apt-get install"))
	}
	if len(sr.CallsMatching("dpkg --compare-versions")) == 0 {
		t.Fatal("version compare not run")
	}
	if c.errs != 0 {
		t.Fatalf("cycle errors on satisfied pin: %d", c.errs)
	}
}

// TestAPILBOlderHaproxyInstallsDeb — installed OLDER than the pin
// still converges: compare-versions ge fails, the staged deb goes to
// apt-get.
func TestAPILBOlderHaproxyInstallsDeb(t *testing.T) {
	vars := lbVarsDebStaged(t)
	sr := lbRunner()
	sr.On("dpkg-query -W -f=${Status} ${Version} haproxy", "install ok installed 2.8.10-1")
	sr.FailOn("dpkg --compare-versions", nil) // ge fails: 2.8.10 < pin
	r := newLBHost(t, vars, sr)
	stageHaproxyDeb(t, r)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()
	if len(sr.CallsMatching("apt-get install -y /var/lib/node-watchdog/haproxy.deb")) == 0 {
		t.Fatalf("older haproxy did not install pinned deb: %v",
			sr.CallsMatching("apt-get"))
	}
}

// TestProbeReachableRejectsBadAddr — a backend addr containing a
// quote is skipped before it can break out of the bash -c wrapper.
func TestProbeReachableRejectsBadAddr(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - {name: api_evil, addr: "10.0.0.1';id:6443", probe: true}
  - {name: api_ok, addr: "10.0.1.10:6443", probe: true}
`)
	sr := newScripted(map[string]string{
		"/dev/tcp/10.0.1.10/6443": "",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.probeReachable()
	if len(got) != 1 || got[0] != "api_ok" {
		t.Fatalf("probeReachable = %v", got)
	}
	if len(sr.CallsMatching("/dev/tcp/10.0.0.1")) > 0 {
		t.Fatalf("injected addr reached the shell: %v", sr.CallsMatching("/dev/tcp"))
	}
	if c.errs == 0 {
		t.Fatal("injected backend addr not counted")
	}
}

// ---------- groupAPILB candidate staging ----------

// TestAPILBStagesHaproxyCandidate — a cfg that fails haproxy -c must
// never sit at the live path the unit loads on next start.
func TestAPILBStagesHaproxyCandidate(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.FailOn("api-local-lb.cfg.candidate", nil)
	r := newLBHost(t, vars, sr)
	hostWrite(t, r, "/etc/haproxy/api-local-lb.cfg", "global\n# last good\n")
	c := loadCyc(t, r, vars, "node-b")
	before := c.errs
	c.groupAPILB()
	if c.errs == before {
		t.Fatal("haproxy -c failure not counted")
	}
	if got := hostRead(t, r, "/etc/haproxy/api-local-lb.cfg"); got != "global\n# last good\n" {
		t.Fatalf("deploy path clobbered by a rejected render:\n%s", got)
	}
	if hostExists(r, "/etc/haproxy/api-local-lb.cfg.candidate") {
		t.Fatal("rejected cfg candidate left behind")
	}
	if len(sr.CallsMatching("haproxy -c -f /etc/haproxy/api-local-lb.cfg.candidate")) == 0 {
		t.Fatalf("haproxy -c did not target the candidate: %v",
			sr.CallsMatching("haproxy"))
	}
}

// TestAPILBStagesNftCandidate — a ruleset that fails nft -c must
// never sit at the live path ExecStartPost loads.
func TestAPILBStagesNftCandidate(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.FailOn("api-local-dnat.nft.candidate", nil)
	r := newLBHost(t, vars, sr)
	hostWrite(t, r, "/etc/api-local-dnat.nft", "table ip good {}\n")
	c := loadCyc(t, r, vars, "node-b")
	before := c.errs
	c.groupAPILB()
	if c.errs == before {
		t.Fatal("nft -c failure not counted")
	}
	if got := hostRead(t, r, "/etc/api-local-dnat.nft"); got != "table ip good {}\n" {
		t.Fatalf("deploy path clobbered by a rejected ruleset:\n%s", got)
	}
	if hostExists(r, "/etc/api-local-dnat.nft.candidate") {
		t.Fatal("rejected nft candidate left behind")
	}
	// deploy aborted before the pin — /etc/hosts untouched.
	if hosts := hostRead(t, r, "/etc/hosts"); strings.Contains(hosts, "api.test.internal") {
		t.Fatalf("hosts pinned despite rejected ruleset:\n%s", hosts)
	}
}

// TestAPILBPromotesAndSweepsCandidates — valid renders promote via
// writeManaged and leave no staging files behind.
func TestAPILBPromotesAndSweepsCandidates(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()
	if hostExists(r, "/etc/haproxy/api-local-lb.cfg.candidate") ||
		hostExists(r, "/etc/api-local-dnat.nft.candidate") {
		t.Fatal("candidate lingered after promotion")
	}
	if len(sr.CallsMatching("haproxy -c -f /etc/haproxy/api-local-lb.cfg.candidate")) == 0 {
		t.Fatalf("haproxy -c did not target the candidate: %v",
			sr.CallsMatching("haproxy"))
	}
	if len(sr.CallsMatching("nft -c -f /etc/api-local-dnat.nft.candidate")) == 0 {
		t.Fatalf("nft -c did not target the candidate: %v",
			sr.CallsMatching("nft -c"))
	}
}

// ---------- probeReachable IPv6 ----------

// TestProbeReachableIPv6SplitHostPort — a bracketed IPv6 backend addr
// must parse host/port via net.SplitHostPort (first-colon Cut would
// mangle [::1]:6443).
func TestProbeReachableIPv6SplitHostPort(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - {name: api_v6, addr: "[::1]:6443", probe: true}
`)
	sr := newScripted(map[string]string{
		"/dev/tcp/::1/6443": "",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.probeReachable()
	if len(got) != 1 || got[0] != "api_v6" {
		t.Fatalf("probeReachable = %v — bracketed IPv6 must parse", got)
	}
	if len(sr.CallsMatching("/dev/tcp/::1/6443")) == 0 {
		t.Fatalf("v6 probe not issued: %v", sr.CallsMatching("/dev/tcp"))
	}
}
