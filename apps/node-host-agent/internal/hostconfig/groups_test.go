package hostconfig

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
)

// scriptedRunner answers canned output per command prefix and records
// every invocation.
type scriptedRunner struct {
	calls []string
	res   map[string]string // substring match -> stdout
	errs  map[string]bool   // substring match -> error
}

func (s *scriptedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, c)
	for k := range s.errs {
		if strings.Contains(c, k) {
			return "", fmt.Errorf("scripted failure for %q", c)
		}
	}
	best := ""
	bestLen := -1
	for k, v := range s.res {
		if strings.Contains(c, k) && len(k) > bestLen {
			best, bestLen = v, len(k)
		}
	}
	return best, nil
}

func (s *scriptedRunner) callsMatching(sub string) []string {
	var out []string
	for _, c := range s.calls {
		if strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

func writeVarsDir(t *testing.T, cluster string) string {
	t.Helper()
	if strings.TrimSpace(cluster) == "" {
		cluster = "{}\n"
	}
	d := t.TempDir()
	files := map[string]string{
		"interdc_nodes.yaml": `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`,
		"defaults.yaml": `interdc_nebula_enabled: true
interdc_marker_base: "172.29.0"
cp_endpoint: api.test.internal
cp_endpoint_fallback_names: [api2.test.internal]
fallback_dns: "1.1.1.1 9.9.9.9"
interdc_nebula_net: interdc
interdc_nebula_dev: neb1
interdc_nebula_port: 45670
interdc_nebula_table_pub: 100
interdc_nebula_table_marker: 101
interdc_nebula_version: "1.11.2"
interdc_stub_public_upstream: "1.1.1.1 8.8.8.8"
interdc_coredns_version: "1.14.7"
interdc_coredns_url: "https://example/coredns.tgz"
interdc_coredns_sha256: "deadbeef"
interdc_coredns_tgz: "coredns.tgz"
api_lb_enabled: true
api_lb_haproxy_version: "2.8.16-0ubuntu0.24.04.3"
api_lb_haproxy_deb_url: "https://example/haproxy.deb"
api_lb_haproxy_deb_file: "haproxy.deb"
api_lb_haproxy_deb_sha256: "deadbeef"
nodelocaldns_guard_allow_private: [10.0.0.0/8]
fail2ban_enabled: true
ssh_hardening_enabled: true
`,
		"cluster.yaml": cluster,
		"interdc_dns_zone.yaml": `zone: test.internal
ttl: 60
records:
  api:
    ip: "203.0.113.14"
  db:
    node: node-a
node_records: true
`,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func loadCyc(t *testing.T, r *Reconciler, varsDir, node string) *cyc {
	t.Helper()
	topo, err := topology.Load(topology.Config{VarsDir: varsDir, NodeName: node})
	if err != nil {
		t.Fatal(err)
	}
	return &cyc{r: r, ctx: context.Background(), t: topo}
}

func hostWrite(t *testing.T, r *Reconciler, path, content string) {
	t.Helper()
	dst := filepath.Join(r.cfg.HostRoot, path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hostRead(t *testing.T, r *Reconciler, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.cfg.HostRoot, path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func hostExists(r *Reconciler, path string) bool {
	_, err := os.Stat(filepath.Join(r.cfg.HostRoot, path))
	return err == nil
}

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
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{
		// probe for api_far fails -> name NOT in api_lb_probe_reachable
		"/dev/tcp/10.0.2.99/6443": true,
	}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	sr.errs = map[string]bool{}
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

func lbRunner() *scriptedRunner {
	return &scriptedRunner{
		res: map[string]string{
			"dpkg-query -W -f=${Status} ${Version} haproxy": "install ok installed 2.8.16-0ubuntu0.24.04.3",
			"/dev/tcp/10.0.2.99/6443":                       "",
		},
		errs: map[string]bool{},
	}
}

func newLBHost(t *testing.T, vars string, sr *scriptedRunner) *Reconciler {
	t.Helper()
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	if len(sr.callsMatching("systemctl disable --now haproxy.service")) == 0 {
		t.Fatal("distro haproxy.service not disabled")
	}
	if len(sr.callsMatching("nft -c -f /etc/api-local-dnat.nft")) == 0 {
		t.Fatal("nft ruleset not validated")
	}
}

func TestAPILBNoPinWhenProbeFails(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.errs["/dev/tcp/127.0.0.1/6443"] = true // LB never listens
	r := newLBHost(t, vars, sr)
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILB()

	hosts := hostRead(t, r, "/etc/hosts")
	if strings.Contains(hosts, "api.test.internal") {
		t.Fatalf("hosts pinned despite dead LB (ansible assert parity):\n%s", hosts)
	}
}

func TestUnpinRemovesBothMarkerStyles(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	hostWrite(t, r, "/etc/hosts",
		"127.0.0.1 localhost\n"+
			"# BEGIN api-local-lb managed block\n127.0.0.1 api.test.internal\n# END api-local-lb managed block\n"+
			"# BEGIN ANSIBLE MANAGED BLOCK - api-local-lb\n127.0.0.1 api.test.internal\n# END ANSIBLE MANAGED BLOCK - api-local-lb\n")
	c := loadCyc(t, r, vars, "node-b")
	c.unpinHosts()
	hosts := hostRead(t, r, "/etc/hosts")
	if strings.Contains(hosts, "api.test.internal") || strings.Contains(hosts, "MANAGED BLOCK") {
		t.Fatalf("stale pin survived:\n%s", hosts)
	}
}

// ---------- #3: groupPulls ----------

func TestGroupPullsUnitsAndKubeletCfg(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args="--node-ip=172.29.0.14 --node-labels=zone=x"`+"\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/var/lib/k0s/kubelet-config.yaml",
		"kind: KubeletConfiguration\nevictionHard:\n  memory.available: \"500Mi\"\n")

	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()

	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	// flags must live INSIDE --kubelet-extra-args with literal \x20
	if !strings.Contains(unit, `\x20--serialize-image-pulls=false`) ||
		!strings.Contains(unit, `\x20--registry-qps=2\x20--registry-burst=4`) {
		t.Fatalf("pull flags not inside extra-args:\n%s", unit)
	}
	ctl := hostRead(t, r, "/etc/systemd/system/k0scontroller.service")
	if !strings.Contains(ctl,
		`--kubelet-extra-args=--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4`) {
		t.Fatalf("extra-args injection missing on controller unit:\n%s", ctl)
	}
	kf := hostRead(t, r, "/var/lib/k0s/kubelet-config.yaml")
	for _, want := range []string{
		"maxParallelImagePulls: 4", "kubeAPIQPS: 100", "kubeAPIBurst: 50",
		"podPidsLimit: 4096",
		"evictionMinimumReclaim:\n  memory.available: \"200Mi\"\n  nodefs.available: \"1Gi\"\n  imagefs.available: \"2Gi\"",
	} {
		if !strings.Contains(kf, want) {
			t.Fatalf("kubelet cfg missing %q:\n%s", want, kf)
		}
	}
	t90 := hostRead(t, r, "/etc/k0s/containerd.d/90-parallel-pulls.toml")
	if !strings.Contains(t90, "[plugins.'io.containerd.cri.v1.images']") ||
		!strings.Contains(t90, "max_concurrent_downloads = 5") {
		t.Fatalf("bad parallel-pulls toml:\n%s", t90)
	}
	t91 := hostRead(t, r, "/etc/k0s/containerd.d/91-registry-mirror.toml")
	if !strings.Contains(t91, "discard_unpacked_layers = false") ||
		!strings.Contains(t91, "config_path = '/etc/containerd/certs.d'") {
		t.Fatalf("bad registry-mirror toml:\n%s", t91)
	}
	// ansible header contract: agent NEVER restarts k0s/containerd.
	for _, c2 := range sr.calls {
		if strings.Contains(c2, "restart") &&
			(strings.Contains(c2, "k0sworker") || strings.Contains(c2, "k0scontroller") || strings.Contains(c2, "containerd")) {
			t.Fatalf("unexpected restart call: %s", c2)
		}
	}
	if len(sr.callsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not invoked after unit change")
	}
}

// ---------- #4: fail2ban ignoreip derivation ----------

func TestFail2BanIgnoreIPDerived(t *testing.T) {
	vars := writeVarsDir(t, "fail2ban_ignoreip_extra: \"192.168.0.0/16\"\n")
	sr := &scriptedRunner{}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.fail2banIgnoreIP()
	want := "127.0.0.1/8 ::1 10.0.1.10 10.0.1.30 10.0.2.20 192.168.0.0/16"
	if got != want {
		t.Fatalf("ignoreip=%q want %q", got, want)
	}
}

// ---------- #5: groupNLD refuse path ----------

func TestNLDRefusePathSkipsWrite(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res: map[string]string{
			"systemctl show systemd-resolved.service": "active",
			"ss -lntu": "tcp  LISTEN 0  4096  127.0.0.53:53  0.0.0.0:*",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// no /run/systemd/resolve/resolv.conf in hostroot
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()

	if hostExists(r, "/etc/systemd/resolved.conf.d/99-nodelocal-stub.conf") {
		t.Fatal("stub-off drop-in written on the refuse path — DNS blackout risk")
	}
	if len(sr.callsMatching("systemctl restart systemd-resolved.service")) > 0 {
		t.Fatal("systemd-resolved restarted on the refuse path")
	}
	// the nft guard still converges (independent concern)
	if !hostExists(r, "/etc/nodelocaldns-guard.nft") {
		t.Fatal("nodelocaldns guard nft not deployed")
	}
	if len(sr.callsMatching("nft -c -f /etc/nodelocaldns-guard.nft")) == 0 {
		t.Fatal("guard ruleset not validated against the real file")
	}
}

// ---------- #6: worker stub Corefile vs ansible ----------

func TestCoreDNSWorkerStub(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res: map[string]string{
			"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
			"dig @127.0.0.1":                  "10.0.1.10",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()

	want := `# Managed by node-config-agent (T9) - local stub, domain-aware
# routing: test.internal -> mesh resolvers; "." -> public
# upstreams, then the mesh (rescue via tinc).
test.internal {
    bind 127.0.0.1
    forward . 172.29.0.10 {
        policy sequential
        health_check 10s
    }
    errors
}
. {
    bind 127.0.0.1
    forward . 1.1.1.1 8.8.8.8 172.29.0.10 {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`
	got := hostRead(t, r, "/etc/coredns/Corefile")
	if got != want {
		t.Fatalf("Corefile mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	rc := hostRead(t, r, "/etc/resolv.conf")
	if !strings.Contains(rc, "nameserver 127.0.0.1\nnameserver 1.1.1.1\nnameserver 172.29.0.10\noptions timeout:2 attempts:2") {
		t.Fatalf("resolv.conf not repointed per ansible:\n%s", rc)
	}
	unit := hostRead(t, r, "/etc/systemd/system/coredns.service")
	if !strings.Contains(unit, "After=network-online.target nebula@interdc.service") ||
		!strings.Contains(unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Fatalf("bad coredns unit:\n%s", unit)
	}
}

func TestCoreDNSSkipsResolvConfWhenDigFails(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res:  map[string]string{"/usr/local/bin/coredns -version": "CoreDNS-1.14.7"},
		errs: map[string]bool{"dig @127.0.0.1": true},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/resolv.conf", "nameserver 8.8.8.8\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupCoreDNS()
	if got := hostRead(t, r, "/etc/resolv.conf"); got != "nameserver 8.8.8.8\n" {
		t.Fatalf("resolv.conf repointed despite dig failure:\n%s", got)
	}
}

// ---------- #11: hub zone file + hosts pins ----------

func TestCoreDNSHubZoneFile(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res: map[string]string{
			"/usr/local/bin/coredns -version": "CoreDNS-1.14.7",
			"dig @127.0.0.1":                  "172.29.0.10",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-a")
	if !c.t.AmLighthouse {
		t.Fatal("node-a should be a hub")
	}
	c.groupCoreDNS()

	zf := hostRead(t, r, "/etc/coredns/db.test.internal")
	for _, want := range []string{
		"$TTL 60\n",
		"@   IN SOA ns1.test.internal. admin.test.internal. (\n",
		"    IN NS ns1.test.internal.\n",
		"api                            IN A 203.0.113.14",
		"db                             IN A 172.29.0.10", // node ref -> marker
		"a.node                         IN A 172.29.0.10",
		"b.node                         IN A 172.29.0.20",
		"c.node                         IN A 172.29.0.30",
	} {
		if !strings.Contains(zf, want) {
			t.Fatalf("zone file missing %q:\n%s", want, zf)
		}
	}
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "# BEGIN interdc-zone-pins managed block") ||
		!strings.Contains(hosts, "203.0.113.14 api.test.internal") ||
		!strings.Contains(hosts, "172.29.0.10 a.node.test.internal") {
		t.Fatalf("zone pins missing from /etc/hosts:\n%s", hosts)
	}
	rc := hostRead(t, r, "/etc/resolv.conf")
	if !strings.Contains(rc, "nameserver 127.0.0.1\nnameserver 1.1.1.1") {
		t.Fatalf("hub resolv.conf wrong:\n%s", rc)
	}
	// own marker is the only resolver -> excluded from "other" fallbacks
	if strings.Contains(rc, "nameserver 172.29.0.10") {
		t.Fatalf("hub should not fall back to its own marker:\n%s", rc)
	}
	corefile := hostRead(t, r, "/etc/coredns/Corefile")
	if !strings.Contains(corefile, "bind 172.29.0.10 127.0.0.1") ||
		!strings.Contains(corefile, "file /etc/coredns/db.test.internal") {
		t.Fatalf("bad hub Corefile:\n%s", corefile)
	}
}

// ---------- #20/#21: security files ----------

func TestSecurityFileContents(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{
		"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
		"sshd -T": "passwordauthentication no",
	}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()

	jail := hostRead(t, r, "/etc/fail2ban/jail.d/90-cluster-sshd.conf")
	if !strings.Contains(jail, "ignoreip = 127.0.0.1/8 ::1 10.0.1.10 10.0.1.30 10.0.2.20") {
		t.Fatalf("jail ignoreip not derived:\n%s", jail)
	}
	sshd := hostRead(t, r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
	for _, want := range []string{
		"KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
		"MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no",
		"ClientAliveInterval 300", "ClientAliveCountMax 2",
	} {
		if !strings.Contains(sshd, want) {
			t.Fatalf("sshd drop-in missing %q:\n%s", want, sshd)
		}
	}
}

// ---------- legacy watchdog prune ----------

func TestPruneLegacyWatchdogStack(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	// Seed every legacy artifact the prune must sweep.
	for _, u := range legacyWatchdogUnits {
		hostWrite(t, r, "/etc/systemd/system/"+u, "[Unit]\n")
	}
	for _, p := range legacyWatchdogDropins {
		hostWrite(t, r, p, "[Service]\nWatchdogSec=30s\n")
	}
	for _, s := range legacyWatchdogScripts {
		hostWrite(t, r, s, "#!/bin/sh\n")
	}
	hostWrite(t, r, "/usr/local/lib/node-watchdog/lib.sh", "# lib\n")
	hostWrite(t, r, "/usr/local/lib/node-watchdog/modules/50-fail2ban.sh", "#!/bin/sh\n")
	hostWrite(t, r, "/var/lib/node-exporter/textfile/node-watchdog.prom", "x 1\n")

	c := loadCyc(t, r, vars, "node-b")
	c.groupWatchdog()

	// units stopped+disabled
	for _, want := range []string{
		"systemctl disable --now node-watchdog.timer",
		"systemctl disable --now k0s-apiserver-wedge-probe.timer",
		"systemctl disable --now kine-db-probe.timer",
		"systemctl disable --now api-backend-guard.service",
		"systemctl disable --now nebula-route-guard.service",
	} {
		if len(sr.callsMatching(want)) == 0 {
			t.Fatalf("missing call %q", want)
		}
	}
	// every unit file / drop-in / script / lib dir gone
	for _, u := range legacyWatchdogUnits {
		if hostExists(r, "/etc/systemd/system/"+u) {
			t.Fatalf("unit file still present: %s", u)
		}
	}
	for _, p := range append(append([]string{}, legacyWatchdogDropins...), legacyWatchdogScripts...) {
		if hostExists(r, p) {
			t.Fatalf("file still present: %s", p)
		}
	}
	if hostExists(r, "/usr/local/lib/node-watchdog") {
		t.Fatal("/usr/local/lib/node-watchdog still present")
	}
	if hostExists(r, "/var/lib/node-exporter/textfile/node-watchdog.prom") {
		t.Fatal("stale .prom not removed on k8s worker")
	}
	// keep-list: conf rendered, state dir + log + marker live on
	conf := hostRead(t, r, "/etc/node-watchdog.conf")
	if !strings.Contains(conf, "OVERLAY_PROBE_TARGETS") {
		t.Fatalf("node-watchdog.conf must keep rendering:\n%s", conf)
	}
	if !hostExists(r, "/var/lib/node-watchdog/installed") {
		t.Fatal("state dir installed marker missing")
	}
	if len(sr.callsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("daemon-reload not run after unit removal")
	}
	// idempotent second cycle — no resurrected files, no errors
	sr.calls = nil
	c.groupWatchdog()
	for _, u := range legacyWatchdogUnits {
		if hostExists(r, "/etc/systemd/system/"+u) {
			t.Fatalf("unit file resurrected: %s", u)
		}
	}
}

// ---------- swap sizing ----------

// swapRunner wraps scriptedRunner and materializes the swapfile under
// HostRoot on fallocate/dd — the real nsenter runner creates it on
// the host where hostconfig then sees it through the HostRoot mount.
type swapRunner struct {
	*scriptedRunner
	hostRoot string
}

func (s *swapRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := s.scriptedRunner.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	if name == "fallocate" && len(args) >= 3 {
		mb, _ := strconv.ParseInt(strings.TrimSuffix(args[1], "M"), 10, 64)
		p := filepath.Join(s.hostRoot, args[2])
		if f, ferr := os.Create(p); ferr == nil {
			f.Truncate(mb * 1048576)
			f.Close()
		}
	}
	if name == "dd" {
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				os.WriteFile(filepath.Join(s.hostRoot, a[3:]), []byte{}, 0o644)
			}
		}
	}
	return out, err
}

func newSwapHost(t *testing.T, vars, node string, sr *scriptedRunner) *Reconciler {
	t.Helper()
	hr := t.TempDir()
	r, err := New(Config{Enabled: true, NodeName: node, HostRoot: hr,
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: &swapRunner{scriptedRunner: sr, hostRoot: hr}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSwapControllerDefault12G(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if len(sr.callsMatching("fallocate -l 12288M /swapfile-kine")) == 0 {
		t.Fatalf("12G fallocate missing: %v", sr.callsMatching("fallocate"))
	}
	if len(sr.callsMatching("mkswap /swapfile-kine")) == 0 ||
		len(sr.callsMatching("swapon /swapfile-kine")) == 0 {
		t.Fatal("mkswap/swapon not invoked")
	}
	fstab := hostRead(t, r, "/etc/fstab")
	if !strings.Contains(fstab, "\n/swapfile-kine none swap sw 0 0\n") {
		t.Fatalf("fstab entry missing:\n%s", fstab)
	}
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 60") {
		t.Fatalf("controller swappiness drop-in wrong (ansible: 60):\n%s", sys)
	}
	fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "/swapfile-kine"))
	if fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("swapfile mode wrong: %v", fi)
	}
}

func TestSwapKineDBHost2G(t *testing.T) {
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: db-vm-1
    ip: 10.9.9.9
    kine_db: true
  - name: other-vm
    ip: 10.9.9.10
`)
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "db-vm-1", sr)
	hostWrite(t, r, "/etc/fstab", "")
	c := loadCyc(t, r, vars, "db-vm-1")
	c.groupSwap()
	// ansible db include passed NO swap_path → the task default
	// /swapfile (NOT the controller's /swapfile-kine — that created
	// a second 2G file + orphaned fstab line on the real db-vm).
	if len(sr.callsMatching("fallocate -l 2048M /swapfile")) == 0 {
		t.Fatalf("2G fallocate missing: %v", sr.callsMatching("fallocate"))
	}
	if len(sr.callsMatching("swapfile-kine")) > 0 {
		t.Fatalf("db VM must not touch /swapfile-kine: %v", sr.callsMatching("swapfile-kine"))
	}
	fstab := hostRead(t, r, "/etc/fstab")
	if !strings.Contains(fstab, "/swapfile none swap sw 0 0") {
		t.Fatalf("db fstab entry missing:\n%s", fstab)
	}
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 10") {
		t.Fatalf("db swappiness drop-in wrong (ansible: 10):\n%s", sys)
	}

	// non-matching host name -> no swap at all
	sr2 := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r2 := newSwapHost(t, vars, "other-vm", sr2)
	c2 := loadCyc(t, r2, vars, "other-vm")
	c2.groupSwap()
	if len(sr2.callsMatching("fallocate")) > 0 || len(sr2.callsMatching("swapon ")) > 0 {
		t.Fatalf("swap touched on non-kine_db host: %v", sr2.calls)
	}
}

func TestSwapSwappinessVarOverride(t *testing.T) {
	vars := writeVarsDir(t, "swap_swappiness: \"30\"\n")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "")
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()
	sys := hostRead(t, r, "/etc/sysctl.d/99-kine-swap.conf")
	if !strings.Contains(sys, "vm.swappiness = 30") {
		t.Fatalf("swap_swappiness override not honoured:\n%s", sys)
	}
}

func TestSwapNoOpOnPlainWorker(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "node-b", sr)
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupSwap()
	for _, call := range sr.calls {
		if strings.Contains(call, "fallocate") || strings.Contains(call, "swapon") ||
			strings.Contains(call, "mkswap") {
			t.Fatalf("swap touched on plain worker: %s", call)
		}
	}
	if hostExists(r, "/etc/sysctl.d/99-kine-swap.conf") {
		t.Fatal("swappiness drop-in written on non-swap host")
	}
}

func TestSwapSkipsRecreateWhenRightSize(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	// pre-existing 12G sparse file => no recreate path
	sp := filepath.Join(r.cfg.HostRoot, "/swapfile-kine")
	f, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(12288 * 1048576); err != nil {
		t.Fatal(err)
	}
	f.Close()
	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()
	if len(sr.callsMatching("fallocate")) > 0 {
		t.Fatal("right-size swapfile must not be recreated")
	}
	if len(sr.callsMatching("swapon /swapfile-kine")) == 0 {
		t.Fatal("swapon still expected on inactive file")
	}
}

// ---------- hub-metrics-fw ----------

func TestHubMetricsFWRenders(t *testing.T) {
	vars := writeVarsDir(t, "hub_metrics_extra_ports: [2380, 2381]\n")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
	calls := sr.callsMatching("iptables -N HUBMETRICS")
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
	if len(sr.callsMatching("systemctl enable prometheus-node-exporter.service")) == 0 ||
		len(sr.callsMatching("systemctl start prometheus-node-exporter.service")) == 0 {
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
	sr := &scriptedRunner{res: map[string]string{
		"dpkg-query -W -f=${Status} ${Version} prometheus-node-exporter": "install ok installed 1.7.0-1ubuntu0.3",
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.callsMatching("apt-get install -y /tmp/nexp.deb")) > 0 {
		t.Fatalf("deb install ran despite matching version: %v",
			sr.callsMatching("apt-get"))
	}
	if len(sr.callsMatching("systemctl enable prometheus-node-exporter.service")) == 0 {
		t.Fatal("node-exporter not enabled")
	}
}

func TestHubMetricsNexpInstallsPinnedDeb(t *testing.T) {
	deb := []byte("fake-deb-payload")
	sum := sha256.Sum256(deb)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(deb)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "1.7.0-1ubuntu0.3"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%x"
`, srv.URL, sum))
	// dpkg-query empty (package absent) → download → sha256 verify →
	// apt-get install /tmp/<basename> (deb_file defaults to the URL
	// basename, ansible `| basename` parity).
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.callsMatching("apt-get install -y /tmp/nexp.deb")) == 0 {
		t.Fatalf("deb install not invoked: %v", sr.callsMatching("apt"))
	}
	staged := filepath.Join(r.cfg.HostRoot, "/tmp/nexp.deb")
	got, err := os.ReadFile(staged)
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("staged deb missing/corrupt: %v", err)
	}
}

func TestHubMetricsNexpRejectsBadSHA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered"))
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`interdc_nexp_version: "9.9.9"
interdc_nexp_deb_url: "%s/nexp.deb"
interdc_nexp_deb_sha256: "%s"
`, srv.URL, strings.Repeat("0", 64)))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.callsMatching("apt-get install")) > 0 {
		t.Fatalf("install ran despite sha256 mismatch: %v", sr.callsMatching("apt-get"))
	}
}

func TestHubMetricsNexpNoPinsNoOp(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupHubMetricsFW()
	if len(sr.callsMatching("dpkg-query")) > 0 || len(sr.callsMatching("apt-get")) > 0 {
		t.Fatalf("deb chain ran without pins: %v", sr.calls)
	}
}

func TestHubMetricsFWSkipsContainer(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupHubMetricsFW()
	if len(sr.callsMatching("HUBMETRICS")) > 0 {
		t.Fatal("HUBMETRICS touched on a non-standalone host")
	}
	if hostExists(r, "/etc/systemd/system/prometheus-node-exporter.service.d/textfile.conf") {
		t.Fatal("drop-in written on a non-standalone host")
	}
}

// ---------- api-lb-vm ----------

func TestAPILBVMConverge(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_guard_vms:
  - name: lb-vm-1
    ip: 203.0.113.27
    api_backends: "api_dc1=10.0.1.10:6443"
    mode: enforce
`)
	inspectJSON := `[{"Config":{"Image":"haproxy:2.8-alpine","Labels":{"com.docker.compose.project.config_files":"/opt/haproxy/docker-compose.yml"}},"Mounts":[{"Source":"/opt/haproxy/haproxy.cfg","Destination":"/usr/local/etc/haproxy/haproxy.cfg"}]}]`
	sr := &scriptedRunner{res: map[string]string{
		"docker inspect haproxy": inspectJSON,
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "lb-vm-1", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/opt/haproxy/haproxy.cfg", "global\n    maxconn 2000\n\ndefaults\n    mode tcp\n")
	hostWrite(t, r, "/opt/haproxy/docker-compose.yml",
		"services:\n  haproxy:\n    image: haproxy:2.8-alpine\n    volumes:\n"+
			"      - /opt/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro\n")
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	// pre-seed the admin socket so the wait_for exits immediately
	hostWrite(t, r, "/run/haproxy-admin/admin.sock", "")
	// legacy shell guard present
	hostWrite(t, r, "/etc/systemd/system/api-backend-guard.timer", "[Unit]\n")
	hostWrite(t, r, "/usr/local/sbin/api-backend-guard.sh", "#!/bin/sh\n")
	// credential dir pre-exists with drifted 0755 — converge must
	// tighten it back to 0700 (MkdirAll alone never re-chmods).
	gd := filepath.Join(r.cfg.HostRoot, "/etc/api-backend-guard")
	if err := os.MkdirAll(gd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gd, 0o755); err != nil {
		t.Fatal(err)
	}

	c := loadCyc(t, r, vars, "lb-vm-1")
	c.groupAPILBVM()

	tf := hostRead(t, r, "/etc/tmpfiles.d/api-lb-guard.conf")
	if !strings.Contains(tf, "d /run/haproxy-admin 0755 99 99 -") {
		t.Fatalf("bad tmpfiles conf:\n%s", tf)
	}
	jd := hostRead(t, r, "/etc/systemd/journald.conf.d/50-api-lb-guard.conf")
	if !strings.Contains(jd, "Storage=persistent") || !strings.Contains(jd, "SystemMaxUse=500M") {
		t.Fatalf("bad journald drop-in:\n%s", jd)
	}
	cfg := hostRead(t, r, "/opt/haproxy/haproxy.cfg")
	if !strings.Contains(cfg, "stats socket /run/haproxy/admin.sock mode 660 level admin") {
		t.Fatalf("stats socket block missing:\n%s", cfg)
	}
	cmp := hostRead(t, r, "/opt/haproxy/docker-compose.yml")
	if !strings.Contains(cmp, "- /run/haproxy-admin:/run/haproxy") {
		t.Fatalf("bind-mount line missing:\n%s", cmp)
	}
	if len(sr.callsMatching("haproxy -c -f /tmp/haproxy.cfg")) == 0 {
		t.Fatal("cfg not validated in throwaway container")
	}
	if len(sr.callsMatching("docker compose -f '/opt/haproxy/docker-compose.yml' up -d")) == 0 {
		t.Fatal("container not recreated for missing sock mount")
	}
	conf := hostRead(t, r, "/etc/api-backend-guard.conf")
	for _, want := range []string{
		"MODE=enforce", `API_BACKENDS="api_dc1=10.0.1.10:6443"`,
		"HAPROXY_BACKEND=kubeAPI_backend", `HAPROXY_BACKENDS="kubeAPI_backend"`,
		"HAPROXY_SOCKET=/run/haproxy-admin/admin.sock",
		// Original ansible contract (deployed VMs carry this
		// spelling) — plus the short-spelling compat keys.
		"API_TOKEN_FILE=/etc/api-backend-guard/token",
		"API_CA_FILE=/etc/api-backend-guard/ca.crt",
		"TOKEN_FILE=/etc/api-backend-guard/token",
		"CA_FILE=/etc/api-backend-guard/ca.crt",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("guard conf missing %q:\n%s", want, conf)
		}
	}
	if fi, err := os.Stat(gd); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("credential dir mode = %v want 0700 (drift re-tightened)", fi)
	}
	if len(sr.callsMatching("systemctl disable --now api-backend-guard.timer api-backend-guard.service")) == 0 {
		t.Fatal("legacy guard units not disabled")
	}
	if hostExists(r, "/etc/systemd/system/api-backend-guard.timer") ||
		hostExists(r, "/usr/local/sbin/api-backend-guard.sh") {
		t.Fatal("legacy guard files not removed")
	}
}

func TestAPILBVMSkipsUnlisted(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupAPILBVM()
	if hostExists(r, "/etc/api-backend-guard.conf") ||
		hostExists(r, "/etc/tmpfiles.d/api-lb-guard.conf") {
		t.Fatal("api-lb files written on a non api_lb_guard_vms node")
	}
}

// ---------- hub hairpin route prune ----------

func TestHairpinPruneOnlyOnLighthouse(t *testing.T) {
	vars := writeVarsDir(t, "")
	// node-a (hub, site s1): only cross-site target is node-b 10.0.2.20;
	// route get says it resolves via node-c's public IP => prune.
	sr := &scriptedRunner{res: map[string]string{
		"ip -o route get 10.0.2.20 mark 0x1000": "10.0.2.20 via 10.0.1.30 dev eth0 src 10.0.1.10 mark 0x1000",
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	if !c.t.AmLighthouse {
		t.Fatal("node-a should be a lighthouse")
	}
	c.nebulaRouting()
	if len(sr.callsMatching("ip -o route get 10.0.2.20 mark 0x1000")) == 0 {
		t.Fatal("route get not issued for target")
	}
	if len(sr.callsMatching("ip route del 10.0.2.20/32 table main")) == 0 {
		t.Fatalf("hairpin route not pruned: %v", sr.callsMatching("route del"))
	}

	// non-lighthouse node: no hairpin probing at all
	sr2 := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r2, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.nebulaRouting()
	if len(sr2.callsMatching("route get")) > 0 {
		t.Fatalf("hairpin probe ran on non-lighthouse: %v", sr2.callsMatching("route get"))
	}
}

// ---------- self-stage /usr/local/bin/node-host-agent ----------

func TestSelfStageBinaryCopiesAndIsIdempotent(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	srcb, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	srcSum := sha256.Sum256(srcb)
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	// stale/different host binary -> must be replaced by the running build
	hostWrite(t, r, "/usr/local/bin/node-host-agent", "stale-binary")

	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	dst := filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
	if sha256.Sum256(got) != srcSum {
		t.Fatal("staged binary sha256 != running binary")
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %v want 0755", fi)
	}
	// second cycle: hash matches -> writeManaged must not rewrite
	// (the staged content survives untouched).
	c.groupBase()
	got2, _ := os.ReadFile(dst)
	if string(got2) != string(got) {
		t.Fatal("staged binary rewritten despite matching sha256")
	}
}

func TestSelfStageSkippedOnStandalone(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	if hostExists(r, "/usr/local/bin/node-host-agent") {
		t.Fatal("binary staged on a standalone host — /host/usr/local not mounted there")
	}
}

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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
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
	sr.errs["/dev/tcp/10.0.2.99/6443"] = true
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

// ---------- Phase 3: kine.service ----------

func TestKineServiceOffByDefault(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
		w.Write(bin)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "%s/kine"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://postgres:pw@db.test.internal:6432/postgres?sslmode=disable"
`, srv.URL, sum))
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
		"MemorySwapMax=0",
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
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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
