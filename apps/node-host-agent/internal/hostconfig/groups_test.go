package hostconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
# upstreams roi moi toi mesh (rescue qua tinc).
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
