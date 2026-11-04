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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
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
	c := &cyc{r: r, ctx: context.Background(), t: topo}
	// Same attribution CycleWithErrors sets up: managed-op helper
	// failures count against this cycle.
	r.cur = c
	return c
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

func TestSwapSwaponProbeFailureSkipsCycle(t *testing.T) {
	vars := writeVarsDir(t, "")
	// Probe failure must fail CLOSED: the wrong-size file may be an
	// ACTIVE swapfile — removing it pulls the kernel's swap target
	// out from under it. The whole cycle must be skipped on a
	// failed probe, not just the remove branch.
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{
		"swapon --show=NAME": true,
	}}
	r := newSwapHost(t, vars, "node-a", sr)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	// wrong-size file on disk (2G where 12G is wanted) — the exact
	// shape that would hit the os.Remove path on a bogus "inactive".
	sp := filepath.Join(r.cfg.HostRoot, "/swapfile-kine")
	f, err := os.Create(sp)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(2048 * 1048576); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := loadCyc(t, r, vars, "node-a")
	c.groupSwap()

	if !hostExists(r, "/swapfile-kine") {
		t.Fatal("wrong-size swapfile removed despite failed active-state probe")
	}
	// the ONLY host command issued is the probe itself — nothing
	// (create/chmod/mkswap/fstab/swapon/sysctl) may proceed.
	if len(sr.calls) != 1 || !strings.Contains(sr.calls[0], "swapon --show") {
		t.Fatalf("swap converge proceeded past the failed probe: %v", sr.calls)
	}
	if hostExists(r, "/etc/sysctl.d/99-kine-swap.conf") {
		t.Fatal("swappiness drop-in written despite skipped cycle")
	}
	if strings.Contains(hostRead(t, r, "/etc/fstab"), "swapfile-kine") {
		t.Fatal("fstab entry added despite skipped cycle")
	}
}

func TestSwapActiveMatchExactLine(t *testing.T) {
	// swapon --show=NAME emits one swap name per line — active-state
	// must be an exact line match. A substring probe marks /swapfile
	// active just because /swapfile-kine is listed, yet the two are
	// independent swap targets.
	vars := writeVarsDir(t, `node_exporter_extra_hosts:
  - name: db-vm-1
    ip: 10.9.9.9
    kine_db: true
`)
	seed := func(r *Reconciler, path string, mb int64) {
		t.Helper()
		f, err := os.Create(filepath.Join(r.cfg.HostRoot, path))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(mb * 1048576); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	// /swapfile probed while only /swapfile-kine is active: NOT active
	// — the wrong-size file is recreated and swapon is issued.
	sr := &scriptedRunner{res: map[string]string{
		"swapon --show=NAME": "/swapfile-kine\n",
	}, errs: map[string]bool{}}
	r := newSwapHost(t, vars, "db-vm-1", sr)
	hostWrite(t, r, "/etc/fstab", "")
	seed(r, "/swapfile", 1024) // wrong size vs db default 2048
	c := loadCyc(t, r, vars, "db-vm-1")
	c.groupSwap()
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/swapfile"))
	if err != nil || fi.Size() != 2048*1048576 {
		t.Fatalf("/swapfile must be recreated at 2G — substring match marked it active: fi=%v err=%v", fi, err)
	}
	if len(sr.callsMatching("swapon /swapfile")) == 0 {
		t.Fatalf("swapon /swapfile expected on inactive file: %v", sr.calls)
	}

	// /swapfile-kine listed exactly: ACTIVE — never removed, never
	// re-swapon'd (controller wants 12G; the live 2G file stays).
	sr2 := &scriptedRunner{res: map[string]string{
		"swapon --show=NAME": "/swapfile\n/swapfile-kine\n",
	}, errs: map[string]bool{}}
	r2 := newSwapHost(t, vars, "node-a", sr2)
	hostWrite(t, r2, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s\n")
	hostWrite(t, r2, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
	seed(r2, "/swapfile-kine", 2048) // wrong size vs controller 12288
	c2 := loadCyc(t, r2, vars, "node-a")
	c2.groupSwap()
	fi, err = os.Stat(filepath.Join(r2.cfg.HostRoot, "/swapfile-kine"))
	if err != nil || fi.Size() != 2048*1048576 {
		t.Fatal("active /swapfile-kine was removed/resized")
	}
	if len(sr2.callsMatching("swapon /swapfile-kine")) > 0 {
		t.Fatal("swapon issued for already-active /swapfile-kine")
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

// ---------- nebula restart-vs-reload decision ----------

func TestNebulaNeedsRestartDecision(t *testing.T) {
	c := &cyc{}
	base := `pki:
  ca: /etc/nebula/interdc/ca.crt
  cert: /etc/nebula/interdc/host.crt
  key: /etc/nebula/interdc/host.key
static_host_map:
  "172.29.0.10": ["10.0.1.10:4242"]
lighthouse:
  am_lighthouse: false
  hosts: ["172.29.0.10"]
tun:
  dev: neb1
  mtu: 1300
  unsafe_routes:
    - route: 10.99.0.0/24
      via: 172.29.0.10
listen:
  host: 0.0.0.0
  port: 45670
firewall:
  outbound:
    - port: any
      proto: any
      host: any
`
	rep := func(old, new string) string {
		return strings.Replace(base, old, new, 1)
	}
	for _, tc := range []struct {
		name string
		old  string
		new  string
		want bool
	}{
		{"identical", base, base, false},
		// SIGHUP-reloadable surfaces — reload only.
		{"firewall rule change", base,
			rep("- port: any\n      proto: any\n      host: any", "- port: 443\n      proto: tcp\n      host: any"), false},
		{"lighthouse.hosts change", base,
			rep(`hosts: ["172.29.0.10"]`, `hosts: ["172.29.0.10", "172.29.0.20"]`), false},
		{"tun.unsafe_routes change", base,
			rep("route: 10.99.0.0/24", "route: 10.98.0.0/24"), false},
		{"top-level key reorder",
			`firewall:
  outbound:
    - port: any
      proto: any
      host: any
` + base[:strings.Index(base, "firewall:")], base, false},
		// Non-reloadable surfaces — full restart.
		{"tun.mtu change", base, rep("mtu: 1300", "mtu: 1400"), true},
		{"tun.dev change", base, rep("dev: neb1", "dev: neb2"), true},
		{"listen.port change", base, rep("port: 45670", "port: 45671"), true},
		{"static_host_map change", base, rep("10.0.1.10:4242", "10.0.1.11:4242"), true},
		{"pki path change", base, rep("interdc/host.key", "interdc/host2.key"), true},
		{"am_lighthouse flip", base, rep("am_lighthouse: false", "am_lighthouse: true"), true},
		{"unparseable new config", base, "{", true},
		{"unparseable old config", "{", base, true},
		{"empty old config (first install)", "", base, true},
	} {
		if got := c.nebulaNeedsRestart([]byte(tc.old), []byte(tc.new)); got != tc.want {
			t.Errorf("%s: needsRestart=%v want %v", tc.name, got, tc.want)
		}
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

// ---------- CycleWithErrors / per-group error accounting (2.6) ----------

// cleanCycleFixture returns a Reconciler + runner whose groups all
// self-gate or succeed under a tempdir HostRoot, so CycleWithErrors
// reports 0 and lastOK is stamped.
func cleanCycleFixture(t *testing.T) (*Reconciler, *scriptedRunner) {
	t.Helper()
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\n")
	sr := &scriptedRunner{
		res: map[string]string{
			"/usr/local/bin/coredns -version":               "CoreDNS-1.14.7",
			"dig @127.0.0.1":                                "10.0.1.10",
			"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
			"sshd -T": "passwordauthentication no",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		DownloadDir: t.TempDir(), Runner: sr,
		NowFn: func() time.Time { return time.Unix(1_700_000_000, 0) }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr
}

func TestCycleWithErrorsCleanCycleStampsLastOK(t *testing.T) {
	r, _ := cleanCycleFixture(t)
	if got := r.CycleWithErrors(context.Background()); got != 0 {
		t.Fatalf("clean cycle returned %d errors", got)
	}
	if got := testutil.ToFloat64(r.lastOK); got != 1_700_000_000 {
		t.Fatalf("lastOK = %v, want NowFn unix", got)
	}
}

func TestCycleWithErrorsTopologyLoadFailure(t *testing.T) {
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: t.TempDir(), // missing interdc_nodes.yaml/cluster.yaml
		Runner:  sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.CycleWithErrors(context.Background()); got == 0 {
		t.Fatal("topology load failure must count as an error")
	}
}

func TestCycleWithErrorsCountsGroupErrors(t *testing.T) {
	r, sr := cleanCycleFixture(t)
	// daemon-reload runs when the nodelocaldns nft+unit change —
	// failing it is a command error attributed to that group only.
	sr.errs["systemctl daemon-reload"] = true
	got := r.CycleWithErrors(context.Background())
	// EXACT count — one noteErr per daemonReload invocation:
	// nodelocaldns nft apply + host-internal-ports nft apply
	// (W6.1, same groupNLD) + nodeip_cpu nebula drop-in. (coredns
	// self-gates here: nebula disabled → derive() leaves no
	// DNSResolvers.) A regression that counts a fault twice (or
	// skips one) moves this number.
	if got != 3 {
		t.Fatalf("cycle returned %d errors, want exactly 3 "+
			"(daemon-reload x nodelocaldns/host-ports-guard/nodeip_cpu)", got)
	}
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("nodelocaldns", "error")); got != 1 {
		t.Fatalf("cycles{nodelocaldns,error} = %v want 1", got)
	}
	// Errors attribute per group: a clean group still reads "ok".
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("base", "ok")); got != 1 {
		t.Fatalf("cycles{base,ok} = %v want 1 (error mis-attributed)", got)
	}
	if got := testutil.ToFloat64(r.lastOK); got != 0 {
		t.Fatalf("lastOK stamped on a failed cycle: %v", got)
	}
}

func TestGroupRecordsOkErrorPanic(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	c.group("g-ok", func() {})
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("g-ok", "ok")); got != 1 {
		t.Fatalf("cycles{g-ok,ok} = %v want 1", got)
	}
	if c.errs != 0 {
		t.Fatalf("errs = %d after clean group", c.errs)
	}

	c.group("g-err", func() { c.err("boom") })
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("g-err", "error")); got != 1 {
		t.Fatalf("cycles{g-err,error} = %v want 1", got)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d after failing group", c.errs)
	}

	c.group("g-panic", func() { panic("test panic") })
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("g-panic", "panic")); got != 1 {
		t.Fatalf("cycles{g-panic,panic} = %v want 1", got)
	}
	if c.errs != 2 {
		t.Fatalf("errs = %d after panicking group", c.errs)
	}
	// later groups still run after a panic.
	c.group("g-after", func() {})
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("g-after", "ok")); got != 1 {
		t.Fatalf("cycles{g-after,ok} = %v want 1", got)
	}
}

func TestGroupWriteFailureCountedViaHelper(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	hr := t.TempDir()
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: hr,
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// /etc is a regular FILE — writeManaged's MkdirAll must fail.
	if err := os.WriteFile(filepath.Join(hr, "etc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.group("g-write", func() {
		if _, werr := r.writeManaged("/etc/x.conf", []byte("y"), 0o644); werr == nil {
			t.Error("writeManaged unexpectedly succeeded")
		}
	})
	if got := testutil.ToFloat64(r.cycles.WithLabelValues("g-write", "error")); got != 1 {
		t.Fatalf("cycles{g-write,error} = %v want 1", got)
	}
}

// ---------- journald integrity (A5, groupBase) ----------

func journaldEnv(t *testing.T, res map[string]string, errs map[string]bool) (*cyc, *Reconciler, *scriptedRunner) {
	t.Helper()
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: res, errs: errs}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	return loadCyc(t, r, vars, "node-b"), r, sr
}

func TestJournaldCorruptOutputRotates(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	// groupBase runs the probe; corrupted output must trigger the
	// rotate+vacuum remediation.
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("corrupt journal not remediated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldAbnormallyEmptyRotates(t *testing.T) {
	// journalctl answers but returns nothing while journal files are
	// on disk — post-hard-reboot truncated/misindexed journal.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot,
		"/var/log/journal/machine-x/system.journal"), []byte("journal"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("abnormally empty journal not remediated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldHealthyNoRotate(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "Oct 01 10:00:00 node-b systemd[1]: Started node-host-agent.service",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatalf("healthy journal rotated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldMissingBinaryNoRotate(t *testing.T) {
	// journalctl absent → probe errors with empty output; that is not
	// corruption evidence (rotating would fail anyway) — no action.
	c, _, sr := journaldEnv(t, map[string]string{}, map[string]bool{"journalctl": true})
	c.groupBase()
	if len(sr.callsMatching("--rotate")) > 0 {
		t.Fatalf("rotate attempted without journalctl: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldRotateRateLimited(t *testing.T) {
	// A persistently-corrupt probe must not re-run rotate+vacuum every
	// cycle — the last-journald-rotate latch caps it to once per
	// cooldown window (a false positive would otherwise pin errs and
	// hammer the journal on every converge).
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	c.groupBase()
	c.groupBase()
	if got := len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")); got != 1 {
		t.Fatalf("rotate ran %d times, want 1 (cooldown latch)", got)
	}
}

// ---------- journald persistence (standalone) + silent restart ----------

// standaloneJournaldEnv is journaldEnv for the standalone (HostRoot
// "/" — on-host systemd) path journaldPersistence gates on.
func standaloneJournaldEnv(t *testing.T, res map[string]string, errs map[string]bool) (*cyc, *Reconciler, *scriptedRunner) {
	t.Helper()
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: res, errs: errs}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	return loadCyc(t, r, vars, "node-a"), r, sr
}

func TestJournaldPersistenceStandaloneConverge(t *testing.T) {
	c, r, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()

	jd := hostRead(t, r, "/etc/systemd/journald.conf.d/50-node-config-agent.conf")
	if !strings.Contains(jd, "[Journal]") || !strings.Contains(jd, "Storage=persistent") {
		t.Fatalf("bad journald drop-in:\n%s", jd)
	}
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/var/log/journal/abcdef1234567890"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("journal dir missing/wrong mode (want 02755): fi=%v err=%v", fi.Mode(), err)
	}
	if len(sr.callsMatching("chgrp systemd-journal /var/log/journal/abcdef1234567890")) == 0 {
		t.Fatalf("journal dir not chgrp'd: %v", sr.callsMatching("chgrp"))
	}
	// First converge: drop-in write + fresh dir → exactly one restart.
	if got := len(sr.callsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1: %v", got, sr.callsMatching("systemctl"))
	}
}

func TestJournaldPersistenceSkipsContainer(t *testing.T) {
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()
	if hostExists(r, "/etc/systemd/journald.conf.d/50-node-config-agent.conf") {
		t.Fatal("standalone drop-in written on a DaemonSet host")
	}
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) > 0 {
		t.Fatal("journald restarted on a DaemonSet host by the persistence converge")
	}
}

func TestJournaldPersistenceIdempotent(t *testing.T) {
	c, _, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()
	c.groupBase()
	// Second converge: drop-in unchanged, dir exists → no more
	// restarts (journald restart is a bounded side-effect, not a
	// per-cycle action).
	if got := len(sr.callsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts across 2 cycles = %d, want 1", got)
	}
}

func TestJournaldSilentNoFilesRestarts(t *testing.T) {
	// Incident shape: journalctl answers "No journal files were
	// found." while a journal storage root exists — journald is
	// writing nowhere and must be restarted (rotate cannot create
	// files).
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("silent journald not restarted: %v", sr.callsMatching("systemctl"))
	}
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran for a file-less journal — rotate cannot create files")
	}
}

func TestJournaldSilentEmptyNoFilesRestarts(t *testing.T) {
	// Same verdict without the notice text (suppressed/locale): a
	// literally empty read + a storage root + zero *.journal files.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("empty journal with storage root not restarted: %v", sr.callsMatching("systemctl"))
	}
}

func TestJournaldSilentNoStorageNoRestart(t *testing.T) {
	// No journal storage at all → journald legitimately absent —
	// silence is configuration, not a fault: no restart, no rotate.
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) > 0 {
		t.Fatal("journald restarted with no storage configured")
	}
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran with no storage configured")
	}
}

func TestJournaldSilentRestartRateLimited(t *testing.T) {
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	c.groupBase()
	if got := len(sr.callsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1 (last-journald-restart cooldown)", got)
	}
}

func TestJournaldPersistenceRestartNotDoubled(t *testing.T) {
	// Standalone + silent probe: the persistence converge's own
	// restart must satisfy the integrity probe — one bounce per
	// cycle, never two (journaldRestarted dedupe).
	c, r, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if got := len(sr.callsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1 (converge restart covers the probe)", got)
	}
}

// ---------- audit regression tests ----------

// TestHostnamePinNoGlueOnMissingNewline — a hosts file without a
// trailing newline must not fuse the 127.0.1.1 pin onto the last
// existing line.
func TestHostnamePinNoGlueOnMissingNewline(t *testing.T) {
	c, r, _ := journaldEnv(t, map[string]string{
		"journalctl -n 5": "ok",
	}, map[string]bool{})
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost") // NO trailing \n
	c.groupBase()
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.0.1 localhost\n127.0.1.1 node-b\n") {
		t.Fatalf("hostname pin glued onto the last line:\n%q", hosts)
	}
}

// TestResolvConfAtomicRepoint — the T4 repoint creates the symlink
// at a temp name and renames over; no gap window and no leftover tmp.
func TestResolvConfAtomicRepoint(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{
		"systemctl show systemd-resolved.service": "active",
		"ss -lntu": "tcp  LISTEN 0  4096  127.0.0.53:53  0.0.0.0:*",
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/run/systemd/resolve/resolv.conf", "nameserver 10.0.0.2\n")
	hostWrite(t, r, "/etc/resolv.conf", "nameserver 8.8.8.8\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()
	dst := filepath.Join(r.cfg.HostRoot, "etc/resolv.conf")
	fi, err := os.Lstat(dst)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("resolv.conf not a symlink after repoint: %v %v", fi, err)
	}
	if l, _ := os.Readlink(dst); l != "/run/systemd/resolve/resolv.conf" {
		t.Fatalf("resolv.conf -> %q", l)
	}
	if hostExists(r, "/etc/resolv.conf.hostconfig.tmp") {
		t.Fatal("temp symlink lingered after repoint")
	}
}

// TestApplyNftUnitRejectsBeforePromote — an invalid ruleset must be
// nft -c'd at a CANDIDATE path and never reach the deploy file.
func TestApplyNftUnitRejectsBeforePromote(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{
		"nft -c -f": true,
	}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/guard.nft", "table ip good {}\n")
	c := loadCyc(t, r, vars, "node-b")
	before := c.errs
	c.applyNftUnit("guard", "/etc/guard.nft", []byte("garbage ruleset\n"), "test guard")
	if c.errs == before {
		t.Fatal("invalid ruleset not counted")
	}
	if got := hostRead(t, r, "/etc/guard.nft"); got != "table ip good {}\n" {
		t.Fatalf("deploy path clobbered by invalid ruleset:\n%s", got)
	}
	if hostExists(r, "/etc/guard.nft.candidate") {
		t.Fatal("rejected candidate left behind")
	}
	// validation ran on the candidate, not the deploy path
	if len(sr.callsMatching("nft -c -f /etc/guard.nft.candidate")) == 0 {
		t.Fatalf("nft -c did not target the candidate: %v",
			sr.callsMatching("nft -c"))
	}
}

// TestApplyNftUnitPromotesValidCandidate — a valid candidate is
// promoted through writeManaged and the staging file swept.
func TestApplyNftUnitPromotesValidCandidate(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.applyNftUnit("guard", "/etc/guard.nft", []byte("table ip guard {}\n"), "test guard")
	if got := hostRead(t, r, "/etc/guard.nft"); got != "table ip guard {}\n" {
		t.Fatalf("valid ruleset not promoted:\n%s", got)
	}
	if hostExists(r, "/etc/guard.nft.candidate") {
		t.Fatal("candidate lingered after promotion")
	}
	if len(sr.callsMatching("systemctl restart guard.service")) == 0 {
		t.Fatal("changed ruleset did not restart the unit")
	}
}

// TestBlockInHostsReadFail — a failed /etc/hosts read must bail (and
// count) rather than rewrite the file to only the managed block.
func TestBlockInHostsReadFail(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// /etc/hosts as a DIRECTORY makes ReadFile fail.
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc/hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	before := c.errs
	c.blockInHosts("x-test", "# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n")
	if c.errs == before {
		t.Fatal("hosts read failure not counted")
	}
	if fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "etc/hosts")); !fi.IsDir() {
		t.Fatal("hosts overwritten on read failure")
	}
}

// TestGroupPullsQuotedExtraArgs — flags must land INSIDE a quoted
// --kubelet-extra-args value (before the closing quote), both quote
// styles.
func TestGroupPullsQuotedExtraArgs(t *testing.T) {
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
			`--kubelet-extra-args="--node-ip=172.29.0.14"`+"\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service",
		"[Service]\nExecStart=/usr/bin/k0s controller --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args='--node-ip=172.29.0.14'`+"\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if !strings.Contains(unit,
		`--kubelet-extra-args="--node-ip=172.29.0.14\x20--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4"`) {
		t.Fatalf("flags not inside the double-quoted value:\n%s", unit)
	}
	ctl := hostRead(t, r, "/etc/systemd/system/k0scontroller.service")
	if !strings.Contains(ctl,
		`--kubelet-extra-args='--node-ip=172.29.0.14\x20--serialize-image-pulls=false\x20--registry-qps=2\x20--registry-burst=4'`) {
		t.Fatalf("flags not inside the single-quoted value:\n%s", ctl)
	}
}

// TestRenderZoneFileSkipsMarkerlessHub — a hub with no registry
// marker must not render `nsN IN A ` (empty rdata coredns rejects).
func TestRenderZoneFileSkipsMarkerlessHub(t *testing.T) {
	vars := writeVarsDir(t, "")
	if err := os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-z:
  name: z
  site: s1
  hub: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	zb, err := c.renderZoneFile()
	if err != nil {
		t.Fatal(err)
	}
	z := string(zb)
	if strings.Contains(z, "ns2") {
		t.Fatalf("markerless hub rendered NS records:\n%s", z)
	}
	if regexp.MustCompile(`IN A\s*\n`).MatchString(z) {
		t.Fatalf("empty A rdata rendered:\n%s", z)
	}
	if !strings.Contains(z, "IN NS ns1.test.internal.") ||
		!strings.Contains(z, "IN A 172.29.0.10") {
		t.Fatalf("marker hub records missing:\n%s", z)
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
	sr.calls = nil
	c2 := loadCyc(t, r, vars, "node-b")
	c2.groupAPILB()
	if len(sr.callsMatching("systemctl restart api-local-lb.service")) == 0 {
		t.Fatalf("unit drift did not restart api-local-lb: %v",
			sr.callsMatching("api-local-lb"))
	}
}

// TestNebulaEmptyVersionPinSkips — an empty version pin is "not
// pinned": log+skip, never a vacuous version match, never download("").
func TestNebulaEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_version: \"\"\n")
	sr := &scriptedRunner{res: map[string]string{
		"/usr/local/bin/nebula -version": "nebula version 9.9.9",
	}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaInstallBinary()
	if c.errs == 0 {
		t.Fatal("unpinned nebula install not counted")
	}
	if len(sr.callsMatching("nebula -version")) > 0 {
		t.Fatal("version probe ran on an empty pin")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("download attempted without a version pin")
	}
}

// TestCoreDNSEmptyVersionPinSkips — same contract for coredns.
func TestCoreDNSEmptyVersionPinSkips(t *testing.T) {
	vars := writeVarsDir(t, "interdc_coredns_version: \"\"\n")
	sr := &scriptedRunner{res: map[string]string{
		"/usr/local/bin/coredns -version": "CoreDNS-9.9.9",
	}, errs: map[string]bool{}}
	dl := t.TempDir()
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: dl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.corednsInstallBinary()
	if c.errs == 0 {
		t.Fatal("unpinned coredns install not counted")
	}
	if len(sr.callsMatching("coredns -version")) > 0 {
		t.Fatal("version probe ran on an empty pin")
	}
	if entries, _ := os.ReadDir(dl); len(entries) > 0 {
		t.Fatal("download attempted without a version pin")
	}
}

// TestNebulaRoutingRefusesBadVar — a var carrying shell metachars
// must abort the routing converge before any sh -c is built.
func TestNebulaRoutingRefusesBadVar(t *testing.T) {
	vars := writeVarsDir(t, `interdc_marker_base: "172.29.0;rm -rf /"`)
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if c.errs == 0 {
		t.Fatal("injected var not counted")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with injected marker_base: %v", sr.callsMatching("sh -c"))
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
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-a", HostRoot: t.TempDir(),
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

// TestProbeReachableRejectsBadAddr — a backend addr containing a
// quote is skipped before it can break out of the bash -c wrapper.
func TestProbeReachableRejectsBadAddr(t *testing.T) {
	vars := writeVarsDir(t, `api_lb_backends:
  - {name: api_evil, addr: "10.0.0.1';id:6443", probe: true}
  - {name: api_ok, addr: "10.0.1.10:6443", probe: true}
`)
	sr := &scriptedRunner{res: map[string]string{
		"/dev/tcp/10.0.1.10/6443": "",
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.probeReachable()
	if len(got) != 1 || got[0] != "api_ok" {
		t.Fatalf("probeReachable = %v", got)
	}
	if len(sr.callsMatching("/dev/tcp/10.0.0.1")) > 0 {
		t.Fatalf("injected addr reached the shell: %v", sr.callsMatching("/dev/tcp"))
	}
	if c.errs == 0 {
		t.Fatal("injected backend addr not counted")
	}
}

// TestDownloadSweepsTmpOnShaMismatch — the .dl staging file must not
// survive a rejected download.
func TestDownloadSweepsTmpOnShaMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered"))
	}))
	t.Cleanup(srv.Close)
	r := newTestReconciler(t, t.TempDir())
	dst := filepath.Join(r.cfg.HostRoot, "dl/x.tgz")
	if err := r.download(context.Background(), srv.URL+"/x.tgz", dst,
		strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if hostExists(r, "/dl/x.tgz.dl") {
		t.Fatal("partial .dl left behind")
	}
	if hostExists(r, "/dl/x.tgz") {
		t.Fatal("mismatched payload promoted")
	}
}

// ---------- runLong timeout routing ----------

// budgetProbe answers canned output like scriptedRunner but records
// the deadline each command ran under — asserts the run vs runLong
// routing of slow host ops.
type budgetProbe struct {
	res map[string]string
	dls map[string]time.Duration
}

func (b *budgetProbe) Run(ctx context.Context, name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	if b.dls == nil {
		b.dls = map[string]time.Duration{}
	}
	if dl, ok := ctx.Deadline(); ok {
		b.dls[c] = time.Until(dl)
	}
	best, bestLen := "", -1
	for k, v := range b.res {
		if strings.Contains(c, k) && len(k) > bestLen {
			best, bestLen = v, len(k)
		}
	}
	return best, nil
}

// TestSlowOpsUseLongBudget — the package/vacuum commands run under
// CmdTimeoutLong (~10m); plain probes stay on CmdTimeout (~120s).
func TestSlowOpsUseLongBudget(t *testing.T) {
	vars := writeVarsDir(t, "")
	bp := &budgetProbe{res: map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
		"sshd -T":         "passwordauthentication no",
	}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: bp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	c.groupSecurity()
	budget := func(call string) time.Duration {
		d, ok := bp.dls[call]
		if !ok {
			t.Fatalf("%q never ran", call)
		}
		return d
	}
	if d := budget("journalctl --rotate --vacuum-time=3d"); d <= 9*time.Minute+50*time.Second {
		t.Fatalf("rotate/vacuum budget %v — slow vacuum must run under CmdTimeoutLong", d)
	}
	if d := budget("env DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban"); d <= 9*time.Minute+50*time.Second {
		t.Fatalf("apt-get install budget %v — must run under CmdTimeoutLong", d)
	}
	if d := budget("journalctl -n 5 --no-pager"); d > 2*time.Minute {
		t.Fatalf("probe budget %v — plain queries stay on CmdTimeout", d)
	}
	if d := budget("dpkg-query -W -f=${db:Status-Status} fail2ban"); d > 2*time.Minute {
		t.Fatalf("dpkg-query budget %v — plain queries stay on CmdTimeout", d)
	}
}

// ---------- groupAPILB candidate staging ----------

// TestAPILBStagesHaproxyCandidate — a cfg that fails haproxy -c must
// never sit at the live path the unit loads on next start.
func TestAPILBStagesHaproxyCandidate(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.errs["api-local-lb.cfg.candidate"] = true
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
	if len(sr.callsMatching("haproxy -c -f /etc/haproxy/api-local-lb.cfg.candidate")) == 0 {
		t.Fatalf("haproxy -c did not target the candidate: %v",
			sr.callsMatching("haproxy"))
	}
}

// TestAPILBStagesNftCandidate — a ruleset that fails nft -c must
// never sit at the live path ExecStartPost loads.
func TestAPILBStagesNftCandidate(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	sr.errs["api-local-dnat.nft.candidate"] = true
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
	if len(sr.callsMatching("haproxy -c -f /etc/haproxy/api-local-lb.cfg.candidate")) == 0 {
		t.Fatalf("haproxy -c did not target the candidate: %v",
			sr.callsMatching("haproxy"))
	}
	if len(sr.callsMatching("nft -c -f /etc/api-local-dnat.nft.candidate")) == 0 {
		t.Fatalf("nft -c did not target the candidate: %v",
			sr.callsMatching("nft -c"))
	}
}

// TestApplyNftUnitSweepsStaleCandidate — on the unchanged-content
// path a leftover .candidate from a crashed converge is still swept.
func TestApplyNftUnitSweepsStaleCandidate(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/guard.nft", "table ip guard {}\n")
	hostWrite(t, r, "/etc/guard.nft.candidate", "stale from crashed converge\n")
	c := loadCyc(t, r, vars, "node-b")
	c.applyNftUnit("guard", "/etc/guard.nft", []byte("table ip guard {}\n"), "test guard")
	if hostExists(r, "/etc/guard.nft.candidate") {
		t.Fatal("stale candidate not swept on the unchanged path")
	}
	if len(sr.callsMatching("nft -c")) > 0 {
		t.Fatal("unchanged ruleset re-validated — staging must be skipped")
	}
}

// ---------- blockInHosts ENOENT ----------

// TestBlockInHostsCreatesWhenMissing — a missing /etc/hosts is not
// the unreadable case: create it containing just the managed block.
func TestBlockInHostsCreatesWhenMissing(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.blockInHosts("x-test", "# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n")
	if c.errs != 0 {
		t.Fatalf("ENOENT hosts counted %d errors — must create instead", c.errs)
	}
	if got := hostRead(t, r, "/etc/hosts"); got !=
		"# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n" {
		t.Fatalf("hosts = %q, want just the managed block", got)
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
	sr := &scriptedRunner{res: map[string]string{
		"/dev/tcp/::1/6443": "",
	}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.probeReachable()
	if len(got) != 1 || got[0] != "api_v6" {
		t.Fatalf("probeReachable = %v — bracketed IPv6 must parse", got)
	}
	if len(sr.callsMatching("/dev/tcp/::1/6443")) == 0 {
		t.Fatalf("v6 probe not issued: %v", sr.callsMatching("/dev/tcp"))
	}
}

// ---------- required-slot empty values ----------

// TestNebulaRoutingEmptyRequiredIPCounted — node-b has no ip, so the
// REQUIRED pub/marker slots resolve "". Empty cannot inject, but it
// emits `src <blank>`/`snat to <blank>` that only fail inside sh -c
// at Debug level — the *Req gates must count it instead.
func TestNebulaRoutingEmptyRequiredIPCounted(t *testing.T) {
	vars := writeVarsDir(t, "")
	if err := os.WriteFile(filepath.Join(vars, "interdc_nodes.yaml"), []byte(`node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
node-b:
  name: b
  site: s2
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.nebulaRouting()
	if c.errs == 0 {
		t.Fatal("empty required ip not counted")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("shell ran with an empty required ip: %v", sr.callsMatching("sh -c"))
	}
}

// TestShRequiredGatesCountEmpty — the base gates keep their empty-
// allowed semantics; only the *Req variants count empty as an error.
func TestShRequiredGatesCountEmpty(t *testing.T) {
	c := &cyc{}
	if !c.shToken("x", "") || !c.shIPCIDR("x", "") || !c.shPort("x", "") {
		t.Fatal("base gates must keep allowing empty")
	}
	if c.shIPCIDRReq("x", "") || c.shPortReq("x", "") {
		t.Fatal("required gates must refuse empty")
	}
	if c.errs != 2 {
		t.Fatalf("errs = %d, want 2", c.errs)
	}
}

// ---------- t7 extra-args hardening ----------

// TestGroupPullsRefusesUnsafeQPS — a vars value with shell metachars
// interpolated into ExecStart must skip the unit rewrite, not emit a
// mangled unit.
func TestGroupPullsRefusesUnsafeQPS(t *testing.T) {
	vars := writeVarsDir(t, "kubelet_registry_qps: \"2;rm -rf /\"\n")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	if c.errs == 0 {
		t.Fatal("metachar kubelet_registry_qps not counted")
	}
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if strings.Contains(unit, `\x20`) || strings.Contains(unit, "kubelet-extra-args") {
		t.Fatalf("unit mutated despite a refused qps value:\n%s", unit)
	}
}

// TestGroupPullsUnterminatedExtraArgsQuote — `--kubelet-extra-args="abc`
// (no closing quote) must error and leave the unit untouched rather
// than merge flags into a value systemd tokenizes differently.
func TestGroupPullsUnterminatedExtraArgsQuote(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s "+
			`--kubelet-extra-args="--node-ip=172.29.0.14`+"\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupPulls()
	if c.errs == 0 {
		t.Fatal("unterminated --kubelet-extra-args quote not counted")
	}
	unit := hostRead(t, r, "/etc/systemd/system/k0sworker.service")
	if strings.Contains(unit, `\x20`) {
		t.Fatalf("flags merged into an unterminated value:\n%s", unit)
	}
}

// TestT7AppendExtraArgsUnterminated — direct check of the ok flag on
// open-quote values vs properly quoted/bare ones.
func TestT7AppendExtraArgsUnterminated(t *testing.T) {
	if _, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args="abc`, `\x20--x`); ok {
		t.Fatal("unterminated double-quote accepted")
	}
	if _, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args='abc`, `\x20--x`); ok {
		t.Fatal("unterminated single-quote accepted")
	}
	if out, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args="abc"`, `\x20--x`); !ok ||
		!strings.Contains(out, `--kubelet-extra-args="abc\x20--x"`) {
		t.Fatalf("quoted append wrong: %q ok=%v", out, ok)
	}
	if out, ok := t7AppendExtraArgs(`ExecStart=k0s --kubelet-extra-args=abc`, `\x20--x`); !ok ||
		!strings.Contains(out, `--kubelet-extra-args=abc\x20--x`) {
		t.Fatalf("bare append wrong: %q ok=%v", out, ok)
	}
}

// ---------- groupNebula disable path ----------

// TestNebulaDisableRunsUnconditionalCleanup — a charset-refused var
// must only skip the INTERPOLATED sweep; the non-interpolated
// systemctl disable cleanup still runs.
func TestNebulaDisableRunsUnconditionalCleanup(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\ninterdc_marker_base: \"172.29.0;rm -rf /\"\n")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{Enabled: true, NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNebula()
	if len(sr.callsMatching("systemctl disable --now nebula@interdc.service")) == 0 {
		t.Fatal("nebula unit not disabled on the gate-refused path")
	}
	if len(sr.callsMatching("systemctl disable --now nebula-route-guard.service")) == 0 {
		t.Fatal("route-guard not disabled on the gate-refused path")
	}
	if len(sr.callsMatching("sh -c")) > 0 {
		t.Fatalf("interpolated sweep ran with a refused var: %v", sr.callsMatching("sh -c"))
	}
	if c.errs == 0 {
		t.Fatal("refused marker_base not counted")
	}
}
