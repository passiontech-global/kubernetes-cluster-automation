// groups_test.go — shared converge fixtures (newScripted,
// writeVarsDir, loadCyc, host-root helpers) plus cross-group and
// orchestration coverage: CycleWithErrors accounting, applyNftUnit
// staging, run budgets, and the sh* charset gates.
package hostconfig

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// newScripted loads the shared FakeRunner from the res/errs maps the
// suites used to hand the private scriptedRunner: res maps a command
// substring to stdout, errs marks substrings that fail (a fail key
// wins over a res key however long either is — the old errs-first
// lookup, now FakeRunner's fail-rules-beat-replies rule).
func newScripted(res map[string]string, errs map[string]bool) *testutil.FakeRunner {
	f := testutil.NewFakeRunner()
	for k, v := range res {
		f.On(k, v)
	}
	for k := range errs {
		f.FailOn(k, nil)
	}
	return f
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

// TestKineServiceTLSAndTCPReadiness — the Phase-3 mTLS cutover:
// tcp:// listen renders the cert flags plus an ExecStartPost that
// waits for the TCP port to accept before Before= is satisfied.
func TestKineServiceTLSAndTCPReadiness(t *testing.T) {
	bin := []byte("#!/bin/sh\n# fake kine\n")
	sum := sha256.Sum256(bin)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bin)
	}))
	t.Cleanup(srv.Close)
	vars := writeVarsDir(t, fmt.Sprintf(`kine_service_hosts: [node-a]
kine_bin_url: "%s/kine"
kine_bin_sha256: "%x"
kine_endpoint: "postgres://x"
kine_listen_address: "tcp://127.0.0.1:2379"
kine_ca_file: "/var/lib/k0s/pki/etcd/ca.crt"
kine_server_cert_file: "/var/lib/k0s/pki/apiserver-etcd-client.crt"
kine_server_key_file: "/var/lib/k0s/pki/apiserver-etcd-client.key"
`, srv.URL, sum))
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr, DownloadDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	c.groupKineService()
	unit := hostRead(t, r, "/etc/systemd/system/kine.service")
	for _, want := range []string{
		"--ca-file=/var/lib/k0s/pki/etcd/ca.crt",
		"--server-cert-file=/var/lib/k0s/pki/apiserver-etcd-client.crt",
		"--server-key-file=/var/lib/k0s/pki/apiserver-etcd-client.key",
		"--listen-address=tcp://127.0.0.1:2379",
		"/dev/tcp/127.0.0.1/2379",
		"[ $i -lt 30 ]",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("kine.service missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "/run/k0s/kine.sock") {
		t.Fatal("unix socket rendered on a tcp:// listen")
	}
}

// ---------- CycleWithErrors / per-group error accounting (2.6) ----------

// cleanCycleFixture returns a Reconciler + runner whose groups all
// self-gate or succeed under a tempdir HostRoot, so CycleWithErrors
// reports 0 and lastOK is stamped.
func cleanCycleFixture(t *testing.T) (*Reconciler, *testutil.FakeRunner) {
	t.Helper()
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\n")
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version":               "CoreDNS-1.14.7",
		"dig @127.0.0.1":                                "10.0.1.10",
		"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
		"sshd -T": "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		DownloadDir: t.TempDir(), Runner: sr,
		Clock: timex.NewCell(func() time.Time { return time.Unix(1_700_000_000, 0) })}, nil)
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
	if got := promtestutil.ToFloat64(r.lastOK); got != 1_700_000_000 {
		t.Fatalf("lastOK = %v, want Clock unix", got)
	}
}

func TestCycleWithErrorsTopologyLoadFailure(t *testing.T) {
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
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
	sr.FailOn("systemctl daemon-reload", nil)
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
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("nodelocaldns", "error")); got != 1 {
		t.Fatalf("cycles{nodelocaldns,error} = %v want 1", got)
	}
	// Errors attribute per group: a clean group still reads "ok".
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("base", "ok")); got != 1 {
		t.Fatalf("cycles{base,ok} = %v want 1 (error mis-attributed)", got)
	}
	if got := promtestutil.ToFloat64(r.lastOK); got != 0 {
		t.Fatalf("lastOK stamped on a failed cycle: %v", got)
	}
}

func TestGroupRecordsOkErrorPanic(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	c.group("g-ok", func() {})
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("g-ok", "ok")); got != 1 {
		t.Fatalf("cycles{g-ok,ok} = %v want 1", got)
	}
	if c.errs != 0 {
		t.Fatalf("errs = %d after clean group", c.errs)
	}

	c.group("g-err", func() { c.err("boom") })
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("g-err", "error")); got != 1 {
		t.Fatalf("cycles{g-err,error} = %v want 1", got)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d after failing group", c.errs)
	}

	c.group("g-panic", func() { panic("test panic") })
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("g-panic", "panic")); got != 1 {
		t.Fatalf("cycles{g-panic,panic} = %v want 1", got)
	}
	if c.errs != 2 {
		t.Fatalf("errs = %d after panicking group", c.errs)
	}
	// later groups still run after a panic.
	c.group("g-after", func() {})
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("g-after", "ok")); got != 1 {
		t.Fatalf("cycles{g-after,ok} = %v want 1", got)
	}
}

func TestGroupWriteFailureCountedViaHelper(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	hr := t.TempDir()
	r, err := New(Config{NodeName: "node-b", HostRoot: hr,
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
	if got := promtestutil.ToFloat64(r.cycles.WithLabelValues("g-write", "error")); got != 1 {
		t.Fatalf("cycles{g-write,error} = %v want 1", got)
	}
}

// ---------- journald integrity (A5, groupBase) ----------

func journaldEnv(t *testing.T, res map[string]string, errs map[string]bool) (*cyc, *Reconciler, *testutil.FakeRunner) {
	t.Helper()
	vars := writeVarsDir(t, "")
	sr := newScripted(res, errs)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	return loadCyc(t, r, vars, "node-b"), r, sr
}

// TestApplyNftUnitRejectsBeforePromote — an invalid ruleset must be
// nft -c'd at a CANDIDATE path and never reach the deploy file.
func TestApplyNftUnitRejectsBeforePromote(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, map[string]bool{
		"nft -c -f": true,
	})
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
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
	if len(sr.CallsMatching("nft -c -f /etc/guard.nft.candidate")) == 0 {
		t.Fatalf("nft -c did not target the candidate: %v",
			sr.CallsMatching("nft -c"))
	}
}

// TestApplyNftUnitPromotesValidCandidate — a valid candidate is
// promoted through writeManaged and the staging file swept.
func TestApplyNftUnitPromotesValidCandidate(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
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
	if len(sr.CallsMatching("systemctl restart guard.service")) == 0 {
		t.Fatal("changed ruleset did not restart the unit")
	}
}

// TestDownloadSweepsTmpOnShaMismatch — the .dl staging file must not
// survive a rejected download.
func TestDownloadSweepsTmpOnShaMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered"))
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

// TestSlowOpsUseLongBudget — the package/vacuum commands run under
// CmdTimeoutLong (~10m); plain probes stay on CmdTimeout (~120s).
// FakeRunner's per-call deadline record (DeadlineFor) is the probe.
func TestSlowOpsUseLongBudget(t *testing.T) {
	vars := writeVarsDir(t, "")
	bp := newScripted(map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
		"sshd -T":         "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: bp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	c.groupSecurity()
	budget := func(call string) time.Duration {
		d, ok := bp.DeadlineFor(call)
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

// TestApplyNftUnitSweepsStaleCandidate — on the unchanged-content
// path a leftover .candidate from a crashed converge is still swept.
func TestApplyNftUnitSweepsStaleCandidate(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
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
	if len(sr.CallsMatching("nft -c")) > 0 {
		t.Fatal("unchanged ruleset re-validated — staging must be skipped")
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
