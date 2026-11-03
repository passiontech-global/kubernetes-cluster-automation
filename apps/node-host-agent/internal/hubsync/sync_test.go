package hubsync

import (
	"context"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// testConfig returns a Config pointed at the fixture dirs plus a
// scratch local binary, an existing SSH key path (ensureKey gate),
// fake dialer and fake clientset carrying the guard secret.
func testConfig(t *testing.T, cs *fake.Clientset, dialer *fakeDialer,
	binary []byte) Config {
	t.Helper()
	dir := t.TempDir()
	bin := path.Join(dir, "node-host-agent")
	if err := os.WriteFile(bin, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	// The file only needs to exist — Enabled()/ensureKey stat it and
	// the fake dialer never parses it.
	key := path.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Client:         cs,
		Identity:       "pod-a",
		VarsDir:        "testdata/vars",
		NebulaCertsDir: "testdata/nebula-certs",
		SSHKeyPath:     key,
		LocalBinary:    bin,
		Dialer:         dialer,
	}
}

func newClientsetWithSecret() *fake.Clientset {
	return fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "api-backend-guard-token",
		},
		Data: map[string][]byte{
			"token":  []byte("guard-token-value"),
			"ca.crt": []byte("guard-ca-pem"),
		},
	})
}

// TestSyncTargetFreshHost: a bare host gets the binary, all vars,
// nebula certs (interdc only), unit file and `enable --now`.
func TestSyncTargetFreshHost(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer,
		[]byte("fake-agent-binary-v1")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "hub-controller-01", IP: "10.0.0.25",
		SSHUser: "root", InterDC: true, Hub: true}

	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	c := dialer.conn(tg)

	// Binary staged + renamed into place with executable mode.
	bin, ok := c.fileContent("/usr/local/bin/node-host-agent")
	if !ok || string(bin) != "fake-agent-binary-v1" {
		t.Fatalf("remote binary missing: %v", c.files)
	}
	assertOpOrder(t, c.opsLog(),
		"write:/usr/local/bin/.node-host-agent.tmp",
		"run:chmod 0755 '/usr/local/bin/.node-host-agent.tmp'",
		"run:mv '/usr/local/bin/.node-host-agent.tmp' '/usr/local/bin/node-host-agent'")

	// Vars dir fully mirrored.
	for _, name := range []string{"defaults.yaml", "cluster.yaml", "interdc_nodes.yaml"} {
		if _, ok := c.fileContent("/etc/node-host-agent/vars/" + name); !ok {
			t.Fatalf("vars file %s not synced", name)
		}
	}
	// InterDC target gets nebula certs.
	if _, ok := c.fileContent("/etc/node-host-agent/nebula-certs/nebula-ca.crt"); !ok {
		t.Fatal("nebula certs not synced to interdc target")
	}
	// Unit installed; fresh host installs the binary → enable +
	// restart (binaryUpdated path — restart on a stopped unit starts
	// it, and `enable` covers the boot-time path enable --now would).
	if _, ok := c.fileContent("/etc/systemd/system/node-host-agent.service"); !ok {
		t.Fatal("unit not installed")
	}
	ops := strings.Join(c.opsLog(), "\n")
	assertOpOrder(t, c.opsLog(),
		"run:systemctl enable node-host-agent.service",
		"run:systemctl restart node-host-agent.service")
	if strings.Contains(ops, "enable --now") {
		t.Fatalf("binary install path must restart, not enable --now:\n%s", ops)
	}
}

// TestSyncTargetNonInterDC: a non-registry target (db-vm style)
// skips the nebula-certs dir entirely.
func TestSyncTargetNonInterDC(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "db-vm", IP: "10.0.0.15", SSHUser: "root", KineDB: true}
	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	ops := strings.Join(dialer.conn(tg).opsLog(), "\n")
	if strings.Contains(ops, "nebula-certs") {
		t.Fatalf("non-interdc target must skip certs:\n%s", ops)
	}
}

// TestSyncTargetBinaryUpToDate: matching sha256 → no upload, and the
// service only gets enable --now (no restart).
func TestSyncTargetBinaryUpToDate(t *testing.T) {
	dialer := newFakeDialer()
	local := []byte("same-binary")
	tg := Target{Name: "hub-controller-01", IP: "10.0.0.25",
		SSHUser: "root", InterDC: true}
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, local), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-seed: binary + unit already converged.
	c := newFakeConn()
	c.seedFile("/usr/local/bin/node-host-agent", local)
	c.seedFile("/etc/systemd/system/node-host-agent.service",
		[]byte(systemdUnit(tg, s.cfg.RemoteBinary, s.cfg.RemoteVarsDir, s.cfg.RemoteCertsDir)))
	dialer.conns[tg.IP] = c

	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	ops := strings.Join(c.opsLog(), "\n")
	if strings.Contains(ops, "write:/usr/local/bin/") {
		t.Fatalf("up-to-date binary must not upload:\n%s", ops)
	}
	if strings.Contains(ops, "systemctl restart") || strings.Contains(ops, "daemon-reload") {
		t.Fatalf("no drift → no restart/daemon-reload:\n%s", ops)
	}
	if !strings.Contains(ops, "systemctl enable --now") {
		t.Fatalf("expected enable --now:\n%s", ops)
	}
}

// TestSyncTargetBinaryUpdatedRestarts: binary drift → upload then
// restart (not enable --now).
func TestSyncTargetBinaryUpdatedRestarts(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer,
		[]byte("new-binary")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "hub-controller-01", IP: "10.0.0.25",
		SSHUser: "root", InterDC: true}
	c := newFakeConn()
	c.seedFile("/usr/local/bin/node-host-agent", []byte("old-binary"))
	dialer.conns[tg.IP] = c

	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	ops := c.opsLog()
	assertOpOrder(t, ops,
		"run:mv '/usr/local/bin/.node-host-agent.tmp' '/usr/local/bin/node-host-agent'",
		"run:systemctl restart node-host-agent.service")
	joined := strings.Join(ops, "\n")
	if strings.Contains(joined, "enable --now") {
		t.Fatalf("binary update path must restart, not enable --now:\n%s", joined)
	}
}

// TestSyncTargetAPILBCreds: APILB targets receive token 0600 +
// ca.crt 0600 atomically under /etc/api-backend-guard.
func TestSyncTargetAPILBCreds(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "api-lb-vm", IP: "10.0.0.14", SSHUser: "root", APILB: true}
	if err := s.syncTarget(context.Background(), tg,
		[]byte("guard-token-value"), []byte("guard-ca-pem")); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	c := dialer.conn(tg)
	tok, ok := c.fileContent("/etc/api-backend-guard/token")
	if !ok || string(tok) != "guard-token-value" {
		t.Fatal("token not written")
	}
	ca, ok := c.fileContent("/etc/api-backend-guard/ca.crt")
	if !ok || string(ca) != "guard-ca-pem" {
		t.Fatal("ca.crt not written")
	}
	assertOpOrder(t, c.opsLog(),
		"run:chmod 0600 '/etc/api-backend-guard/.token.tmp'",
		"run:mv '/etc/api-backend-guard/.token.tmp' '/etc/api-backend-guard/token'")
	assertOpOrder(t, c.opsLog(),
		"run:chmod 0600 '/etc/api-backend-guard/.ca.crt.tmp'",
		"run:mv '/etc/api-backend-guard/.ca.crt.tmp' '/etc/api-backend-guard/ca.crt'")

	// Non-APILB target never touches the guard dir.
	plain := Target{Name: "db-vm", IP: "10.0.0.15", SSHUser: "root"}
	if err := s.syncTarget(context.Background(), plain,
		[]byte("t"), []byte("c")); err != nil {
		t.Fatalf("syncTarget plain: %v", err)
	}
	ops := strings.Join(dialer.conn(plain).opsLog(), "\n")
	if strings.Contains(ops, "api-backend-guard") {
		t.Fatalf("non-apilb target touched guard dir:\n%s", ops)
	}
}

// TestCycleEndToEnd: Cycle aggregates the fixture targets, converges
// each via the fake dialer and emits the metrics contract.
func TestCycleEndToEnd(t *testing.T) {
	dialer := newFakeDialer()
	reg := prometheus.NewRegistry()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), reg)
	if err != nil {
		t.Fatal(err)
	}
	s.Cycle(context.Background())

	if got := len(dialer.dials()); got != 5 {
		t.Fatalf("dialed %d targets, want 5", got)
	}
	// api-lb-vm (deduped) must have gotten the guard creds.
	alb := dialer.conn(Target{IP: "10.0.0.14"})
	if _, ok := alb.fileContent("/etc/api-backend-guard/token"); !ok {
		t.Fatal("api-lb creds missing after cycle")
	}
	// Metric contract: cycles ok per target + last_success set.
	cycles := gatherVec(t, reg, "node_host_agent_hubsync_cycles_total")
	for _, name := range []string{"hub-controller-01", "lanit-hub-01",
		"lanit-hub-02", "api-lb-vm", "db-vm"} {
		if cycles[labelKey("target", name, "result", "ok")] != 1 {
			t.Fatalf("cycles_total{%s,ok} = %v", name,
				cycles[labelKey("target", name, "result", "ok")])
		}
	}
	last := gatherVec(t, reg, "node_host_agent_hubsync_last_success_seconds")
	if last[labelKey("target", "db-vm")] <= 0 {
		t.Fatal("last_success not set")
	}
}

// TestCycleTargetErrorIsolation: a dial failure marks only that
// target's metric and doesn't abort the rest.
func TestCycleTargetErrorIsolation(t *testing.T) {
	dialer := newFakeDialer()
	dialer.err = map[string]error{"10.0.0.15": exitErr{255}}
	reg := prometheus.NewRegistry()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), reg)
	if err != nil {
		t.Fatal(err)
	}
	s.Cycle(context.Background())
	cycles := gatherVec(t, reg, "node_host_agent_hubsync_cycles_total")
	if cycles[labelKey("target", "db-vm", "result", "error")] != 1 {
		t.Fatal("db-vm error not counted")
	}
	if cycles[labelKey("target", "api-lb-vm", "result", "ok")] != 1 {
		t.Fatal("api-lb-vm should still converge")
	}
}

// TestRunLeaseGatesSync: while another pod holds a fresh lease the
// Run loop performs no SSH dials; once that lease expires a cycle
// runs. Uses real tickers at 5ms.
func TestRunLeaseGatesSync(t *testing.T) {
	now := time.Now()
	dur := int32(2) // 2s lease duration
	other := "pod-b"
	rt := metav1.NewMicroTime(now)
	cs := fake.NewSimpleClientset(&coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "node-ops", Name: "node-host-agent-hubsync",
		},
		Spec: coordv1.LeaseSpec{
			HolderIdentity:       &other,
			LeaseDurationSeconds: &dur,
			RenewTime:            &rt,
		},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "api-backend-guard-token",
		},
		Data: map[string][]byte{
			"token":  []byte("guard-token-value"),
			"ca.crt": []byte("guard-ca-pem"),
		},
	})
	dialer := newFakeDialer()
	cfg := testConfig(t, cs, dialer, []byte("bin"))
	cfg.RenewInterval = 10 * time.Millisecond
	cfg.WatchInterval = time.Hour // keep watcher out of this test
	cfg.SyncInterval = time.Hour
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Foreign lease is fresh → no converge dials.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(dialer.dials()) > 0 {
			t.Fatal("dialed while foreign lease held")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Age the foreign lease past expiry → takeover + converge.
	rt = metav1.NewMicroTime(time.Now().Add(-time.Hour))
	l, _ := cs.CoordinationV1().Leases("node-ops").
		Get(ctx, "node-host-agent-hubsync", metav1.GetOptions{})
	l.Spec.RenewTime = &rt
	if _, err := cs.CoordinationV1().Leases("node-ops").
		Update(ctx, l, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(dialer.dials()) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no converge after foreign lease expired")
}

// --- helpers ---

// assertOpOrder checks each want appears in ops in order.
func assertOpOrder(t *testing.T, ops []string, want ...string) {
	t.Helper()
	idx := 0
	for _, op := range ops {
		if idx < len(want) && op == want[idx] {
			idx++
		}
	}
	if idx < len(want) {
		t.Fatalf("op order mismatch — found %d/%d in order:\nwant %v\ngot\n%s",
			idx, len(want), want, strings.Join(ops, "\n"))
	}
}

func labelKey(kvs ...string) string {
	var parts []string
	for i := 0; i+1 < len(kvs); i += 2 {
		parts = append(parts, kvs[i]+"="+kvs[i+1])
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// gatherVec flattens a metric family into "k=v,k=v" → value.
func gatherVec(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			var parts []string
			for _, l := range m.GetLabel() {
				parts = append(parts, l.GetName()+"="+l.GetValue())
			}
			sort.Strings(parts) // dto labels arrive name-sorted; keep the key canonical
			key := strings.Join(parts, ",")
			switch {
			case m.Counter != nil:
				out[key] = m.GetCounter().GetValue()
			case m.Gauge != nil:
				out[key] = m.GetGauge().GetValue()
			}
		}
	}
	return out
}

// TestSyncTargetNonRootSudo: a non-root resolved SSH user (registry
// ssh_user / site map — ansible become:true parity) wraps every
// remote op in `sudo -n`, gated by a fail-fast probe; a root target
// stays unwrapped.
func TestSyncTargetNonRootSudo(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "lanit-hub-01", IP: "10.1.0.7",
		SSHUser: "ubuntu", InterDC: true}
	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	c := dialer.conn(tg)
	ops := c.opsLog()
	if len(ops) == 0 || ops[0] != "run:sudo -n true" {
		t.Fatalf("first op must be the sudo -n probe:\n%s", strings.Join(ops, "\n"))
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "run:") && !strings.HasPrefix(op, "run:sudo -n ") {
			t.Fatalf("non-root run op without sudo -n:\n%s", strings.Join(ops, "\n"))
		}
	}
	// Converge actually completed under sudo (binary landed).
	if _, ok := c.fileContent("/usr/local/bin/node-host-agent"); !ok {
		t.Fatal("non-root converge did not install the binary")
	}

	// Root target keeps raw commands.
	root := Target{Name: "db-vm", IP: "10.0.0.15", SSHUser: "root"}
	if err := s.syncTarget(context.Background(), root, nil, nil); err != nil {
		t.Fatalf("syncTarget root: %v", err)
	}
	for _, op := range dialer.conn(root).opsLog() {
		if strings.Contains(op, "sudo") {
			t.Fatalf("root target op unexpectedly sudo'd: %s", op)
		}
	}
}

// TestSyncTargetSudoUnavailable: when `sudo -n` fails remotely the
// probe surfaces a clear error naming the user — not a cryptic
// mkdir/write failure.
func TestSyncTargetSudoUnavailable(t *testing.T) {
	dialer := newFakeDialer()
	s, err := New(testConfig(t, newClientsetWithSecret(), dialer, []byte("bin")), nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "lanit-hub-02", IP: "10.1.0.8", SSHUser: "converge"}
	c := newFakeConn()
	c.sudo = true
	c.runHook = func(cmd string) (string, error) {
		if cmd == "sudo -n true" {
			return "sudo: a password is required", exitErr{1}
		}
		return "", nil
	}
	dialer.conns[tg.IP] = c

	err = s.syncTarget(context.Background(), tg, nil, nil)
	if err == nil {
		t.Fatal("syncTarget succeeded without passwordless sudo")
	}
	if !strings.Contains(err.Error(), "converge") ||
		!strings.Contains(err.Error(), "sudo -n") {
		t.Fatalf("error must name the user and sudo -n: %v", err)
	}
	// The probe aborted the converge — no writes happened.
	for _, op := range c.opsLog() {
		if strings.HasPrefix(op, "write:") {
			t.Fatalf("write attempted after failed sudo probe:\n%s",
				strings.Join(c.opsLog(), "\n"))
		}
	}
}

// TestCycleSecretFailureScopesAPILB: a failed guard-secret fetch
// marks only api-lb targets secret_error — interdc/infra targets
// still converge (the fetch is the ONLY thing they share).
func TestCycleSecretFailureScopesAPILB(t *testing.T) {
	dialer := newFakeDialer()
	reg := prometheus.NewRegistry()
	// Clientset WITHOUT the api-backend-guard-token secret.
	s, err := New(testConfig(t, fake.NewSimpleClientset(), dialer,
		[]byte("bin")), reg)
	if err != nil {
		t.Fatal(err)
	}
	s.Cycle(context.Background())

	cycles := gatherVec(t, reg, "node_host_agent_hubsync_cycles_total")
	if cycles[labelKey("target", "api-lb-vm", "result", "secret_error")] != 1 {
		t.Fatalf("api-lb-vm secret_error = %v",
			cycles[labelKey("target", "api-lb-vm", "result", "secret_error")])
	}
	for _, name := range []string{"hub-controller-01", "lanit-hub-01",
		"lanit-hub-02", "db-vm"} {
		if cycles[labelKey("target", name, "result", "ok")] != 1 {
			t.Fatalf("%s must still converge: %v", name, cycles)
		}
	}
	// api-lb-vm is skipped before the SSH dial.
	for _, ip := range dialer.dials() {
		if ip == "10.0.0.14" {
			t.Fatal("api-lb-vm dialed despite missing guard secret")
		}
	}
}

// TestNebulaCertsFilter: the certs mirror carries only cert/key
// material — the pod's certs and vars dirs are the same projected
// volume, so cluster.yaml/defaults.yaml must not be duplicated into
// the remote nebula-certs dir.
func TestNebulaCertsFilter(t *testing.T) {
	certs := t.TempDir()
	for name, data := range map[string]string{
		"nebula-ca.crt":  "ca",
		"nebula-hub.crt": "host-cert",
		"host.pub":       "pub",
		"host.key":       "key",
		"cluster.yaml":   "pollution",
		"defaults.yaml":  "pollution",
	} {
		if err := os.WriteFile(path.Join(certs, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dialer := newFakeDialer()
	cfg := testConfig(t, newClientsetWithSecret(), dialer, []byte("bin"))
	cfg.NebulaCertsDir = certs
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "hub-controller-01", IP: "10.0.0.25",
		SSHUser: "root", InterDC: true}
	if err := s.syncTarget(context.Background(), tg, nil, nil); err != nil {
		t.Fatalf("syncTarget: %v", err)
	}
	c := dialer.conn(tg)
	for _, want := range []string{"nebula-ca.crt", "nebula-hub.crt", "host.pub", "host.key"} {
		if _, ok := c.fileContent("/etc/node-host-agent/nebula-certs/" + want); !ok {
			t.Fatalf("cert artifact %s not synced", want)
		}
	}
	for _, unwanted := range []string{"cluster.yaml", "defaults.yaml"} {
		if _, ok := c.fileContent("/etc/node-host-agent/nebula-certs/" + unwanted); ok {
			t.Fatalf("%s must not land in nebula-certs", unwanted)
		}
	}
}

// TestRunWaitsForKey: with the converge key absent (secret not yet
// synced — the DS mounts it optional:true) the loop performs no
// dials; once the key materializes the next renew tick converges.
func TestRunWaitsForKey(t *testing.T) {
	dialer := newFakeDialer()
	cfg := testConfig(t, newClientsetWithSecret(), dialer, []byte("bin"))
	cfg.SSHKeyPath = path.Join(t.TempDir(), "key") // absent
	cfg.RenewInterval = 10 * time.Millisecond
	cfg.WatchInterval = time.Hour // keep watcher out of this test
	cfg.SyncInterval = time.Hour
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(dialer.dials()) > 0 {
			t.Fatal("dialed while converge key absent")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The secret lands — next renew tick must pick it up.
	if err := os.WriteFile(cfg.SSHKeyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(dialer.dials()) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no converge after the key materialized")
}

// TestSplitUserHostPort: proxyjump "user@host:port" keeps its port —
// same spec as cli.go's splitJump.
func TestSplitUserHostPort(t *testing.T) {
	user, host, port := splitUserHost("admin@10.0.0.1:2222")
	if user != "admin" || host != "10.0.0.1" || port != "2222" {
		t.Fatalf("splitUserHost(admin@10.0.0.1:2222)=%q,%q,%q", user, host, port)
	}
	user, host, port = splitUserHost("10.0.0.1")
	if user != "root" || host != "10.0.0.1" || port != "" {
		t.Fatalf("splitUserHost(10.0.0.1)=%q,%q,%q", user, host, port)
	}
	user, host, port = splitUserHost("ops@bastion")
	if user != "ops" || host != "bastion" || port != "" {
		t.Fatalf("splitUserHost(ops@bastion)=%q,%q,%q", user, host, port)
	}
}

// TestSystemdUnitContent: the rendered unit carries the standalone
// ExecStart and the env wiring the DaemonSet env block provides
// in-cluster.
func TestSystemdUnitContent(t *testing.T) {
	u := systemdUnit(Target{Name: "db-vm"},
		"/usr/local/bin/node-host-agent",
		"/etc/node-host-agent/vars", "/etc/node-host-agent/nebula-certs")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/node-host-agent --standalone --node-name=db-vm --health-probe-bind-address=:8091",
		"Environment=NODE_HOST_AGENT_HOST_ROOT=/",
		"Environment=NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR=/etc/node-host-agent/vars",
		"Environment=NODE_HOST_AGENT_NEBULA_CERTS_DIR=/etc/node-host-agent/nebula-certs",
		"Type=simple",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q:\n%s", want, u)
		}
	}
}
