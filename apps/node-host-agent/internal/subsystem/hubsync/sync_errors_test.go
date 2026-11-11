// sync_errors_test.go — the converge error ladder the happy-path
// suite can't reach: every stage of syncTarget/prepareHost/syncDir/
// pruneRemoteDir failing over the Conn seam, plus the Cycle abort
// paths (binary-hash failure, parse notes) and the convergeTargets
// split-brain guards.
package hubsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// failConn delegates to a seeded fakeConn but fails the ops whose
// command matches a fail entry (substring, checked before the
// emulation) and Write wholesale when writeErr is set — the fault
// injection that drives syncTarget to each of its error returns.
type failConn struct {
	*fakeConn
	fail     map[string]string
	passOn   map[string]string // cmd substring → canned success output
	writeErr error
}

func (f *failConn) Run(ctx context.Context, cmd string) (string, error) {
	f.mu.Lock()
	f.ops = append(f.ops, "run:"+cmd)
	f.mu.Unlock()
	for sub, out := range f.passOn {
		if strings.Contains(cmd, sub) {
			return out, nil
		}
	}
	for sub, msg := range f.fail {
		if strings.Contains(cmd, sub) {
			return "", errors.New(msg)
		}
	}
	return f.fakeConn.Run(ctx, cmd)
}

func (f *failConn) Write(ctx context.Context, remotePath string, r io.Reader) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.fakeConn.Write(ctx, remotePath, r)
}

// fnDialer hands out a per-dial Conn built by fn — each error case
// gets a fresh conn whose failure hook matches the stage under test.
type fnDialer struct{ fn func(Target) (Conn, error) }

func (d fnDialer) Dial(ctx context.Context, t Target) (Conn, error) {
	return d.fn(t)
}

// ladderSyncer builds a Syncer wired to the fixtures (secret-bearing
// clientset, scratch binary + key) with the dialer swapped per case.
func ladderSyncer(t *testing.T) *Syncer {
	t.Helper()
	s, err := New(testConfig(t, newClientsetWithSecret(), newFakeDialer(),
		[]byte("fake-agent-binary-v1")), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPrepareHostErrorLadder: the preamble's vars mkdir, the role's
// extra dir mkdir and its chmod each propagate as-is.
func TestPrepareHostErrorLadder(t *testing.T) {
	cfg := Config{RemoteVarsDir: "/etc/node-host-agent/vars",
		RemoteCertsDir: "/etc/node-host-agent/nebula-certs",
		GuardDir:       "/etc/api-backend-guard"}
	mk := func(fail map[string]string) *failConn {
		return &failConn{fakeConn: newFakeConn(), fail: fail}
	}
	ctx := context.Background()

	err := prepareHost(ctx, mk(map[string]string{
		"mkdir -p '/etc/node-host-agent/vars'": "boom:vars-mkdir",
	}), cfg, Target{}, roleProfile{})
	if err == nil || !strings.Contains(err.Error(), "boom:vars-mkdir") {
		t.Fatalf("vars mkdir err=%v", err)
	}

	err = prepareHost(ctx, mk(map[string]string{
		"mkdir -p '/etc/node-host-agent/nebula-certs'": "boom:certs-mkdir",
	}), cfg, Target{InterDC: true},
		roleProfile{dirs: []remoteDir{{path: cfg.RemoteCertsDir}}})
	if err == nil || !strings.Contains(err.Error(), "boom:certs-mkdir") {
		t.Fatalf("role mkdir err=%v", err)
	}

	err = prepareHost(ctx, mk(map[string]string{
		"chmod 0700 '/etc/api-backend-guard'": "boom:guard-chmod",
	}), cfg, Target{APILB: true},
		roleProfile{dirs: []remoteDir{{path: cfg.GuardDir, mode: "0700"}}})
	if err == nil || !strings.Contains(err.Error(), "boom:guard-chmod") {
		t.Fatalf("role chmod err=%v", err)
	}
}

// TestSyncTargetErrorLadder: one case per unguarded `return err` in
// syncTarget — the hook that fires names the stage, so a wrong
// unwinding order fails the assertion.
func TestSyncTargetErrorLadder(t *testing.T) {
	const unit = "/etc/systemd/system/node-host-agent.service"
	const remoteBin = "/usr/local/bin/node-host-agent"
	binSumArr := sha256.Sum256([]byte("fake-agent-binary-v1"))
	binSum := hex.EncodeToString(binSumArr[:])

	cases := []struct {
		name     string
		target   Target
		localSum string
		noBinary bool // point cfg.LocalBinary at a missing file
		seed     func(c *failConn)
		fail     map[string]string
		wantErr  string
	}{
		{
			name:    "prepareHost failure surfaces",
			fail:    map[string]string{"mkdir -p '/etc/node-host-agent/vars'": "boom:336"},
			wantErr: "boom:336",
		},
		{
			name: "binary sha256 transport error",
			// Path-only key: the binary hashes inside the batched
			// binary+unit sha256sum session, so the "sha256sum "
			// prefix may not sit directly before the path.
			fail:    map[string]string{"'" + remoteBin + "'": "boom:341"},
			wantErr: "boom:341",
		},
		{
			name:     "empty localSum re-hash of missing binary",
			noBinary: true,
			seed:     func(c *failConn) { c.seedFile(remoteBin, []byte("remote")) },
			wantErr:  "no such file",
		},
		{
			name:     "binary open failure on drift",
			noBinary: true,
			localSum: "stale",
			wantErr:  "no such file",
		},
		{
			name:     "binary putAtomic mv failure",
			localSum: "stale",
			fail:     map[string]string{"mv '/usr/local/bin/.node-host-agent.tmp'": "boom:367"},
			wantErr:  "boom:367",
		},
		{
			name:    "vars mirror upload failure",
			fail:    map[string]string{"'/etc/node-host-agent/vars/cluster.yaml'": "boom:371"},
			wantErr: "boom:371",
		},
		{
			name:   "certs mirror upload failure",
			target: Target{InterDC: true},
			fail: map[string]string{
				"'/etc/node-host-agent/nebula-certs/nebula-ca.crt'": "boom:378",
			},
			wantErr: "boom:378",
		},
		{
			name:   "guard token failure",
			target: Target{APILB: true},
			fail: map[string]string{
				"sha256sum '/etc/api-backend-guard/token'": "boom:378",
			},
			wantErr: "boom:378",
		},
		{
			name:   "guard ca.crt failure",
			target: Target{APILB: true},
			fail: map[string]string{
				"sha256sum '/etc/api-backend-guard/ca.crt'": "boom:381",
			},
			wantErr: "boom:381",
		},
		{
			name:     "unit sha256 transport error",
			seed:     func(c *failConn) { c.seedFile(remoteBin, []byte("fake-agent-binary-v1")) },
			localSum: binSum,
			// Path-only key: the unit hashes inside the batched
			// binary+unit sha256sum session, so the "sha256sum "
			// prefix may not sit directly before the path.
			fail:    map[string]string{"'" + unit + "'": "boom:393"},
			wantErr: "boom:393",
		},
		{
			name:     "unit putAtomic mv failure",
			seed:     func(c *failConn) { c.seedFile(remoteBin, []byte("fake-agent-binary-v1")) },
			localSum: binSum,
			fail:     map[string]string{"mv '/etc/systemd/system/.node-host-agent.service.tmp'": "boom:401"},
			wantErr:  "boom:401",
		},
		{
			name:     "daemon-reload failure",
			seed:     func(c *failConn) { c.seedFile(remoteBin, []byte("fake-agent-binary-v1")) },
			localSum: binSum,
			fail:     map[string]string{"systemctl daemon-reload": "boom:406"},
			wantErr:  "boom:406",
		},
		{
			name:     "enable failure after binary update",
			localSum: "stale", // binary drift → restart branch
			fail:     map[string]string{"systemctl enable '": "boom:412"},
			wantErr:  "boom:412",
		},
		{
			name:     "restart failure after binary update",
			localSum: "stale",
			fail:     map[string]string{"systemctl restart '": "boom:415"},
			wantErr:  "boom:415",
		},
		{
			name:     "enable --now failure on fresh host",
			seed:     func(c *failConn) { c.seedFile(remoteBin, []byte("fake-agent-binary-v1")) },
			localSum: binSum,
			fail:     map[string]string{"systemctl enable --now '": "boom:421"},
			wantErr:  "boom:421",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ladderSyncer(t)
			if tc.noBinary {
				s.cfg.LocalBinary = filepath.Join(t.TempDir(), "missing-bin")
			}
			fc := &failConn{fakeConn: newFakeConn(), fail: tc.fail}
			if tc.seed != nil {
				tc.seed(fc)
			}
			s.dialer = fnDialer{fn: func(Target) (Conn, error) { return fc, nil }}
			err := s.syncTarget(context.Background(), tc.target,
				[]byte("guard-token-value"), []byte("guard-ca-pem"), tc.localSum)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("syncTarget err=%v want %q", err, tc.wantErr)
			}
		})
	}
}

// TestSyncDirLocalErrors: an unreadable local dir, hidden-file skip,
// an undecodable (dangling-symlink) entry and a failing upload each
// behave per the mirror contract.
func TestSyncDirLocalErrors(t *testing.T) {
	ctx := context.Background()
	s := ladderSyncer(t)

	if err := s.syncDir(ctx, newFakeConn(), "/nonexistent-dir", "/remote",
		"0644", nil); err == nil {
		t.Fatal("missing local dir want error")
	}

	// Hidden entries are skipped, not mirrored.
	hidden := t.TempDir()
	if err := os.WriteFile(filepath.Join(hidden, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hidden, ".hidden"), []byte("h"), 0o644); err != nil {
		t.Fatal(err)
	}
	fc := newFakeConn()
	if err := s.syncDir(ctx, fc, hidden, "/remote", "0644", nil); err != nil {
		t.Fatalf("hidden skip: %v", err)
	}
	for _, op := range fc.opsLog() {
		if strings.Contains(op, ".hidden") {
			t.Fatalf("hidden file mirrored: %v", fc.opsLog())
		}
	}

	// A dangling symlink reads as a regular entry, then fails ReadDir's
	// ReadFile half — surfaced, not silently skipped.
	dangling := t.TempDir()
	if err := os.Symlink("../gone", filepath.Join(dangling, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := s.syncDir(ctx, newFakeConn(), dangling, "/remote", "0644", nil); err == nil {
		t.Fatal("dangling symlink want error")
	}

	// A failing sha256sum on the mirror's batched hash session
	// aborts the mirror loop (path-only key — the path may sit
	// anywhere in the batched command).
	up := &failConn{fakeConn: newFakeConn(),
		fail: map[string]string{"'/remote/a.txt'": "boom:485"}}
	if err := s.syncDir(ctx, up, hidden, "/remote", "0644", nil); err == nil ||
		!strings.Contains(err.Error(), "boom:485") {
		t.Fatalf("upload failure err=%v", err)
	}
}

// TestPruneRemoteDirErrors: a failing ls and a failing stale rm both
// abort the prune with the scoped wording.
func TestPruneRemoteDirErrors(t *testing.T) {
	ctx := context.Background()
	s := ladderSyncer(t)

	ls := &failConn{fakeConn: newFakeConn(),
		fail: map[string]string{"ls -1pA '/remote'": "boom:ls"}}
	if err := s.pruneRemoteDir(ctx, ls, "/remote", []string{"a.txt"}); err == nil ||
		!strings.Contains(err.Error(), "ls /remote") {
		t.Fatalf("ls failure err=%v", err)
	}

	rm := &failConn{fakeConn: newFakeConn(),
		fail: map[string]string{"rm -f '/remote/stale.txt'": "boom:rm"}}
	rm.seedFile("/remote/a.txt", []byte("a"))
	rm.seedFile("/remote/stale.txt", []byte("gone"))
	if err := s.pruneRemoteDir(ctx, rm, "/remote", []string{"a.txt"}); err == nil ||
		!strings.Contains(err.Error(), "rm stale /remote/stale.txt") {
		t.Fatalf("rm failure err=%v", err)
	}
}

// TestConvergeTargetsAbortGuards: a cancelled ctx and a lapsed lease
// both abort the loop before the first dial with complete=false.
func TestConvergeTargetsAbortGuards(t *testing.T) {
	s := ladderSyncer(t)
	dialer := newFakeDialer()
	s.dialer = dialer
	targets := []Target{{Name: "t1", IP: "10.9.0.1"}, {Name: "t2", IP: "10.9.0.2"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, sk, f, complete := s.convergeTargets(ctx, targets, nil, nil, "sum", true)
	if c != 0 || sk != 0 || f != 0 || complete {
		t.Fatalf("cancelled ctx tally=%d/%d/%d complete=%v", c, sk, f, complete)
	}

	// A held-but-lapsed lease reads as lost — the split-brain guard.
	holdLease(s)
	s.mu.Lock()
	s.leaseExpiresAt = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	c, sk, f, complete = s.convergeTargets(context.Background(), targets,
		nil, nil, "sum", true)
	if c != 0 || complete {
		t.Fatalf("lapsed lease tally=%d complete=%v", c, complete)
	}
	if dials := dialer.dials(); len(dials) != 0 {
		t.Fatalf("dials after abort: %v", dials)
	}
}

// TestGuardCredsMissingData: a secret that exists but lacks the keys
// is an error, not a silent empty push.
func TestGuardCredsMissingData(t *testing.T) {
	s := ladderSyncer(t) // clientset carries token + ca.crt
	if _, _, err := s.guardCreds(context.Background()); err != nil {
		t.Fatalf("complete secret err=%v", err)
	}

	empty := newClientsetWithSecret()
	s.cfg.Client = empty
	// Strip the secret's token to the ca.crt-only shape.
	sec, err := empty.CoreV1().Secrets("kube-system").
		Get(context.Background(), "api-backend-guard-token", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	delete(sec.Data, "token")
	if _, err := empty.CoreV1().Secrets("kube-system").
		Update(context.Background(), sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.guardCreds(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "missing token/ca.crt data") {
		t.Fatalf("stripped secret err=%v", err)
	}
}

// TestCycleBinaryHashAbort: a local-binary hash failure aborts the
// whole cycle — error counter, every last-known target driven down,
// no dials.
func TestCycleBinaryHashAbort(t *testing.T) {
	reg := prometheus.NewRegistry()
	s, err := New(testConfig(t, newClientsetWithSecret(), newFakeDialer(),
		[]byte("bin")), reg)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.LocalBinary = filepath.Join(t.TempDir(), "missing-bin")
	s.lastTargets = []string{"ghost"}
	holdLease(s)

	s.Cycle(context.Background())

	cycles := gatherVec(t, reg, "node_host_agent_hubsync_cycles_total")
	if cycles[labelKey("target", "all", "result", "error")] != 1 {
		t.Fatalf("cycles=%v want all/error=1", cycles)
	}
	up := gatherVec(t, reg, "node_host_agent_hubsync_target_up")
	if up[labelKey("target", "ghost")] != 0 {
		t.Fatalf("target_up=%v want ghost=0", up)
	}
}

// TestCycleParseNoteStillConverges: a non-fatal resolution note (a
// non-mapping dns-zone file) meters parse_note but the resolved
// targets still converge.
func TestCycleParseNoteStillConverges(t *testing.T) {
	varsDir := t.TempDir()
	for name, content := range map[string]string{
		"defaults.yaml": "interdc_nebula_enabled: true\n",
		"cluster.yaml": "interdc_ssh_default_user: root\n" +
			"node_exporter_extra_hosts: []\napi_lb_guard_vms: []\n",
		"interdc_nodes.yaml": "hubz:\n  agent: false\n  ip: 10.5.0.1\n" +
			"  marker_octet: 3\n",
		"interdc_dns_zone.yaml": "- zone-list-not-a-mapping\n",
	} {
		if err := os.WriteFile(filepath.Join(varsDir, name),
			[]byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dialer := newFakeDialer()
	cfg := testConfig(t, newClientsetWithSecret(), dialer, []byte("bin"))
	cfg.VarsDir = varsDir
	cfg.NebulaCertsDir = "testdata/nebula-certs"
	reg := prometheus.NewRegistry()
	s, err := New(cfg, reg)
	if err != nil {
		t.Fatal(err)
	}
	holdLease(s)
	s.Cycle(context.Background())

	cycles := gatherVec(t, reg, "node_host_agent_hubsync_cycles_total")
	if cycles[labelKey("target", "all", "result", "parse_note")] != 1 {
		t.Fatalf("cycles=%v want all/parse_note=1", cycles)
	}
	up := gatherVec(t, reg, "node_host_agent_hubsync_target_up")
	if up[labelKey("target", "hubz")] != 1 {
		t.Fatalf("target_up=%v want hubz=1", up)
	}
	if dials := dialer.dials(); len(dials) != 1 || dials[0] != "10.5.0.1" {
		t.Fatalf("dials=%v", dials)
	}
}

// TestRemoteSHA256MalformedOutput: a sha256sum that exits 0 with no
// fields reads as "" (drift) — the hash gate re-uploads rather than
// trusting a garbage sum.
func TestRemoteSHA256MalformedOutput(t *testing.T) {
	fc := &failConn{fakeConn: newFakeConn(),
		passOn: map[string]string{"sha256sum '/f'": ""}}
	sum, err := remoteSHA256(context.Background(), fc, "/f")
	if err != nil || sum != "" {
		t.Fatalf("sum=%q err=%v want empty drift", sum, err)
	}
}

// TestRemoteSHA256TransportError: a non-exit-1 failure (denied exec,
// missing tool) propagates — treating it as "absent" would re-upload
// every cycle.
func TestRemoteSHA256TransportError(t *testing.T) {
	fc := &failConn{fakeConn: newFakeConn(),
		fail: map[string]string{"sha256sum '/f'": "boom:sha"}}
	if _, err := remoteSHA256(context.Background(), fc, "/f"); err == nil ||
		!strings.Contains(err.Error(), "boom:sha") {
		t.Fatalf("err=%v", err)
	}
}

// TestPutAtomicErrorLadder: each staging step (install for secret
// material, the upload, chmod, fsync, mv) surfaces its failure with
// the staged path named.
func TestPutAtomicErrorLadder(t *testing.T) {
	ctx := context.Background()
	payload := strings.NewReader("secret")

	t.Run("install failure", func(t *testing.T) {
		fc := &failConn{fakeConn: newFakeConn(),
			fail: map[string]string{"install -m 600": "boom:install"}}
		err := putAtomic(ctx, fc, "/sec/token", payload, "0600")
		if err == nil || !strings.Contains(err.Error(),
			"install /sec/.token.tmp") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("upload failure", func(t *testing.T) {
		fc := &failConn{fakeConn: newFakeConn(), writeErr: errors.New("boom:write")}
		err := putAtomic(ctx, fc, "/dst/a", payload, "0755")
		if err == nil || !strings.Contains(err.Error(), "upload /dst/.a.tmp") {
			t.Fatalf("err=%v", err)
		}
	})

	for _, tc := range []struct {
		name, remote, hook, want string
	}{
		{"chmod failure", "/dst/b", "chmod 0755 '/dst/.b.tmp'", "chmod /dst/.b.tmp"},
		{"fsync failure", "/dst/c", "sync '/dst/.c.tmp'", "sync /dst/.c.tmp"},
		{"mv failure", "/dst/d", "mv '/dst/.d.tmp'", "mv /dst/d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &failConn{fakeConn: newFakeConn(),
				fail: map[string]string{tc.hook: "boom"}}
			err := putAtomic(ctx, fc, tc.remote, payload, "0755")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}
