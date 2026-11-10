// signpaths_test.go — the buildSignJobs registry-edge derivations
// and the nebulaSign/signAll error ladder the happy-path suite
// doesn't reach: missing registry fields, cert-name traversal
// guard, per-stage nebula-cert failures and unwritable output.
package nebulasign

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// writeVarsFiles lays out a vars dir from raw file contents — full
// control over which defaults exist (the fixed varsFixture always
// provides interdc_ssh_default_user, which the root-fallback edge
// needs absent).
func writeVarsFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadTopo(t *testing.T, varsDir string) *topology.Topology {
	t.Helper()
	topo, err := topology.Load(topology.Config{VarsDir: varsDir})
	if err != nil {
		t.Fatalf("topology.Load: %v", err)
	}
	return topo
}

// TestBuildSignJobsUserAndNameFallbacks: the ssh chain's by-site
// lookup, the root default when no default user is configured, the
// registry-key name fallback, and a non-mapping registry entry
// skipped silently.
func TestBuildSignJobsUserAndNameFallbacks(t *testing.T) {
	varsDir := writeVarsFiles(t, map[string]string{
		"defaults.yaml": "interdc_nebula_enabled: true\n",
		"cluster.yaml":  "interdc_ssh_user_by_site:\n  lanit: alice\n",
		"interdc_nodes.yaml": `by-site:
  name: by-site
  ip: 10.0.0.5
  marker_octet: 5
  site: lanit
noname:
  ip: 10.0.0.6
  marker_octet: 6
weird: plain-string
`,
	})
	jobs, err := buildSignJobs(loadTopo(t, varsDir), "")
	if err != nil {
		t.Fatalf("buildSignJobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("jobs=%d want 2 (non-mapping entry skipped)", len(jobs))
	}
	if jobs[0].SSHUser != "alice" {
		t.Fatalf("by-site user=%q want site-map alice", jobs[0].SSHUser)
	}
	// No interdc_ssh_default_user anywhere → the root fallback.
	if jobs[1].Name != "noname" || jobs[1].SSHUser != "root" {
		t.Fatalf("noname job=%+v", jobs[1])
	}
}

// TestBuildSignJobsRejectsPathTraversal: a cert name carrying '../'
// would path-traverse out of <varsDir>/nebula-<name>.crt.
func TestBuildSignJobsRejectsPathTraversal(t *testing.T) {
	varsDir := writeVarsFiles(t, map[string]string{
		"defaults.yaml": "",
		"cluster.yaml":  "interdc_ssh_default_user: admin\n",
		"interdc_nodes.yaml": `evil:
  name: "../escape"
  ip: 10.0.0.7
  marker_octet: 7
  nebula_key: UHViQQ==
`,
	})
	_, err := buildSignJobs(loadTopo(t, varsDir), "")
	if err == nil || !strings.Contains(err.Error(),
		"must not contain path separators") {
		t.Fatalf("err=%v", err)
	}
}

// TestBuildSignJobsReportsMissingFields: nodes missing ip and/or
// marker_octet are reported together, per node, before any signing.
func TestBuildSignJobsReportsMissingFields(t *testing.T) {
	varsDir := writeVarsFiles(t, map[string]string{
		"defaults.yaml": "",
		"cluster.yaml":  "interdc_ssh_default_user: admin\n",
		"interdc_nodes.yaml": `empty-node:
  name: empty-node
ip-only:
  name: ip-only
  marker_octet: 8
`,
	})
	_, err := buildSignJobs(loadTopo(t, varsDir), "")
	if err == nil || !strings.Contains(err.Error(),
		"empty-node (missing ip, marker_octet), ip-only (missing ip)") {
		t.Fatalf("err=%v", err)
	}
}

// TestNebulaSignStageErrors: the pre-flight gates in order — a CA
// dir missing ca.crt, an unreadable vars dir, and a registry with
// missing node fields each fail with their specific wording.
func TestNebulaSignStageErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("PATH", filepath.Dir(fakeCertScript(t, false))+
		string(os.PathListSeparator)+os.Getenv("PATH"))

	// CA dir without ca.crt — the backup/ gitignore wording.
	err := nebulaSign(ctx, signConfig{CaDir: t.TempDir(),
		VarsDir: varsFixture(t, "", "")})
	if err == nil || !strings.Contains(err.Error(), "missing ca.crt in") {
		t.Fatalf("no ca.crt err=%v", err)
	}

	// Unreadable vars dir.
	err = nebulaSign(ctx, signConfig{CaDir: caFixture(t),
		VarsDir: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "load vars") {
		t.Fatalf("bad vars err=%v", err)
	}

	// Registry missing required node fields.
	bad := writeVarsFiles(t, map[string]string{
		"defaults.yaml": "",
		"cluster.yaml":  "interdc_ssh_default_user: admin\n",
		"interdc_nodes.yaml": "empty-node:\n  name: empty-node\n" +
			"ip-only:\n  name: ip-only\n  marker_octet: 8\n",
	})
	err = nebulaSign(ctx, signConfig{CaDir: caFixture(t), VarsDir: bad})
	if err == nil || !strings.Contains(err.Error(),
		"nodes missing required fields") {
		t.Fatalf("bad nodes err=%v", err)
	}
}

// TestCmdSignsRegistryExitsZero: the full dispatch contract on a
// happy path — fake nebula-cert in PATH, complete CA + registry.
func TestCmdSignsRegistryExitsZero(t *testing.T) {
	binDir := filepath.Dir(fakeCertScript(t, false))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	varsDir := varsFixture(t, "", "")
	code := Cmd(context.Background(), []string{
		"--ca-dir", caFixture(t), "--vars-dir", varsDir,
	})
	if code != 0 {
		t.Fatalf("exit=%d want 0", code)
	}
	if b, err := os.ReadFile(filepath.Join(varsDir, "nebula-hub-a.crt")); err != nil ||
		string(b) != "CERTDATA\n" {
		t.Fatalf("crt=%q err=%v", b, err)
	}
}

// TestNebulaSignFetchesMissingPubOverSSH: the composition path — a
// registry node without nebula_key gets its host.pub fetched through
// the ssh_proxyjump bastion, normalized to bare base64, signed, and
// installed at <varsDir>/nebula-<name>.crt.
func TestNebulaSignFetchesMissingPubOverSSH(t *testing.T) {
	final := newSSHTestServer(t, "cat", testPubPEM)
	bastion := newSSHTestServer(t, "cat", "")
	bastion.bridge = final.ln.Addr().String()

	binDir := filepath.Dir(fakeCertScript(t, false))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// jump-node carries no nebula_key — the fetch fallback supplies it.
	jump := "root@127.0.0.1:" + strconv.Itoa(bastion.port())
	varsDir := writeVarsFiles(t, map[string]string{
		"defaults.yaml": "interdc_nebula_enabled: true\n",
		"cluster.yaml":  "interdc_ssh_default_user: root\n",
		"interdc_nodes.yaml": "jump-node:\n  name: jump-node\n" +
			"  ip: 10.0.0.8\n  marker_octet: 8\n  ssh_proxyjump: \"" +
			jump + "\"\n",
	})
	cfg := signConfig{VarsDir: varsDir, CaDir: caFixture(t),
		Duration: "8760h", SSHKey: fetchKey(t)}
	if err := nebulaSign(context.Background(), cfg); err != nil {
		t.Fatalf("nebulaSign: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(varsDir,
		"nebula-jump-node.crt")); err != nil || string(b) != "CERTDATA\n" {
		t.Fatalf("crt=%q err=%v", b, err)
	}
	if cmds := final.commands(); len(cmds) != 1 ||
		cmds[0] != "cat /etc/nebula/interdc/host.pub" {
		t.Fatalf("target commands=%v", cmds)
	}
}

// TestSignAllCancelledCtx: a cancelled context stops the sign loop at
// the next job boundary instead of shelling out.
func TestSignAllCancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := signAll(ctx, fakeCertScript(t, false),
		signConfig{CaDir: caFixture(t), VarsDir: t.TempDir()},
		[]signJob{{Hostname: "hub-a", Name: "hub-a", Pub: "UHViQQ=="}})
	if err == nil {
		t.Fatal("cancelled ctx want error")
	}
}

// fakeCertMode writes a fake nebula-cert that fails per subcommand —
// sign succeeds while verify fails, or nothing is written at all.
func fakeCertMode(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	body := map[string]string{
		// sign writes the crt, verify exits 1.
		"verify-fails": `case "$1" in
  verify) echo 'simulated verify failure' >&2; exit 1 ;;
esac
for i in "$@"; do :; done
prev=""
out=""
for a in "$@"; do
  if [ "$prev" = "-out-crt" ]; then out="$a"; fi
  prev="$a"
done
[ -n "$out" ] && printf 'CERTDATA
' > "$out"
exit 0
`,
		// everything exits 0 but no crt is ever written — the
		// read-after-verify failure.
		"no-crt": "exit 0\n",
	}[mode]
	p := filepath.Join(dir, "nebula-cert")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSignAllStageFailures: per-job staging failures — verify exiting
// non-zero and a verify that succeeds without producing a crt — both
// abort with the job named and the tmp dir cleaned up.
func TestSignAllStageFailures(t *testing.T) {
	cfg := func(varsDir, caDir string) signConfig {
		return signConfig{CaDir: caDir, VarsDir: varsDir, Duration: "8760h"}
	}
	jobs := []signJob{{
		Hostname: "hub-a", Name: "hub-a",
		IPCIDR: "172.29.0.3/24", Subnets: "10.0.0.1/32", Pub: "UHViQQ==",
	}}

	t.Run("verify fails", func(t *testing.T) {
		varsDir := t.TempDir()
		err := signAll(context.Background(),
			fakeCertMode(t, "verify-fails"), cfg(varsDir, caFixture(t)), jobs)
		if err == nil || !strings.Contains(err.Error(),
			"hub-a: nebula-cert verify") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("crt missing after verify", func(t *testing.T) {
		varsDir := t.TempDir()
		err := signAll(context.Background(),
			fakeCertMode(t, "no-crt"), cfg(varsDir, caFixture(t)), jobs)
		if err == nil || !strings.Contains(err.Error(),
			"hub-a: open") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("tmp dir creation fails", func(t *testing.T) {
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
		err := signAll(context.Background(),
			fakeCertScript(t, false),
			cfg(t.TempDir(), caFixture(t)), jobs)
		if err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("vars dir unwritable", func(t *testing.T) {
		varsDir := t.TempDir()
		if err := os.Chmod(varsDir, 0o555); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(varsDir, 0o755) }()
		err := signAll(context.Background(),
			fakeCertScript(t, false), cfg(varsDir, caFixture(t)), jobs)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("err=%v", err)
		}
	})
}
