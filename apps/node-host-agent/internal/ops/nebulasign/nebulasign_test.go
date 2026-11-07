package nebulasign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// --- sign-job derivation + pubkey normalization ---

func TestStripPubArmor(t *testing.T) {
	bare := "QUJDREVGRw=="
	if got := stripPubArmor(bare); got != bare {
		t.Fatalf("bare pubkey mangled: %q", got)
	}
	pem := "-----BEGIN NEBULA X25519 PUBLIC KEY-----\n" + bare +
		"\n-----END NEBULA X25519 PUBLIC KEY-----\n"
	if got := stripPubArmor(pem); got != bare {
		t.Fatalf("PEM strip=%q want %q", got, bare)
	}
	// Multi-line base64 joins.
	multi := "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nQUJD\nREVGRw==\n-----END NEBULA X25519 PUBLIC KEY-----\n"
	if got := stripPubArmor(multi); got != bare {
		t.Fatalf("multiline PEM strip=%q want %q", got, bare)
	}
}

func TestBuildSignJobs(t *testing.T) {
	dir := t.TempDir()
	writeVars := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeVars("defaults.yaml",
		"interdc_nebula_enabled: true\ninterdc_marker_base: \"172.29.0\"\n")
	writeVars("cluster.yaml", "interdc_ssh_default_user: admin\n")
	writeVars("interdc_nodes.yaml", `hub-a:
  name: hub-a
  ip: 10.0.0.1
  marker_octet: 3
  nebula_key: UHViQQ==
  relay:
    - ip: 203.0.113.5
    - 198.51.100.9
node-b:
  name: node-b
  ip: 10.0.0.2
  ssh_user: ops
  ssh_proxyjump: admin@203.0.113.1
`)

	topo, err := topology.Load(topology.Config{VarsDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := buildSignJobs(topo, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("jobs=%d want 2", len(jobs))
	}
	a, b := jobs[0], jobs[1]
	if a.IPCIDR != "172.29.0.3/24" {
		t.Fatalf("hub-a marker=%q want 172.29.0.3/24 (marker_octet)", a.IPCIDR)
	}
	// Subnets: ip/32 + both relay ips/32, unique+sorted+csv.
	if a.Subnets != "10.0.0.1/32,198.51.100.9/32,203.0.113.5/32" {
		t.Fatalf("hub-a subnets=%q", a.Subnets)
	}
	if a.Pub != "UHViQQ==" {
		t.Fatalf("hub-a pub=%q want registry nebula_key", a.Pub)
	}
	// node-b: no marker_octet → last octet of ip; ssh chain resolved.
	if b.IPCIDR != "172.29.0.2/24" {
		t.Fatalf("node-b marker=%q want 172.29.0.2/24", b.IPCIDR)
	}
	if b.SSHUser != "ops" || b.ProxyJump != "admin@203.0.113.1" {
		t.Fatalf("node-b ssh=%q jump=%q", b.SSHUser, b.ProxyJump)
	}
	if b.Pub != "" {
		t.Fatalf("node-b pub=%q want empty (SSH fetch path)", b.Pub)
	}

	// --node filters by registry key.
	jobs, err = buildSignJobs(topo, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Hostname != "node-b" {
		t.Fatalf("--node filter jobs=%v", jobs)
	}
	if _, err := buildSignJobs(topo, "nope"); err == nil {
		t.Fatal("unknown --node want error")
	}
}
