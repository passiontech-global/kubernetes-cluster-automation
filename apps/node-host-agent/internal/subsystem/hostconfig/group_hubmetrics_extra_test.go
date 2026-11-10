// group_hubmetrics_extra_test.go — hub-metrics-fw failure arms: the
// node_exporter deb install failing counts but does not abort the
// firewall converge, and the allow-list tolerates scalar registry
// entries.
package hostconfig

import (
	"fmt"
	"strings"
	"testing"
)

// TestHubMetricsDebInstallFailureCounts — pinned install where
// apt-get fails: counted once, the unit/nft converge continues (the
// deb failure must not skip the firewall).
func TestHubMetricsDebInstallFailureCounts(t *testing.T) {
	deb := []byte("!<arch>\ndebian-binary\n")
	url, sum := rawServer(t, deb)
	cluster := fmt.Sprintf(`interdc_nexp_version: "1.8.2"
interdc_nexp_deb_url: %q
interdc_nexp_deb_sha256: %q
interdc_nexp_deb_file: "node-exporter.deb"
`, url, sum)
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	sr.FailOn("apt-get install -y /tmp/node-exporter.deb", nil)
	r, err := New(Config{NodeName: "hub-vm", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "hub-vm")
	c.groupHubMetricsFW()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want exactly the deb install failure", c.errs)
	}
	// The firewall converge still ran.
	if !hostExists(r, "/etc/systemd/system/prometheus-node-exporter.service.d/textfile.conf") {
		t.Fatal("textfile drop-in not converged despite the deb failure")
	}
}

// TestHubMetricsScriptScalarNode — a scalar (non-mapping) registry
// entry is skipped when collecting the whitelist IPs; the script
// still renders with the remaining mesh IPs.
func TestHubMetricsScriptScalarNode(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c: gateway-vm
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "hub-vm", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "hub-vm")
	script := c.hubMetricsScript()
	if script == "" {
		t.Fatal("hub metrics script skipped although the vars are safe")
	}
	for _, want := range []string{"10.0.1.10", "10.0.2.20", "172.29.0.0/24"} {
		if !strings.Contains(script, want) {
			t.Fatalf("whitelist script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "gateway-vm") {
		t.Fatal("scalar registry entry leaked into the script")
	}
	if c.errs != 0 {
		t.Fatalf("scalar node counted errors: %d", c.errs)
	}
}
