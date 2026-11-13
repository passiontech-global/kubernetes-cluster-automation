// group_bwaudit_test.go — T11: the counter-only inet nft table
// renders per-peer in/out counters from the bw-audit derivation,
// deploys through the nft -c candidate gate, and sweeps the invented
// first-port unit; disabled nebula converges nothing.
package hostconfig

import (
	"strings"
	"testing"
)

// TestBwAuditRulesetRendersPeers — every registry peer (public ip +
// marker, deduped relays) gets an in- and out-counter rule.
func TestBwAuditRulesetRendersPeers(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupBwAudit()

	nft := hostRead(t, r, "/etc/interdc-acct.nft")
	for _, want := range []string{
		"destroy table inet interdc_acct",
		"table inet interdc_acct {",
		"policy accept;",
		`10.0.1.10 counter comment "a in-neb"`,
		`10.0.1.10 counter comment "a out-neb"`,
		`172.29.0.10 counter comment "a-marker in-neb"`,
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("bw-audit ruleset missing %q:\n%s", want, nft)
		}
	}
	if len(sr.CallsMatching("nft -c -f /etc/interdc-acct.nft")) == 0 {
		t.Fatal("ruleset not validated via nft -c before promotion")
	}
	// The invented first-port deployment is swept.
	if len(sr.CallsMatching("systemctl disable --now interdc-bw-audit.service")) == 0 {
		t.Fatal("interdc-bw-audit.service not disabled")
	}
	if hostExists(r, "/etc/systemd/system/interdc-bw-audit.service") ||
		hostExists(r, "/etc/nftables.d/interdc-bw-audit.nft") {
		t.Fatal("first-port unit/ruleset files not swept")
	}
	if c.errs != 0 {
		t.Fatalf("happy bw-audit converge counted errors: %d", c.errs)
	}
}

// TestBwAuditSkipsWhenDisabled — no nebula, no accounting table.
func TestBwAuditSkipsWhenDisabled(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_enabled: false\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupBwAudit()
	if hostExists(r, "/etc/interdc-acct.nft") {
		t.Fatal("bw-audit table deployed with nebula disabled")
	}
}
