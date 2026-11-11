// group_nld_inet_test.go — the roadmap-1.2 guard upgrades: both nft
// guards on dual-stack `table inet`, the host-internal-ports guard
// tightened off the pod/VLAN wildcard interfaces and the blanket
// RFC1918 allow list, and the completed port coverage (Cilium
// agents, :39901, the NodePort range).
package hostconfig

import (
	"strings"
	"testing"
)

// convergeNLDWithVars builds the fixture, converges groupNLD and
// returns the two deployed rulesets (nodelocaldns, ports guard).
func convergeNLDWithVars(t *testing.T, cluster string) (nldNFT, portsNFT string) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()
	return hostRead(t, r, "/etc/nodelocaldns-guard.nft"),
		hostRead(t, r, "/etc/host-internal-ports-guard.nft")
}

// TestPortsGuardInetTableTightened — the guard must live on
// `table inet` (the v4-only table let every v6 wildcard bind
// through), must NOT carry the blanket pod/VLAN interface accepts
// (cilium*/lxc*/cali* were the tenant-pod path to /debug/pprof,
// kubelet and the exporters) and must NOT inherit the RFC1918
// private allow list that only nodelocaldns :53 needs.
func TestPortsGuardInetTableTightened(t *testing.T) {
	_, portsNFT := convergeNLDWithVars(t, "")
	if !strings.Contains(portsNFT, "table inet host_internal_ports_guard") ||
		strings.Contains(portsNFT, "table ip ") {
		t.Fatalf("ports guard not on the inet table:\n%s", portsNFT)
	}
	for _, iface := range []string{`iifname "cilium*"`, `iifname "lxc*"`, `iifname "cali*"`} {
		if strings.Contains(portsNFT, iface) {
			t.Fatalf("ports guard still opens %s — the tenant-pod path the roadmap closes:\n%s",
				iface, portsNFT)
		}
	}
	// The private ranges belong to the DNS guard only: a blanket
	// 10.0.0.0/8 accept here is the "every pod can reach kubelet" hole.
	if strings.Contains(portsNFT, "10.0.0.0/8") {
		t.Fatalf("ports guard allowlist inherited the RFC1918 private set:\n%s", portsNFT)
	}
	// Cluster sources stay open: loopback + nebula trunk + established
	// flows + the registry node IPs.
	for _, want := range []string{
		`iifname "lo" accept`, `iifname "neb1" accept`,
		"ct state { established, related } accept",
		"10.0.1.10", "10.0.2.20", "10.0.1.30",
	} {
		if !strings.Contains(portsNFT, want) {
			t.Fatalf("ports guard missing cluster-source rule %q:\n%s", want, portsNFT)
		}
	}
}

// TestPortsGuardPortCoverage — the roadmap's previously missing
// listeners must be in the drop set: the node-host-agent probe/SNR
// port, the Cilium hostNetwork agents and the whole NodePort range
// (the lone 30020 the range subsumes must not regress away).
func TestPortsGuardPortCoverage(t *testing.T) {
	_, portsNFT := convergeNLDWithVars(t, "")
	set := portsNFT[strings.Index(portsNFT, "tcp dport {"):]
	for _, want := range []string{
		"39901", "4240", "4244", "9962", "9963", "9964",
		"9100", "9115", "9253", "10248", "10250", "10256", "20256",
		"30000-32767",
	} {
		if !strings.Contains(set, want) {
			t.Fatalf("ports guard drop set missing %q:\n%s", want, portsNFT)
		}
	}
}

// TestPortsGuardAllowExtraVar — the operator-declared
// Prometheus/monitoring sources land in the ports-guard accept set
// (and nowhere else), which is what keeps the guard closed to pods
// while in-cluster scrapes keep working.
func TestPortsGuardAllowExtraVar(t *testing.T) {
	_, portsNFT := convergeNLDWithVars(t,
		"host_internal_ports_guard_allow_extra: [203.0.113.9, fd00:203:0:113::9]\n")
	if !strings.Contains(portsNFT, "ip saddr { 10.0.1.10, 10.0.1.30, 10.0.2.20, 203.0.113.9 } accept") {
		t.Fatalf("ports guard v4 accept set missing the monitoring IP:\n%s", portsNFT)
	}
	if !strings.Contains(portsNFT, "ip6 saddr { fd00:203:0:113::9 } accept") {
		t.Fatalf("ports guard v6 accept set missing the monitoring v6:\n%s", portsNFT)
	}
}

// TestPortsGuardIPv6RegistryNode — a registry node carrying ip6
// must be allowlisted in the v6 family set (the inet upgrade's
// point: cluster v6 sources stay open, everything else v6 drops);
// a v4-only registry renders no v6 accept rule at all (an empty
// set literal is invalid nft).
func TestPortsGuardIPv6RegistryNode(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  ip6: fd00:10:0:1::10
  site: s1
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()
	portsNFT := hostRead(t, r, "/etc/host-internal-ports-guard.nft")
	if !strings.Contains(portsNFT, "ip6 saddr { fd00:10:0:1::10 } accept") {
		t.Fatalf("ports guard v6 accept set missing the registry ip6:\n%s", portsNFT)
	}
	if !strings.Contains(portsNFT, "ip saddr { 10.0.1.10, 10.0.1.30, 10.0.2.20 } accept") {
		t.Fatalf("ports guard v4 accept set missing the registry ips:\n%s", portsNFT)
	}
}

// TestNLDGuardInetScopedAccepts — the DNS guard rides `table inet`
// with family-scoped, :53-gated accepts (cluster sources beat the
// drops; anything else on ANY family falls to the drops) and its
// allow list keeps the RFC1918 private ranges pods need for
// node-local-dns.
func TestNLDGuardInetScopedAccepts(t *testing.T) {
	nldNFT, _ := convergeNLDWithVars(t, "")
	if !strings.Contains(nldNFT, "table inet nodelocaldns_guard") {
		t.Fatalf("nodelocaldns guard not on the inet table:\n%s", nldNFT)
	}
	if !strings.Contains(nldNFT, "ip saddr { 10.0.0.0/8, 10.0.1.10, 10.0.1.30, 10.0.2.20 } tcp dport 53 accept") {
		t.Fatalf("nld guard missing the scoped v4 accept:\n%s", nldNFT)
	}
	if !strings.Contains(nldNFT, "udp dport 53 accept") {
		t.Fatalf("nld guard missing the UDP accept:\n%s", nldNFT)
	}
	// The old blanket shape — an accept with NO dport gate — must be
	// gone even though the saddr set is the same.
	if strings.Contains(nldNFT, "} accept\n") {
		t.Fatalf("nld guard carries an unscoped accept:\n%s", nldNFT)
	}
	for _, want := range []string{"tcp dport 53 drop", "udp dport 53 drop"} {
		if !strings.Contains(nldNFT, want) {
			t.Fatalf("nld guard missing %q:\n%s", want, nldNFT)
		}
	}
}

// TestSplitAddrFamilies — the family split is the colon literal's
// presence (bare v6 and v6 prefixes both), with unparseable
// entries kept verbatim in the v4 half for nft -c to judge.
func TestSplitAddrFamilies(t *testing.T) {
	v4, v6 := splitAddrFamilies([]string{
		"10.0.0.0/8", "fd00::/64", "fd00::9", "203.0.113.9", "gateway.internal",
	})
	wantV4 := []string{"10.0.0.0/8", "203.0.113.9", "gateway.internal"}
	wantV6 := []string{"fd00::/64", "fd00::9"}
	if strings.Join(v4, ",") != strings.Join(wantV4, ",") ||
		strings.Join(v6, ",") != strings.Join(wantV6, ",") {
		t.Fatalf("splitAddrFamilies = %v, %v; want %v, %v", v4, v6, wantV4, wantV6)
	}
}
