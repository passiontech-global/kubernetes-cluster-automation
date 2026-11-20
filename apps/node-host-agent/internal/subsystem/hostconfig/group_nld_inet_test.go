// group_nld_inet_test.go — the roadmap-1.2 guard upgrades: both nft
// guards on dual-stack `table inet`, the host-internal-ports guard
// tightened off the pod/VLAN wildcard interfaces and the blanket
// RFC1918 allow list, and the completed port coverage (Cilium
// agents, :39901, the NodePort range).
package hostconfig

import (
	"fmt"
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
	nldNFT, portsNFT := convergeNLDWithVars(t, "")
	if !strings.Contains(nldNFT, "destroy table ip nodelocaldns_guard") ||
		!strings.Contains(portsNFT, "destroy table ip host_internal_ports_guard") {
		t.Fatalf("missing legacy table ip destroy lines:\nnld:\n%s\nports:\n%s", nldNFT, portsNFT)
	}
	if !strings.Contains(portsNFT, "table inet host_internal_ports_guard") ||
		strings.Contains(portsNFT, "\ntable ip ") {
		t.Fatalf("ports guard not on the inet table:\n%s", portsNFT)
	}
	// The blanket pod/VLAN accepts must stay gone — the ONLY pod-iface
	// rules allowed are the dport-scoped exemptions (pod veths AND the
	// CNI tunnel devices pods legitimately arrive on).
	for _, iface := range hostPortsGuardPodIFaces {
		for line := range strings.SplitSeq(portsNFT, "\n") {
			if strings.Contains(line, fmt.Sprintf("iifname %q", iface)) && !strings.Contains(line, "tcp dport") {
				t.Fatalf("ports guard still opens %s unscoped — the tenant-pod path the roadmap closes:\n%s",
					iface, portsNFT)
			}
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

// TestPortsGuardPodExemptPorts — three internal ports must still
// answer pod-originated LOCAL-delivery traffic over the pod-veth
// wildcards and the CNI tunnel interfaces: :4240 (the Cilium agent's
// mesh health endpoint — cluster probes must reach it or the mesh
// reports every node dark), :4244 (the hubble-peer Service pins
// internalTrafficPolicy: Local) and :10250 (the kubelet API —
// konnectivity-agent pods carry the apiserver→kubelet dial and
// hairpin it to the SAME node's public IP, landing on a pod-veth
// iif; incident 2026-11-14 cicd). Remote delivery already traverses
// the nebula dev, so the exemptions open nothing the overlay did not
// expose — while every other internal port stays closed to tenant
// pods.
func TestPortsGuardPodExemptPorts(t *testing.T) {
	_, portsNFT := convergeNLDWithVars(t, "")
	for _, p := range hostPortsGuardPodExemptPorts {
		for _, iface := range hostPortsGuardPodIFaces {
			if want := fmt.Sprintf("iifname %q tcp dport %d accept", iface, p); !strings.Contains(portsNFT, want) {
				t.Fatalf("ports guard missing pod-exempt %q:\n%s", want, portsNFT)
			}
		}
	}
	// No other port may ride the pod/tunnel-iface path — the
	// exporters, the probe port and the kubelet read-only/healthz
	// listeners must still drop for tenant pods.
	for _, bad := range []string{
		"tcp dport 9100 accept", "tcp dport 9115 accept",
		"tcp dport 9962 accept", "tcp dport 39901 accept",
		"tcp dport 10248 accept", "tcp dport 10256 accept",
		"tcp dport 20256 accept",
	} {
		if strings.Contains(portsNFT, bad) {
			t.Fatalf("ports guard exempts %q on a pod/tunnel iface — guard hole:\n%s", bad, portsNFT)
		}
	}
	// The exemptions must sit BEFORE the drop rule to take effect.
	for _, p := range hostPortsGuardPodExemptPorts {
		if strings.Index(portsNFT, fmt.Sprintf("tcp dport %d accept", p)) >
			strings.Index(portsNFT, "tcp dport {") {
			t.Fatalf("ports guard exemption for :%d renders after the drop rule:\n%s", p, portsNFT)
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
	// The fixture's three registry nodes also contribute their
	// marker IPs (172.29.0.{10,20,30} — marker_base + last ip octet).
	if !strings.Contains(portsNFT, "ip saddr { 10.0.1.10, 10.0.1.30, 10.0.2.20, 172.29.0.10, 172.29.0.20, 172.29.0.30, 203.0.113.9 } accept") {
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
	if !strings.Contains(portsNFT, "ip saddr { 10.0.1.10, 10.0.1.30, 10.0.2.20, 172.29.0.10, 172.29.0.20, 172.29.0.30 } accept") {
		t.Fatalf("ports guard v4 accept set missing the registry ips + markers:\n%s", portsNFT)
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
	if !strings.Contains(nldNFT, "ip saddr { 10.0.0.0/8, 10.0.1.10, 10.0.1.30, 10.0.2.20, 172.29.0.10, 172.29.0.20, 172.29.0.30 } tcp dport 53 accept") {
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

// TestPortsGuardCustomNebDev — the trunk accept follows
// interdc_nebula_dev (c.nebDev), not a hardcoded "neb1": a cluster
// whose nebula device is named differently must still accept
// cluster traffic on the guard.
func TestPortsGuardCustomNebDev(t *testing.T) {
	_, portsNFT := convergeNLDWithVars(t, "interdc_nebula_dev: neb9\n")
	if !strings.Contains(portsNFT, `iifname "neb9" accept`) {
		t.Fatalf("ports guard missing the custom dev accept:\n%s", portsNFT)
	}
	if strings.Contains(portsNFT, `iifname "neb1" accept`) {
		t.Fatalf("ports guard still accepts the default dev:\n%s", portsNFT)
	}
}

// TestPortsGuardUnsafeDevSkipsInstall — a dev name that fails the
// shell-token charset gate must NOT render (it would splice nft
// rules inside the quoted iifname) and must not install a guard
// missing the trunk accept: the whole converge skips for the cycle.
func TestPortsGuardUnsafeDevSkipsInstall(t *testing.T) {
	vars := writeVarsDir(t, "interdc_nebula_dev: 'neb1\" ; accept'\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.convergeHostPortsGuard()
	if hostExists(r, "/etc/host-internal-ports-guard.nft") ||
		hostExists(r, "/etc/systemd/system/host-internal-ports-guard.service") {
		t.Fatal("unsafe dev still rendered a guard")
	}
}

// TestPortsGuardFailOpenEmptyRegistry — a node absent from the
// registry with NO allow sources at all (standalone host, no vars)
// must not get the guard: its only accepts would be lo/dev/
// established, which drops apiserver→kubelet on a single-node
// cluster. Fail-open = skip the install with a warning, not a
// whiteout table.
func TestPortsGuardFailOpenEmptyRegistry(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", "{}\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-z", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-z")
	c.convergeHostPortsGuard()
	if hostExists(r, "/etc/host-internal-ports-guard.nft") ||
		hostExists(r, "/etc/systemd/system/host-internal-ports-guard.service") {
		t.Fatal("guard installed on a registry-less node with an empty allow set")
	}
	// ...but the SAME node WITH an operator-declared allow source
	// still gets the guard — fail-open only covers the nothing-known
	// case.
	vars2 := writeVarsDir(t,
		"host_internal_ports_guard_allow_extra: [203.0.113.9]\n")
	patchVarsFile(t, vars2, "interdc_nodes.yaml", "{}\n")
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-z", HostRoot: t.TempDir(),
		VarsDir: vars2, Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2 := loadCyc(t, r2, vars2, "node-z")
	c2.convergeHostPortsGuard()
	if !hostExists(r2, "/etc/host-internal-ports-guard.nft") {
		t.Fatal("guard not installed despite a declared allow source")
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

func TestNLDAllowSourcesDeduplicates(t *testing.T) {
	nldNFT, portsNFT := convergeNLDWithVars(t, `
nodelocaldns_guard_allow_private: [10.0.0.0/8, 10.0.0.0/8, "fd00::/64"]
nodelocaldns_guard_allow_extra: [10.0.1.10, 10.0.0.0/8, "fd00::/64", 203.0.113.5, 203.0.113.5]
host_internal_ports_guard_allow_extra: [10.0.1.10, 203.0.113.5, 203.0.113.5, "fd00::9", "fd00::9"]
`)
	checkSetLines := func(label, nft, lineSub string, items ...string) {
		t.Helper()
		found := 0
		for line := range strings.SplitSeq(nft, "\n") {
			if !strings.Contains(line, lineSub) {
				continue
			}
			found++
			for _, item := range items {
				if got := strings.Count(line, item); got != 1 {
					t.Fatalf("%s (%s): expected %q once in line %q, got %d", label, lineSub, item, line, got)
				}
			}
		}
		if found == 0 {
			t.Fatalf("%s: no line matching %q in:\n%s", label, lineSub, nft)
		}
	}
	checkSetLines("nld v4 tcp", nldNFT, "ip saddr {", "10.0.0.0/8", "10.0.1.10", "203.0.113.5")
	checkSetLines("nld v6 tcp", nldNFT, "ip6 saddr {", "fd00::/64")
	checkSetLines("ports v4", portsNFT, "ip saddr {", "10.0.1.10", "203.0.113.5")
	checkSetLines("ports v6", portsNFT, "ip6 saddr {", "fd00::9")
}
