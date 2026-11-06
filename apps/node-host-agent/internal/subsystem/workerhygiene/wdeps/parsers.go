// parsers.go — the response parsers the Seams production defaults
// need: Seams.ApplyDefaults wires the WG allowed-ips counter and
// the cilium encrypt-peers fallback, and both parse command/API
// output. They live here (not in cilium/) because wdeps cannot
// import a domain package that itself imports wdeps.
package wdeps

import (
	"encoding/json"
	"strings"
)

// ParseWGAllowedIPs counts peers carrying a real allowed-ips set —
// `wg show <iface> allowed-ips` prints "<pubkey>\t<ip,ip,...>" per
// line, "(none)" for a peer whose routes were wiped.
func ParseWGAllowedIPs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		n++
	}
	return n
}

// ParseCiliumHealthNodes counts remote cluster members in the
// agent's /v1/healthz payload ({"cluster":{"nodes":[...]}} — the
// same source `cilium status` reports "Cluster health: N/M"). Every
// entry is a remote node running cilium-agent, i.e. one WireGuard
// peer this node should hold; virtual/liqo nodes run no agent and
// never appear. ok=false when the section is absent or empty — the
// caller then falls back to the node-list heuristic.
func ParseCiliumHealthNodes(body []byte) (int, bool) {
	var resp struct {
		Cluster *struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(body, &resp); err != nil ||
		resp.Cluster == nil || len(resp.Cluster.Nodes) == 0 {
		return 0, false
	}
	return len(resp.Cluster.Nodes), true
}
