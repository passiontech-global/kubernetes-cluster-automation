// parsers.go — the response parsers the Seams production defaults
// need: Seams.applyDefaults wires the WG allowed-ips counter and
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

// ParseCiliumServiceBackends reduces the agent's GET /v1/service
// payload (the `cilium-dbg service list -o json` source) to
// "<namespace>/<name>" → backend count. k8s-derived services carry
// their identity in spec.name/spec.namespace (older builds nest it
// under spec.flags); entries without a name (l7lb/synthetic) are
// skipped. Backend counts SUM across a service's per-transport
// entries (kube-dns lists a UDP and a TCP frontend — the desync
// verdict only cares whether ANY backend is programmed).
func ParseCiliumServiceBackends(body []byte) (map[string]int, error) {
	var list []struct {
		Spec struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Flags     struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"flags"`
			BackendAddresses []json.RawMessage `json:"backend-addresses"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, svc := range list {
		ns, name := svc.Spec.Namespace, svc.Spec.Name
		if name == "" {
			ns, name = svc.Spec.Flags.Namespace, svc.Spec.Flags.Name
		}
		if name == "" {
			continue
		}
		out[ns+"/"+name] += len(svc.Spec.BackendAddresses)
	}
	return out, nil
}
