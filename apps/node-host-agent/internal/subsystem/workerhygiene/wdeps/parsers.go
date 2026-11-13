// parsers.go — the response parsers the Cilium group's derived
// reads (seams.go: WGAllowedIPs / EncryptPeers / ServiceBackends)
// need — the `wg allowed-ips` peer count, the /v1/healthz cluster
// nodes and the /v1/service backend map. They live here (not in
// cilium/) because wdeps cannot import a domain package that
// itself imports wdeps.
package wdeps

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ParseWGAllowedIPs counts peers carrying a real allowed-ips set —
// `wg show <iface> allowed-ips` prints "<pubkey>\t<ip,ip,...>" per
// line, "(none)" for a peer whose routes were wiped.
func ParseWGAllowedIPs(out string) int {
	n := 0
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "(none)" {
			continue
		}
		n++
	}
	return n
}

// ParseWGDump parses `wg show <iface> dump` TSV output: line 1 is
// the interface row (4 columns), every following row is one peer
// with 8 tab-separated columns — pub, preshared-key, endpoint,
// allowed-ips, latest-handshake (unix seconds, 0 = never), rx bytes,
// tx bytes, persistent-keepalive. Garbled rows are skipped — a
// malformed line is never peer evidence (ParseCtrLeases parity).
func ParseWGDump(out string) []WGDumpPeer {
	var peers []WGDumpPeer
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 8 || f[0] == "" {
			continue
		}
		handshake, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		peers = append(peers, WGDumpPeer{
			Pub:        f[0],
			AllowedIPs: f[3],
			Handshake:  handshake,
			RX:         rx,
			TX:         tx,
		})
	}
	return peers
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
