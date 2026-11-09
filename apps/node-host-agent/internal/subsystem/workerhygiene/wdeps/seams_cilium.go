// seams_cilium — the Cilium agent unix-API group of the Seams test-seam surface, split out of
// seams.go (which keeps the Seams aggregate + applyDefaults
// orchestration).
package wdeps

import (
	"context"
	"errors"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

// Cilium holds the ONE cilium seam — the unix-socket GET every
// agent endpoint shares. The WireGuard allowed-ips / encrypt-peers /
// BPF service-map evidence reads are derived from it (or from
// Config.Systemd for the `wg` exec): they are methods below, not
// seams — stubbing UnixGet and testing the parsers directly gives
// equal coverage with less surface.
type Cilium struct {
	// UnixGet GETs path over a unix socket and returns the body —
	// the cilium-dbg endpoint list replacement (35). Seam.
	UnixGet func(ctx context.Context, socket, path string) ([]byte, error)
	// WGDump returns the raw `wg show cilium_wg0 dump` output —
	// the zombie-peer evidence source (TSV: one interface
	// line, then one 8-column line per peer). Seam (default execs
	// wg through the systemd client).
	WGDump func(ctx context.Context, sd *systemd.Client) (string, error)
	// MonotonicNow supplies "now" to the per-peer zombie state
	// machine — seam so tests drive cycles (default time.Now).
	MonotonicNow func() time.Time
}

// WGAllowedIPs returns how many cilium_wg0 peers carry a real
// allowed-ips set — `wg show cilium_wg0 allowed-ips` through the
// systemd exec wrapper (sd is Config.Systemd), ParseWGAllowedIPs'd
// (peers at "(none)" are wiped). The cilium-wg-peer-gc check's derived read —
// tests drive it through the systemd exec fake.
func (s *Cilium) WGAllowedIPs(ctx context.Context, sd *systemd.Client) (int, error) {
	if sd == nil {
		return 0, errors.New("no systemd client wired")
	}
	out, err := sd.Exec(ctx, "wg", "show", "cilium_wg0", "allowed-ips")
	if err != nil {
		return 0, err
	}
	return ParseWGAllowedIPs(out), nil
}

// WGDumpPeer is one parsed `wg show <dev> dump` peer row.
type WGDumpPeer struct {
	Pub        string // peer public key
	AllowedIPs string // "(none)" when wiped
	Handshake  int64  // latest handshake, unix seconds (0 = never)
	RX         int64  // received bytes
	TX         int64  // sent bytes
}

// WGDumpPeers returns the parsed cilium_wg0 dump peer rows — the
// Zombie-peer read. Derived over the WGDump seam so tests
// stub the one exec.
func (s *Cilium) WGDumpPeers(ctx context.Context, sd *systemd.Client) ([]WGDumpPeer, error) {
	out, err := s.WGDump(ctx, sd)
	if err != nil {
		return nil, err
	}
	return ParseWGDump(out), nil
}

// EncryptPeers returns the expected WG peer count — the agent's
// /v1/healthz cluster.nodes[] member count through the UnixGet
// seam. The agent's own API beats `cilium-dbg`: the binary only
// lives INSIDE the cilium-agent container — an sd.Exec on the host
// always fails and silently degrades every cycle to the
// ReadyNodes-1 fallback. /v1/healthz's cluster.nodes[] lists
// exactly the remote cilium members this node should peer with
// (virtual/liqo nodes run no agent, so they never appear). An error
// or a count <=0 makes the caller fall back to ReadyNodes-1.
func (s *Cilium) EncryptPeers(ctx context.Context, socket string) (int, error) {
	body, err := s.UnixGet(ctx, socket, "/v1/healthz")
	if err != nil {
		return 0, err
	}
	n, ok := ParseCiliumHealthNodes(body)
	if !ok {
		return 0, errors.New("no cluster.nodes in cilium healthz")
	}
	return n, nil
}

// ServiceBackends returns the local BPF service map's backend
// counts keyed "<namespace>/<name>" — the cilium-lrp desync
// evidence source. GET /v1/service off the agent socket through
// the UnixGet seam (`cilium-dbg service list -o json` equivalent —
// the CLI scrapes the same endpoint over the same socket; no
// container exec).
func (s *Cilium) ServiceBackends(ctx context.Context, socket string) (map[string]int, error) {
	body, err := s.UnixGet(ctx, socket, "/v1/service")
	if err != nil {
		return nil, err
	}
	return ParseCiliumServiceBackends(body)
}

func (s *Cilium) applyDefaults(_ *Config) {
	if s.UnixGet == nil {
		s.UnixGet = probee.UnixGet
	}
	if s.WGDump == nil {
		s.WGDump = func(ctx context.Context, sd *systemd.Client) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.Exec(ctx, "wg", "show", "cilium_wg0", "dump")
		}
	}
	if s.MonotonicNow == nil {
		s.MonotonicNow = time.Now
	}
}
