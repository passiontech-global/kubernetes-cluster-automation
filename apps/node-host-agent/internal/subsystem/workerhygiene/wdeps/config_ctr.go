// config_ctr.go — the containerd knobs: CtrConfig, its defaults and
// its NODE_HOST_AGENT_CONTAINERD_SOCKET env row (the A4 socket hang
// probe, the 31-ctr-tasks caps, the A3 ingest GC, the W9 prune
// budget and the KR3 meta.db probe all read this group).
package wdeps

import (
	"context"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// CtrConfig groups the containerd knobs: the A4 socket hang probe,
// the 31-ctr-tasks per-cycle cleanup caps, the A3 ingest GC, the W9
// content prune budget and the KR3 meta.db journal probe.
type CtrConfig struct {
	Socket             string        // containerd grpc unix socket under /host/run
	IngestDir          string        // containerd content ingest dir (39)
	IngestMaxAge       time.Duration // ingest dir mtime older than → stale (3h)
	IngestScanInterval time.Duration // periodic rescan even under disk WM (6h)
	MaxTaskClean       int           // wedged ctr task dir cap per cycle (31)
	MaxShimKill        int           // orphan shim kill cap per cycle (31)
	// MetaJournalFn is the KR3 journal probe — `journalctl
	// -u k0sworker -u containerd --since "3 minutes ago"`. nil →
	// Systemd.ExecCombined default; a nil Systemd leaves the journal
	// half of the check inconclusive (the orphan-shim half still runs).
	MetaJournalFn func(ctx context.Context) (string, error)
}

func (g *CtrConfig) applyDefaults() {
	if g.Socket == "" {
		g.Socket = defaultContainerdSocket
	}
	if g.IngestDir == "" {
		g.IngestDir = defaultCtrIngestDir
	}
	if g.IngestMaxAge <= 0 {
		g.IngestMaxAge = ctrIngestMaxAge
	}
	if g.IngestScanInterval <= 0 {
		g.IngestScanInterval = ctrIngestScanInterval
	}
	if g.MaxTaskClean <= 0 {
		g.MaxTaskClean = defaultMaxCtrTaskClean
	}
	if g.MaxShimKill <= 0 {
		g.MaxShimKill = defaultMaxShimKill
	}
}

// envKnobs returns the containerd domain's env row — the k0s
// containerd socket (hostPath default: k0s puts the socket at
// /run/k0s/containerd.sock, not inside the state dir).
func (g *CtrConfig) envKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob("NODE_HOST_AGENT_CONTAINERD_SOCKET", &g.Socket,
			hostPath("/run/k0s/containerd.sock")),
	}
}
