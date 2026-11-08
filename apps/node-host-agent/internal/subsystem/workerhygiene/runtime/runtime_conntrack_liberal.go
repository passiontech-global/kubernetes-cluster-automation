// runtime_conntrack_liberal.go — the conntrack-tcp-liberal-guard
// (wdeps.CheckConntrackLiberal). On neb1 (nebula overlay) nodes the
// underlay policy route returns replies over a different path than
// the outbound flow, so conntrack sees ACK/RST that look "out of
// window" and — with nf_conntrack_tcp_be_liberal=0 — marks them
// INVALID and drops them. The guard pins the sysctl to 1 on neb1
// nodes; non-neb1 nodes keep the kernel default (the fix exists
// because of the overlay's asymmetry).
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type ConntrackLiberalCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *ConntrackLiberalCheck) Name() string { return wdeps.CheckConntrackLiberal }

// Run executes one conntrack-liberal round.
func (c *ConntrackLiberalCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckConntrackLiberal) {
		return
	}
	if _, err := os.Stat(filepath.Join(
		c.d.Cfg.SysClassNet, c.d.Cfg.NebulaIface)); err != nil {
		// No nebula iface — the asymmetric-path problem this guard
		// exists for can't occur; leave the kernel default alone.
		c.d.CycleResult(wdeps.CheckConntrackLiberal, "ok")
		return
	}
	p := filepath.Join(c.d.Cfg.ProcRoot, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	data, err := os.ReadFile(p)
	if err != nil {
		// Module not loaded / sysctl absent — dormant, not an error.
		c.d.CycleResult(wdeps.CheckConntrackLiberal, "abort")
		return
	}
	if strings.TrimSpace(string(data)) != "0" {
		c.d.CycleResult(wdeps.CheckConntrackLiberal, "ok")
		return
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: conntrack-tcp-liberal-guard write %s failed: %v", p, err))
		c.d.CycleResult(wdeps.CheckConntrackLiberal, "ok")
		return
	}
	c.d.State.AppendLog(
		"ACTION: conntrack-tcp-liberal-guard set nf_conntrack_tcp_be_liberal=1 (neb1 present)")
	c.d.ConntrackLiberalFixes++
	c.d.Actions.WithLabelValues(wdeps.CheckConntrackLiberal, "sysctl_write").Inc()
	c.d.CycleResult(wdeps.CheckConntrackLiberal, "ok")
}
