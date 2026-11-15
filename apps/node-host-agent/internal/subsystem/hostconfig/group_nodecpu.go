// group_nodecpu.go — T8 wait-for-nodeip drop-in (nebula dev marker IP
// before k0sworker binds --node-ip) + T10 CPU weight/quota
// starvation protection for k0sworker and nebula.
package hostconfig

import "fmt"

// ---------- T8 + T10 ----------

func (c *cyc) groupNodeCPU() {
	r, ctx := c.r, c.ctx
	if c.worker() && !c.t.AmLighthouse {
		// Both scalars render verbatim into a systemd drop-in — the
		// dev inside an ExecStartPre sh -c single-quote pair, the net
		// inside unit names and .d paths. cfgScalar keeps a quote,
		// newline or '#' out of either; a refusal skips ONLY this
		// drop-in (the CPU weight/quota blocks below still converge).
		dev, net := c.nebDev(), c.t.Vars.StrDef("interdc_nebula_net", "interdc")
		if c.cfgScalar("interdc_nebula_dev", dev) &&
			c.cfgScalar("interdc_nebula_net", net) {
			unit := "nebula@" + net + ".service"
			_ = r.ensureDir("/etc/systemd/system/k0sworker.service.d", 0o755)
			if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/20-wait-nodeip.conf",
				[]byte(fmt.Sprintf(`# Managed by node-config-agent - T8: wait for the marker IP
# on the nebula dev before k0sworker binds --node-ip (nebula Before=k0sworker).
[Unit]
After=%s
Wants=%s

[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do ip addr show dev %s | grep -q "inet .* scope global" && exit 0; sleep 1; done; exit 0'
`, unit, unit, dev)), 0o644); ch {
				r.daemonReload(ctx)
			}
		}
	}
	// T10 cpu protection. Both scalars render verbatim into systemd
	// drop-ins — cfgScalar keeps a newline/quote out of the unit
	// file (empty stays allowed, same contract as before).
	w := c.t.Vars.StrDef("critical_cpu_weight", "500")
	if c.worker() && (w == "" || c.cfgScalar("critical_cpu_weight", w)) {
		if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/30-cpu-weight.conf",
			[]byte("# Managed by node-config-agent - T10 CPU starvation protection\n[Service]\nCPUWeight="+w+"\n"), 0o644); ch {
			r.daemonReload(ctx)
			if _, err := r.run(ctx, "systemctl", "set-property", "k0sworker.service", "CPUWeight="+w); err != nil {
				// Best-effort live apply — the declared state is on
				// disk; the agent never restarts k0s so the drop-in
				// lands at the next natural restart.
				logger().Warn("T10: set-property failed — drop-in applies at next restart",
					"unit", "k0sworker.service", "value", w, "error", err)
			}
		}
	}
	if c.t.Found {
		// The quota drop-in targets the ACTIVE nebula instance —
		// interdc_nebula_net, same resolution groupNebula uses for
		// the unit name — not a hardcoded "interdc".
		net := c.t.Vars.StrDef("interdc_nebula_net", "interdc")
		if !c.cfgScalar("interdc_nebula_net", net) {
			return
		}
		unit := "nebula@" + net + ".service"
		_ = r.ensureDir("/etc/systemd/system/"+unit+".d", 0o755)
		quota := c.t.Vars.StrDef("interdc_nebula_cpu_quota", "150%")
		if quota != "" && !c.cfgScalar("interdc_nebula_cpu_quota", quota) {
			return
		}
		if ch, _ := r.writeManaged("/etc/systemd/system/"+unit+".d/10-cpu-quota.conf",
			[]byte("# Managed by node-config-agent - T10 nebula CPU bound\n[Service]\nCPUQuota="+quota+"\n"), 0o644); ch {
			r.daemonReload(ctx)
			if _, err := r.run(ctx, "systemctl", "set-property", unit, "CPUQuota="+quota); err != nil {
				// Best-effort live apply — same drop-in contract.
				logger().Warn("T10: set-property failed — drop-in applies at next restart",
					"unit", unit, "value", quota, "error", err)
			}
		}
	}
}
