// group_nodecpu.go — T8 wait-for-nodeip drop-in (neb1 marker IP
// before k0sworker binds --node-ip) + T10 CPU weight/quota
// starvation protection for k0sworker and nebula.
package hostconfig

// ---------- T8 + T10 ----------

func (c *cyc) groupNodeCPU() {
	r, ctx := c.r, c.ctx
	if c.worker() && !c.t.AmLighthouse {
		r.ensureDir("/etc/systemd/system/k0sworker.service.d", 0o755)
		if ch, _ := r.writeManaged("/etc/systemd/system/k0sworker.service.d/20-wait-nodeip.conf",
			[]byte(`# Managed by node-config-agent - T8: wait for the marker IP
# on neb1 before k0sworker binds --node-ip (nebula Before=k0sworker).
[Unit]
After=nebula@interdc.service
Wants=nebula@interdc.service

[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do ip addr show dev neb1 | grep -q "inet .* scope global" && exit 0; sleep 1; done; exit 0'
`), 0o644); ch {
			r.daemonReload(ctx)
		}
	}
	// T10 cpu protection.
	w := c.v("critical_cpu_weight")
	if w == "" || w == "None" {
		w = "500"
	}
	if c.worker() {
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
		r.ensureDir("/etc/systemd/system/nebula@interdc.service.d", 0o755)
		quota := c.v("interdc_nebula_cpu_quota")
		if quota == "" || quota == "None" {
			quota = "150%"
		}
		if ch, _ := r.writeManaged("/etc/systemd/system/nebula@interdc.service.d/10-cpu-quota.conf",
			[]byte("# Managed by node-config-agent - T10 nebula CPU bound\n[Service]\nCPUQuota="+quota+"\n"), 0o644); ch {
			r.daemonReload(ctx)
			if _, err := r.run(ctx, "systemctl", "set-property", "nebula@interdc.service", "CPUQuota="+quota); err != nil {
				// Best-effort live apply — same drop-in contract.
				logger().Warn("T10: set-property failed — drop-in applies at next restart",
					"unit", "nebula@interdc.service", "value", quota, "error", err)
			}
		}
	}
}
