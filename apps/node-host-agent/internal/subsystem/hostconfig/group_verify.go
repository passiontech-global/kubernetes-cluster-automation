// group_verify.go — informational tail-group probes (ansible
// debug/assert parity): they only log, never count a group error.
package hostconfig

// ---------- verify (informational) ----------

// groupVerify is the informational tail group (ansible debug/assert
// parity) — its probes only log; they never count a group error.
func (c *cyc) groupVerify() {
	if out, err := c.r.run(c.ctx, "getent", "ahosts", c.v("cp_endpoint")); err == nil {
		logger().Info("hostconfig verify: cp_endpoint resolves", "getent", out)
	} else {
		logger().Warn("hostconfig verify: cp_endpoint does not resolve",
			"cp_endpoint", c.v("cp_endpoint"), "error", err)
	}
	if out, err := c.r.run(c.ctx, "sysctl", "-n",
		"net.ipv4.tcp_congestion_control", "net.core.default_qdisc"); err == nil {
		logger().Info("hostconfig verify: cc/qdisc", "sysctl", out)
	} else {
		logger().Warn("hostconfig verify: cc/qdisc unreadable", "error", err)
	}
}
