// group_security.go — fail2ban jail (mesh-whitelisted cluster sshd
// jail) + sshd drop-in hardening, gated on fail2ban_enabled /
// ssh_hardening_enabled.
package hostconfig

import (
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// ---------- security (fail2ban + sshd hardening) ----------

func (c *cyc) groupSecurity() {
	r, ctx := c.r, c.ctx
	if c.vb("fail2ban_enabled") {
		if out, _ := r.run(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", "fail2ban"); out != "installed" {
			// runLong: apt install on slow egress outlives the
			// interactive budget.
			if _, err := r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
				"apt-get", "install", "-y", "fail2ban"); err != nil {
				c.err("security: fail2ban install failed — jail will not apply",
					"error", err)
			}
		}
		b, err := r.render("fail2ban-cluster.conf.j2", c.tplCtx())
		if err != nil {
			c.err("fail2ban render", "error", err)
			return
		}
		_ = r.ensureDir("/etc/fail2ban/jail.d", 0o755)
		// bootstrap-era jail whitelists only localhost and would
		// shadow the mesh whitelist (.local reads after .conf).
		legacyRm, _ := r.removeManaged("/etc/fail2ban/jail.d/sshd.local")
		ch, _ := r.writeManaged("/etc/fail2ban/jail.d/90-cluster-sshd.conf", b, 0o644)
		// stale filename of the first port
		_, _ = r.removeManaged("/etc/fail2ban/jail.d/cluster.conf")
		r.ensureService(ctx, "fail2ban.service", true, true)
		if ch || legacyRm {
			r.restartService(ctx, "fail2ban.service")
		}
		_, _ = r.run(ctx, "fail2ban-client", "status", "sshd") // informational
	} else if _, u := c.t.Vars.Get("fail2ban_enabled").(topology.Undefined); !u {
		// ansible: only when fail2ban_enabled is defined and false —
		// remove the jail AND purge the package.
		_, _ = r.removeManaged("/etc/fail2ban/jail.d/90-cluster-sshd.conf")
		_, _ = r.removeManaged("/etc/fail2ban/jail.d/cluster.conf")
		// runLong: same slow-egress budget as the install above.
		if _, err := r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "purge", "-y", "fail2ban"); err != nil {
			c.err("security: fail2ban purge failed — package remains",
				"error", err)
		}
	}
	if c.vb("ssh_hardening_enabled") {
		// 60- file was renamed to 00- (first-match-wins vs
		// 50-cloud-init.conf) — always purge the old name.
		rm60, _ := r.removeManaged("/etc/ssh/sshd_config.d/60-passiontech-hardening.conf")
		_ = r.ensureDir("/etc/ssh/sshd_config.d", 0o755)
		ch, _ := r.writeManaged("/etc/ssh/sshd_config.d/00-passiontech-hardening.conf",
			[]byte(`# Managed by Ansible - node-config-agent (port tu bootstrap/ansible/ssh_hardening.yaml)
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
`), 0o644)
		if ch || rm60 {
			// ansible: sshd -t gate BEFORE restart — a broken drop-in
			// must never take sshd down on a public node.
			if out, err := r.run(ctx, "sshd", "-t"); err == nil {
				r.restartService(ctx, "ssh.service")
			} else {
				c.err("sshd -t failed — not restarting ssh.service",
					"path", "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf",
					"out", out, "error", err)
			}
		}
		if out, err := r.run(ctx, "sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"); err != nil {
			// Best-effort verify only — a failed probe proves nothing
			// about the applied config.
			logger().Warn("ssh-hardening: sshd -T failed — cannot verify effective config",
				"error", err)
		} else if !strings.Contains(out, "passwordauthentication no") {
			c.err("ssh-hardening: passwordauthentication still enabled — drop-in not effective",
				"path", "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
		}
	} else if _, u := c.t.Vars.Get("ssh_hardening_enabled").(topology.Undefined); !u {
		rm1, _ := r.removeManaged("/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
		rm2, _ := r.removeManaged("/etc/ssh/sshd_config.d/60-passiontech-hardening.conf")
		if rm1 || rm2 {
			if _, err := r.run(ctx, "sshd", "-t"); err == nil {
				r.restartService(ctx, "ssh.service")
			} else {
				c.err("ssh-hardening: sshd -t failed — drop-in removal not active until restart",
					"error", err)
			}
		}
	}
}

// fail2banIgnoreIP — set_fact parity: localhost + sorted mesh node
// IPs (automation SSHes public->public) + optional extras.
func (c *cyc) fail2banIgnoreIP() string {
	var mesh []string
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if ip := nodeIPStr(om, "ip"); ip != "" {
			mesh = append(mesh, ip)
		}
	}
	sort.Strings(mesh)
	parts := []string{"127.0.0.1/8", "::1"}
	parts = append(parts, mesh...)
	if ex := strings.TrimSpace(c.v("fail2ban_ignoreip_extra")); ex != "" && ex != "None" {
		parts = append(parts, ex)
	}
	return strings.Join(parts, " ")
}
