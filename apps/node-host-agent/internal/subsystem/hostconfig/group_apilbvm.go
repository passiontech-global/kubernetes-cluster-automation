// group_apilbvm.go — api-lb VM guard converge ported from
// hub_converge.yaml (tasks/api_lb_guard.yaml): haproxy admin-socket
// plumbing, journald persistence and the guard conf on the
// api_lb_guard_vms VMs (distinct from group_apilb.go's T12
// worker-side api-local-lb).
package hostconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// ---------- api-lb-vm (api_lb_guard.yaml) ----------
//
// Converges the api-backend-guard prerequisites on a VM matching an
// api_lb_guard_vms entry in cluster.yaml: the haproxy admin-socket
// plumbing (tmpfiles dir owner 99 so a reboot doesn't hand docker a
// root:root bind source — incident 2026-09-29), journald persistence
// (the only place a drain audit survives reboot on these VMs), the
// stats socket + bind-mount inside the running haproxy container, and
// the guard conf. The shell guard unit itself is retired — apiprober
// owns the drain logic in-process.

// apiLBVMEntry returns this node's api_lb_guard_vms entry (match on
// the entry name == NODE_NAME, same key ansible add_host used).
func (c *cyc) apiLBVMEntry() *topology.OMap {
	for _, it := range c.vl("api_lb_guard_vms") {
		m, _ := it.(*topology.OMap)
		if m == nil {
			continue
		}
		if strOf(m, "name") == c.r.cfg.NodeName {
			return m
		}
	}
	return nil
}

type lbgInspect struct {
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

var lbgSockMountRe = regexp.MustCompile(`(?m)^\s*-\s*["']?[^\s]*/haproxy\.cfg`)

// sq single-quotes a path for safe interpolation into `sh -c`
// strings (a compose dir/file containing spaces or metachars would
// otherwise split or expand mid-command).
func sq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (c *cyc) groupAPILBVM() {
	r, ctx := c.r, c.ctx
	e := c.apiLBVMEntry()
	if e == nil {
		return
	}
	sockDir := defStr(strOf(e, "haproxy_sock_dir"), "/run/haproxy-admin")
	socket := defStr(strOf(e, "haproxy_socket"), "/run/haproxy-admin/admin.sock")
	container := defStr(strOf(e, "haproxy_container"), "haproxy")
	backend := defStr(strOf(e, "haproxy_backend"), "kubeAPI_backend")
	backends := defStr(strOf(e, "haproxy_backends"), backend)
	apiBackends := strOf(e, "api_backends")
	mode := defStr(strOf(e, "mode"), "enforce")

	// prereqs — best-effort like ansible failed_when: false. runLong:
	// apt on a slow-egress infra VM outlives the interactive budget.
	_, _ = r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "socat", "curl")

	// tmpfiles.d: recreate the bind-mount source owned by the
	// container's haproxy uid on every boot (/run is tmpfs — docker
	// auto-creating it root:root crash-loops the VIP).
	_, _ = r.writeManaged("/etc/tmpfiles.d/api-lb-guard.conf",
		[]byte(fmt.Sprintf(`# api-lb-guard: bind-mount source for the haproxy admin socket.
# owner 99 = uid of the `+"`haproxy`"+` user in the haproxy:*-alpine image.
d %s 0755 99 99 -
`, sockDir)), 0o644)
	if err := os.MkdirAll(r.hp(sockDir), 0o755); err == nil {
		if err := os.Chown(r.hp(sockDir), 99, 99); err != nil {
			c.err("api-lb-vm: chown 99 sock dir failed — docker creates "+
				"the bind source root:root and the VIP crash-loops",
				"dir", sockDir, "error", err)
		}
	} else {
		c.err("api-lb-vm: sock dir create failed", "dir", sockDir, "error", err)
	}

	// journald persistence — the only drain-audit history on these
	// out-of-inventory VMs (incident 2026-10-09: cloned image left
	// journals under a stale machine-id dir, orphaned on next boot).
	// 500M cap: the VM only runs haproxy + agent.
	c.journaldStorage("/etc/systemd/journald.conf.d/50-api-lb-guard.conf",
		[]byte(`# api-lb-guard: persistent journal to audit guard drain
# history across reboots. 500M cap: the VM only runs haproxy + agent.
[Journal]
Storage=persistent
SystemMaxUse=500M
`))

	c.apiLBHaproxy(container, sockDir, socket)

	// guard conf (lbg_* host-var parity).
	conf := fmt.Sprintf(`# /etc/api-backend-guard.conf — managed by node-host-agent hostconfig
# (port of hub_converge.yaml api_lb_guard scope). Do NOT edit by hand —
# converge overwrites. Edit the api_lb_guard_vms vars in vars/cluster.yaml.
MODE=%s

# "haproxy_server_name=ip:port" — name MUST match the `+"`server <name>`"+`
# line in backend %s of the haproxy on this VM.
API_BACKENDS="%s"

HAPROXY_BACKEND=%s
# Disable/enable applies to ALL these backends (a wedged controller
# drains both the api lane and the konnectivity tunnel — incident
# 2026-10-07). A server missing from a backend is a no-op.
HAPROXY_BACKENDS="%s"
HAPROXY_SOCKET=%s

# Credential paths — API_TOKEN_FILE/API_CA_FILE are the ORIGINAL
# contract (templates/api-backend-guard.conf.j2 wrote them and the
# retired api-backend-guard.sh sourced exactly these; api-lb VMs in
# the field still carry a conf with this spelling). TOKEN_FILE/
# CA_FILE are kept alongside for readers of the short-lived Go
# spelling — same values, harmless duplicates in a sourced env file.
API_TOKEN_FILE=/etc/api-backend-guard/token
API_CA_FILE=/etc/api-backend-guard/ca.crt
TOKEN_FILE=/etc/api-backend-guard/token
CA_FILE=/etc/api-backend-guard/ca.crt
`, mode, backend, apiBackends, backend, backends, socket)
	// MkdirAll does not chmod an EXISTING dir — enforce 0700
	// explicitly so a drifted 0755 credential dir is re-tightened.
	_ = r.ensureDir("/etc/api-backend-guard", 0o700)
	if err := os.Chmod(r.hp("/etc/api-backend-guard"), 0o700); err != nil {
		c.err("api-lb-vm: chmod 0700 credential dir failed — guard token left readable",
			"error", err)
	}
	_, _ = r.writeManaged("/etc/api-backend-guard.conf", []byte(conf), 0o644)

	// the shell guard is retired — prune covers it globally too, but
	// sweep it here so this group is self-contained.
	_, _ = r.run(ctx, "systemctl", "disable", "--now", "api-backend-guard.timer", "api-backend-guard.service")
	rm := false
	for _, p := range []string{
		"/etc/systemd/system/api-backend-guard.timer",
		"/etc/systemd/system/api-backend-guard.service",
		"/usr/local/sbin/api-backend-guard.sh",
	} {
		if ch, _ := r.removeManaged(p); ch {
			rm = true
		}
	}
	if rm {
		r.daemonReload(ctx)
	}
}

// apiLBHaproxy ports the "Locate haproxy container" block: parse
// docker inspect for the compose file / cfg path / image / live
// socket mount, insert the stats-socket global block and the
// bind-mount line, validate haproxy -c in a throwaway container, then
// recreate or restart only on real drift.
func (c *cyc) apiLBHaproxy(container, sockDir, socket string) {
	r, ctx := c.r, c.ctx
	out, err := r.run(ctx, "docker", "inspect", container)
	if err != nil {
		c.err("api-lb-vm: docker inspect failed — skipping haproxy converge",
			"container", container, "error", err)
		return
	}
	var ins []lbgInspect
	if err := json.Unmarshal([]byte(out), &ins); err != nil {
		c.err("api-lb-vm: docker inspect unparseable — skipping haproxy converge",
			"container", container, "error", err)
		return
	}
	if len(ins) == 0 {
		c.err("api-lb-vm: docker inspect returned no containers — skipping haproxy converge",
			"container", container)
		return
	}
	d := ins[0]
	composeFile := d.Config.Labels["com.docker.compose.project.config_files"]
	image := d.Config.Image
	cfgPath := ""
	sockMounted := false
	for _, m := range d.Mounts {
		switch m.Destination {
		case "/usr/local/etc/haproxy/haproxy.cfg":
			cfgPath = m.Source
		case "/run/haproxy":
			sockMounted = true
		}
	}
	// ansible assert parity.
	if composeFile == "" || cfgPath == "" {
		c.err("api-lb-vm: cannot locate compose file or haproxy.cfg — "+
			"check this VM manually", "container", container,
			"compose", composeFile, "cfg", cfgPath)
		return
	}
	composeDir := filepath.Dir(composeFile)

	cfgChanged := false
	if b, err := os.ReadFile(r.hp(cfgPath)); err != nil {
		// Best-effort precondition — the definitive signal (admin
		// socket absent after the wait below) is what counts.
		logger().Warn("api-lb-vm: cannot read haproxy.cfg — stats socket not ensured",
			"path", cfgPath, "error", err)
	} else if !strings.Contains(string(b), "stats socket") {
		nb := "# BEGIN api-lb-guard: admin socket for guard backend drain\n" +
			"global\n" +
			"    stats socket /run/haproxy/admin.sock mode 660 level admin\n" +
			"    stats timeout 30s\n" +
			"# END api-lb-guard: admin socket for guard backend drain\n" +
			string(b)
		cfgChanged, _ = r.writeManaged(cfgPath, []byte(nb), 0o644)
	}

	composeChanged := false
	if cb, err := os.ReadFile(r.hp(composeFile)); err != nil {
		// Best-effort precondition — same socket-wait signal below.
		logger().Warn("api-lb-vm: cannot read compose file — /run/haproxy mount not ensured",
			"path", composeFile, "error", err)
	} else {
		mountRe := regexp.MustCompile(`(?m)^\s*-\s*["']?` +
			regexp.QuoteMeta(sockDir) + `:/run/haproxy["']?`)
		if !mountRe.Match(cb) {
			line := "      - " + sockDir + ":/run/haproxy"
			ns := lineInFile(string(cb), `\A\z`, line, lbgSockMountRe.String())
			composeChanged, _ = r.writeManaged(composeFile, []byte(ns), 0o644)
		}
	}

	// validate before touching the live container — a bad cfg never
	// reaches the VIP. runLong: docker run may pull the image first,
	// which outlives the interactive budget on slow egress.
	if cfgChanged || composeChanged {
		if out, err := r.runLong(ctx, "docker", "run", "--rm",
			"-v", cfgPath+":/tmp/haproxy.cfg:ro",
			image, "haproxy", "-c", "-f", "/tmp/haproxy.cfg"); err != nil {
			c.err("api-lb-vm: haproxy -c failed — not recreating/restarting",
				"cfg", cfgPath, "out", out, "error", err)
			return
		}
	}
	switch {
	case composeChanged || !sockMounted:
		// ~2-5s VIP blip — only on first setup or real drift.
		// runLong: compose up pulls images on first setup.
		if _, err := r.runLong(ctx, "sh", "-c",
			fmt.Sprintf("cd %s && docker compose -f %s up -d",
				sq(composeDir), sq(composeFile))); err != nil {
			c.err("api-lb-vm: docker compose up failed — admin socket will not appear",
				"compose", composeFile, "error", err)
		}
	case cfgChanged:
		if _, err := r.run(ctx, "docker", "restart", container); err != nil {
			c.err("api-lb-vm: docker restart failed — config change not applied",
				"container", container, "error", err)
		}
	}
	// wait_for parity: haproxy creates the socket at start.
	for i := 0; i < 60; i++ {
		if r.fileExists(socket) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	c.err("api-lb-vm: haproxy admin socket did not appear in 30s — guard drains will fail",
		"socket", socket, "container", container)
}
