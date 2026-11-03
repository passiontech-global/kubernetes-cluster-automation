// Task groups ported from hub_converge.yaml scopes: swap safety-net
// (tasks/node_tuning_swap.yaml), hub/infra node-exporter firewall
// (tasks/node_exporter_hub.yaml) and the API-LB VM guard converge
// (tasks/api_lb_guard.yaml).
package hostconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/topology"
)

// ---------- swap (node_tuning_swap.yaml) ----------
//
// Swap is a transient OOM buffer, not real capacity (incident
// 2026-10-02: kine fill debt > cgroup MemoryMax -> metastable OOM
// loop; with swap, hitting memory.max swaps out instead of
// OOM-killing so guards get a window to run):
//   - k0s controllers        -> kine_swap_size_mb (default 12288)
//   - node_exporter_extra_hosts entries with kine_db: true
//                            -> db_swap_size_mb (default 2048)
//   - everything else        -> no swapfile managed

// The ansible include pinned the swapfile path + swappiness per
// class: controllers got swap_path=/swapfile-kine + swappiness 60
// (12G kine-boot buffer); the kine DB include passed NO swap_path
// (the task's /swapfile default) + swappiness 10. Sharing
// /swapfile-kine on the DB VM created a second 2G file + fstab line
// next to the existing /swapfile — 4G total and an orphaned fstab
// entry.
const (
	kineSwapPath = "/swapfile-kine"
	dbSwapPath   = "/swapfile"
)

func (c *cyc) groupSwap() {
	var mb int64
	var path, swDef string
	switch {
	case c.controller():
		mb = c.vi("kine_swap_size_mb")
		if mb <= 0 {
			mb = 12288
		}
		path = kineSwapPath
		swDef = "60" // ansible: swap_swappiness 60 on controllers
	case c.kineDBHost():
		mb = c.vi("db_swap_size_mb")
		if mb <= 0 {
			mb = 2048
		}
		path = dbSwapPath
		swDef = "10" // ansible: swap_swappiness 10 on the kine DB VM
	default:
		return
	}
	// swap_swappiness stays a cluster.yaml override; the default is
	// per-class (60 controller / 10 db — a shared 10 regressed the
	// controller tunable the ansible include set to 60).
	c.ensureSwapfile(path, mb, defStr(c.v("swap_swappiness"), swDef))
}

// kineDBHost — this node's name matches a node_exporter_extra_hosts
// entry carrying kine_db: true (the pgbouncer/postgres SPOF VMs).
func (c *cyc) kineDBHost() bool {
	for _, it := range c.vl("node_exporter_extra_hosts") {
		m, _ := it.(*topology.OMap)
		if m == nil {
			continue
		}
		if strOf(m, "name") != c.r.cfg.NodeName {
			continue
		}
		if v, ok := m.Get("kine_db"); ok {
			switch t := v.(type) {
			case bool:
				return t
			case string:
				return t == "true" || t == "True" || t == "yes" || t == "1"
			case int64:
				return t != 0
			}
			return v != nil
		}
		return false // kine_db unset -> item.kine_db | default(false)
	}
	return false
}

// ensureSwapfile ports node_tuning_swap.yaml: idempotent create
// (fallocate, dd fallback), 0600, mkswap only when blkid sees no swap
// signature, fstab line, swapon, and the swappiness drop-in (sw is
// the caller's per-class value). A file at the wrong size is
// recreated ONLY while not active — an active swapfile is never
// deleted out from under the kernel.
func (c *cyc) ensureSwapfile(path string, mb int64, sw string) {
	r, ctx := c.r, c.ctx
	wantBytes := mb * 1048576
	dst := r.hp(path)
	fi, statErr := os.Stat(dst)
	exists := statErr == nil

	activeOut, _ := r.run(ctx, "swapon", "--show=NAME", "--noheadings")
	active := strings.Contains(activeOut, path)

	if exists && fi.Size() != wantBytes && !active {
		slog.Info("swap: removing wrong-size inactive file", "path", path,
			"size", fi.Size(), "want", wantBytes)
		if err := os.Remove(dst); err != nil {
			slog.Error("swap: remove wrong-size file", "path", path, "err", err)
			return
		}
		exists = false
	}
	if !exists {
		if _, err := r.run(ctx, "fallocate", "-l", fmt.Sprintf("%dM", mb), path); err != nil {
			slog.Warn("swap: fallocate failed — dd fallback", "path", path, "err", err)
			if _, derr := r.run(ctx, "dd", "if=/dev/zero", "of="+path, "bs=1M",
				fmt.Sprintf("count=%d", mb), "status=none"); derr != nil {
				slog.Error("swap: dd create failed", "path", path, "err", derr)
				return
			}
		}
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		slog.Error("swap: chmod 0600 failed", "path", path, "err", err)
		return
	}
	out, _ := r.run(ctx, "blkid", "-o", "value", "-s", "TYPE", path)
	if strings.TrimSpace(out) != "swap" {
		if _, err := r.run(ctx, "mkswap", path); err != nil {
			slog.Error("swap: mkswap failed", "path", path, "err", err)
			return
		}
	}
	// fstab parity (lineinfile regexp '^<path>\s').
	want := path + " none swap sw 0 0"
	fstab, _ := os.ReadFile(r.hp("/etc/fstab"))
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(path) + `\s.*$`)
	var nf []byte
	if re.Match(fstab) {
		nf = re.ReplaceAll(fstab, []byte(want))
	} else {
		if len(fstab) > 0 && fstab[len(fstab)-1] != '\n' {
			fstab = append(fstab, '\n')
		}
		nf = append(fstab, []byte(want+"\n")...)
	}
	if string(nf) != string(fstab) {
		r.writeManaged("/etc/fstab", nf, 0o644)
	}
	if !active {
		r.run(ctx, "swapon", path)
	}
	r.writeManaged("/etc/sysctl.d/99-kine-swap.conf",
		[]byte("# Managed by node-config-agent - swap safety-net (node_tuning_swap.yaml)\n"+
			"vm.swappiness = "+sw+"\n"), 0o644)
	r.actions.WithLabelValues("sysctl -w vm.swappiness").Inc()
	r.run(ctx, "sysctl", "-w", "vm.swappiness="+sw)
}

// ---------- hub-metrics-fw (node_exporter_hub.yaml) ----------
//
// Runs on the standalone (HostRoot "/") deployments only — hub
// non-agent nodes and the infra SPOF VMs (api_lb/kine-db) outside the
// mesh: no kubelet => the kube-prometheus-stack node-exporter DS never
// covers them. Converges the textfile drop-in and the HUBMETRICS
// iptables whitelist (mesh node IPs + marker subnet; :9100 has no
// auth so it must be source-gated).

func (c *cyc) groupHubMetricsFW() {
	r, ctx := c.r, c.ctx
	if !r.cfg.Standalone {
		return
	}
	c.hubMetricsNodeExporter()
	r.ensureDir("/var/lib/node-exporter/textfile", 0o755)
	r.ensureDir("/etc/systemd/system/prometheus-node-exporter.service.d", 0o755)
	if ch, _ := r.writeManaged(
		"/etc/systemd/system/prometheus-node-exporter.service.d/textfile.conf",
		[]byte(`# Managed by node-config-agent tasks/node_exporter_hub.yaml
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --collector.textfile.directory=/var/lib/node-exporter/textfile
`), 0o644); ch {
		r.daemonReload(ctx)
		r.restartService(ctx, "prometheus-node-exporter.service")
	}
	r.run(ctx, "sh", "-c", c.hubMetricsScript())
	r.ensureService(ctx, "prometheus-node-exporter.service", true, true)
}

// hubMetricsNodeExporter ports the node_exporter_hub.yaml install
// chain: dpkg-query status+version check → pinned get_url → sha256
// verify → `apt deb:` install. Skipping it left a bare VM with the
// unit enabled+started but no package — enable failed (or worse,
// silently no-op'd) while every other step "converged" green.
//
// The pins reuse the defaults.yaml var names verbatim
// (interdc_nexp_version / interdc_nexp_deb_{url,sha256,file}) so the
// versions.yaml sync path keeps working. interdc_nexp_deb_file
// defaults to the URL basename, same as `{{ interdc_nexp_deb_url |
// basename }}`.
func (c *cyc) hubMetricsNodeExporter() {
	r, ctx := c.r, c.ctx
	ver := c.v("interdc_nexp_version")
	url := c.v("interdc_nexp_deb_url")
	sum := c.v("interdc_nexp_deb_sha256")
	file := c.v("interdc_nexp_deb_file")
	if file == "" {
		file = pathpkg.Base(url)
	}
	if ver == "" || url == "" || sum == "" || file == "" || file == "." {
		return // nothing pinned — nothing to install
	}
	out, _ := r.run(ctx, "dpkg-query", "-W",
		"-f=${Status} ${Version}", "prometheus-node-exporter")
	if strings.Contains(out, "install ok installed") && strings.Contains(out, ver) {
		return // right version already installed — ansible skipped the whole chain
	}
	// Host path /tmp/<file> (get_url dest). Download to the
	// HostRoot-joined path so the agent fs op lands on the host file
	// the runner then installs. download() verifies the sha256 as it
	// streams (the get_url checksum + sha256sum -c tasks folded into
	// one step); a staged file that already matches the pin is not
	// re-fetched.
	local := r.hp("/tmp/" + file)
	if !(fileExistsNoRoot(local) && sha256FileOK(local, sum)) {
		if err := nexpDownload(ctx, url, local, sum); err != nil {
			slog.Error("hub-metrics-fw: node_exporter deb download failed",
				"url", url, "err", err)
			return
		}
	}
	// ansible apt deb: => apt-get on the deb path (dep resolution
	// included); the runner sees host paths, not HostRoot-joined.
	if _, err := r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "install", "-y", "/tmp/"+file); err != nil {
		slog.Error("hub-metrics-fw: node_exporter deb install failed",
			"deb", "/tmp/"+file, "err", err)
	}
}

// nexpDownload mirrors download() (groups2.go) but honours the
// ansible get_url timeout=300 — the api-lb/db infra VMs this runs
// on have very slow egress, and the ~4.5MB deb over ~15KB/s needs
// minutes (the 2026-09-24 hub-converge run failed on the default
// ~10s read timeout). Kept local rather than changing the shared
// helper's contract for coredns/nebula.
func nexpDownload(ctx context.Context, url, dst, wantSHA256 string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 300 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".dl"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	f.Close()
	if err != nil {
		return err
	}
	if wantSHA256 != "" && !strings.EqualFold(wantSHA256, fmt.Sprintf("%x", h.Sum(nil))) {
		os.Remove(tmp)
		return fmt.Errorf("download %s: sha256 mismatch", url)
	}
	return os.Rename(tmp, dst)
}

// hubMetricsExtraPorts — hub_metrics_extra_ports from cluster.yaml
// (e.g. 2380 kine /metrics, 2381; KHONG bat tren cicd — etcd owns 2380
// there). Numeric entries only.
func (c *cyc) hubMetricsExtraPorts() []string {
	var out []string
	for _, it := range c.vl("hub_metrics_extra_ports") {
		s := strings.TrimSpace(fmt.Sprint(it))
		if regexp.MustCompile(`^[0-9]+$`).MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

// hubMetricsScript renders the idempotent HUBMETRICS rebuild — the
// ansible shell task verbatim: flush the chain, per port ACCEPT each
// mesh IP + the marker subnet then DROP, hook INPUT once, persist
// when netfilter-persistent exists.
func (c *cyc) hubMetricsScript() string {
	var ips []string
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if ip := nodeIPStr(om, "ip"); ip != "" {
			ips = append(ips, ip)
		}
	}
	mb := c.markerBase()
	var sb strings.Builder
	sb.WriteString("iptables -N HUBMETRICS 2>/dev/null; iptables -F HUBMETRICS;")
	for _, mport := range append([]string{"9100", "9115"}, c.hubMetricsExtraPorts()...) {
		for _, ip := range ips {
			fmt.Fprintf(&sb, " iptables -A HUBMETRICS -p tcp -s %s --dport %s -j ACCEPT;", ip, mport)
		}
		fmt.Fprintf(&sb, " iptables -A HUBMETRICS -p tcp -s %s.0/24 --dport %s -j ACCEPT;", mb, mport)
		fmt.Fprintf(&sb, " iptables -A HUBMETRICS -p tcp --dport %s -j DROP;", mport)
		fmt.Fprintf(&sb, " iptables -C INPUT -p tcp --dport %s -j HUBMETRICS 2>/dev/null"+
			" || iptables -I INPUT 1 -p tcp --dport %s -j HUBMETRICS;", mport, mport)
	}
	sb.WriteString(" command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save || true")
	return sb.String()
}

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

	// prereqs — best-effort like ansible failed_when: false.
	r.run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "socat", "curl")

	// tmpfiles.d: recreate the bind-mount source owned by the
	// container's haproxy uid on every boot (/run is tmpfs — docker
	// auto-creating it root:root crash-loops the VIP).
	r.writeManaged("/etc/tmpfiles.d/api-lb-guard.conf",
		[]byte(fmt.Sprintf(`# api-lb-guard: bind-mount source cho haproxy admin socket.
# owner 99 = uid user `+"`haproxy`"+` trong image haproxy:*-alpine.
d %s 0755 99 99 -
`, sockDir)), 0o644)
	if err := os.MkdirAll(r.hp(sockDir), 0o755); err == nil {
		if err := os.Chown(r.hp(sockDir), 99, 99); err != nil {
			slog.Warn("api-lb-vm: chown 99 sock dir failed", "dir", sockDir, "err", err)
		}
	} else {
		slog.Error("api-lb-vm: sock dir create failed", "dir", sockDir, "err", err)
	}

	// journald persistence — the only drain-audit history on these
	// out-of-inventory VMs (incident 2026-10-09: cloned image left
	// journals under a stale machine-id dir, orphaned on next boot).
	r.ensureDir("/etc/systemd/journald.conf.d", 0o755)
	jch, _ := r.writeManaged("/etc/systemd/journald.conf.d/50-api-lb-guard.conf",
		[]byte(`# api-lb-guard: persistent journal de audit lich su drain cua
# guard qua reboot. Cap 500M: VM chi chay haproxy + agent, log nho.
[Journal]
Storage=persistent
SystemMaxUse=500M
`), 0o644)
	mid := ""
	if b, err := os.ReadFile(r.hp("/etc/machine-id")); err == nil {
		mid = strings.TrimSpace(string(b))
	}
	jdirChanged := false
	if mid != "" {
		if !r.fileExists("/var/log/journal/" + mid) {
			jdirChanged = true
		}
		if err := os.MkdirAll(r.hp("/var/log/journal/"+mid), 0o755); err == nil {
			os.Chmod(r.hp("/var/log/journal/"+mid), 0o2755)
			r.run(ctx, "chgrp", "systemd-journal", "/var/log/journal/"+mid)
		}
	}
	if jch || jdirChanged {
		r.restartService(ctx, "systemd-journald.service")
	}
	if mid != "" {
		// Fold orphaned *.journal files (stale machine-id dirs) into
		// the current mid dir — same mv-with-rename dance as ansible.
		r.run(ctx, "sh", "-c", fmt.Sprintf(`mid=%q
for f in /var/log/journal/*/*.journal; do
  [ -e "$f" ] || continue
  case "$f" in "/var/log/journal/$mid/"*) continue ;; esac
  base=$(basename "$f")
  dest="/var/log/journal/$mid/$base"
  [ -e "$dest" ] && dest="/var/log/journal/$mid/orphan-$base"
  mv "$f" "$dest" || echo "WARN: khong move duoc $f"
done`, mid))
	}

	c.apiLBHaproxy(container, sockDir, socket)

	// guard conf (lbg_* host-var parity).
	conf := fmt.Sprintf(`# /etc/api-backend-guard.conf — managed by node-host-agent hostconfig
# (port of hub_converge.yaml api_lb_guard scope). KHONG sua tay —
# converge ghi de. Sua vars api_lb_guard_vms trong vars/cluster.yaml.
MODE=%s

# "haproxy_server_name=ip:port" — name PHAI trung `+"`server <name>`"+` line
# trong backend %s cua haproxy tren VM nay.
API_BACKENDS="%s"

HAPROXY_BACKEND=%s
# Disable/enable duoc ap len TAT CA backends nay (controller wedge don
# ca api lane lan konnectivity tunnel — su co 2026-10-07). Server khong
# ton tai trong 1 backend la no-op.
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
	r.ensureDir("/etc/api-backend-guard", 0o700)
	if err := os.Chmod(r.hp("/etc/api-backend-guard"), 0o700); err != nil {
		slog.Warn("api-lb-vm: chmod 0700 credential dir failed", "err", err)
	}
	r.writeManaged("/etc/api-backend-guard.conf", []byte(conf), 0o644)

	// the shell guard is retired — prune covers it globally too, but
	// sweep it here so this group is self-contained.
	r.run(ctx, "systemctl", "disable", "--now", "api-backend-guard.timer", "api-backend-guard.service")
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
		slog.Error("api-lb-vm: docker inspect failed — skipping haproxy converge",
			"container", container, "err", err)
		return
	}
	var ins []lbgInspect
	if err := json.Unmarshal([]byte(out), &ins); err != nil || len(ins) == 0 {
		slog.Error("api-lb-vm: docker inspect unparseable — skipping haproxy converge",
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
		slog.Error("api-lb-vm: cannot locate compose file or haproxy.cfg — "+
			"kiem tra tay VM nay", "container", container,
			"compose", composeFile, "cfg", cfgPath)
		return
	}
	composeDir := filepath.Dir(composeFile)

	cfgChanged := false
	if b, err := os.ReadFile(r.hp(cfgPath)); err == nil &&
		!strings.Contains(string(b), "stats socket") {
		nb := "# BEGIN api-lb-guard: admin socket cho guard drain backend\n" +
			"global\n" +
			"    stats socket /run/haproxy/admin.sock mode 660 level admin\n" +
			"    stats timeout 30s\n" +
			"# END api-lb-guard: admin socket cho guard drain backend\n" +
			string(b)
		cfgChanged, _ = r.writeManaged(cfgPath, []byte(nb), 0o644)
	}

	composeChanged := false
	if cb, err := os.ReadFile(r.hp(composeFile)); err == nil {
		mountRe := regexp.MustCompile(`(?m)^\s*-\s*["']?` +
			regexp.QuoteMeta(sockDir) + `:/run/haproxy["']?`)
		if !mountRe.Match(cb) {
			line := "      - " + sockDir + ":/run/haproxy"
			ns := lineInFile(string(cb), `\A\z`, line, lbgSockMountRe.String())
			composeChanged, _ = r.writeManaged(composeFile, []byte(ns), 0o644)
		}
	}

	// validate before touching the live container — a bad cfg never
	// reaches the VIP.
	if cfgChanged || composeChanged {
		if _, err := r.run(ctx, "docker", "run", "--rm",
			"-v", cfgPath+":/tmp/haproxy.cfg:ro",
			image, "haproxy", "-c", "-f", "/tmp/haproxy.cfg"); err != nil {
			slog.Error("api-lb-vm: haproxy -c failed — not recreating/restarting",
				"err", err)
			return
		}
	}
	switch {
	case composeChanged || !sockMounted:
		// ~2-5s VIP blip — only on first setup or real drift.
		r.run(ctx, "sh", "-c",
			fmt.Sprintf("cd %s && docker compose -f %s up -d",
				sq(composeDir), sq(composeFile)))
	case cfgChanged:
		r.run(ctx, "docker", "restart", container)
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
	slog.Warn("api-lb-vm: haproxy admin socket did not appear in 30s",
		"socket", socket)
}

// ---------- Phase 3: kine.service (tach kine khoi k0scontroller) ----------
//
// Kine embedded trong k0scontroller chia cgroup + lifecycle voi
// apiserver: mot kine OOM (catch-up storm sau compact) keo ca
// controller vao metastable OOM loop (incident 2026-10-02 —
// /swapfile-kine la band-aid cho dung chung cgroup do). Tach kine
// thanh unit systemd RIENG co MemoryMax/GOMEMLIMIT boundary rieng:
// kine OOM chi kine bi kill+restart, apiserver mat storage tam thoi
// nhung khong bi keo theo. k0scontroller ket noi qua kine socket —
// Before= dam bao storage len truoc apiserver.
//
// Gate tuyet doi: chi chay khi NodeName nam trong kine_service_hosts
// (defaults.yaml khai [] => hoan toan off cho den khi cluster.yaml
// list host cutover). Node khong duoc list thi khong touch gi het.

func (c *cyc) groupKineService() {
	r, ctx := c.r, c.ctx
	if !containsSS(c.vs("kine_service_hosts"), r.cfg.NodeName) {
		// NB: khong co rollback — unlist host chi ngung converge, unit
		// dang chay van tiep tuc (co y: khong bao gio giet datastore
		// apiserver chi vi host bi go khoi list).
		return
	}

	// Contract defaults.yaml: kine_endpoint rong = khong render unit.
	// kine khong co DSN se fallback sqlite tren unix socket ma
	// apiserver tro toi -> datastore trong (data loss). Fail closed:
	// giu nguyen last-good, canh bao de operator sua vars.
	ep := c.v("kine_endpoint")
	if ep == "" || ep == "None" {
		slog.Warn("kine.service: kine_endpoint khong duoc cau hinh — bo qua converge")
		return
	}

	// /usr/local/bin/kine pinned qua sha256 — pin thieu thi fail
	// closed ke ca khi file da ton tai (khong bao gio start mot
	// binary khong xac thuc duoc).
	binPath := "/usr/local/bin/kine"
	url, sum := c.v("kine_bin_url"), c.v("kine_bin_sha256")
	if url == "" || url == "None" || sum == "" || sum == "None" {
		slog.Error("kine.service: thieu pin kine_bin_url+kine_bin_sha256 — khong converge")
		return
	}
	binChanged := false
	if !r.fileExists(binPath) || !sha256FileOK(r.hp(binPath), sum) {
		if err := download(ctx, url, r.hp(binPath), sum); err != nil {
			slog.Error("kine.service: kine binary download", "url", url, "err", err)
			return
		}
		binChanged = true
	}
	// Mode drift enforce ca khi hash da dung — binary 0644 khong
	// exec duoc.
	if err := os.Chmod(r.hp(binPath), 0o755); err != nil {
		slog.Error("kine.service: chmod kine binary", "err", err)
		return
	}

	// /etc/kine 0700 + kine.env 0600 — DSN chua DB password nen khong
	// duoc embed vao unit file (unit 0644 doc duoc boi moi user).
	r.ensureDir("/etc/kine", 0o700)
	if err := os.Chmod(r.hp("/etc/kine"), 0o700); err != nil {
		slog.Warn("kine.service: chmod 0700 /etc/kine", "err", err)
	}
	envChanged, _ := r.writeManaged("/etc/kine/kine.env",
		[]byte("# Managed by node-config-agent - kine datastore endpoint (KINE_ENDPOINT)\n"+
			"KINE_ENDPOINT="+ep+"\n"), 0o600)
	// writeManaged giu mode cu cua file ton tai — kine.env chua mat
	// khau nen luon enforce lai 0600.
	if err := os.Chmod(r.hp("/etc/kine/kine.env"), 0o600); err != nil {
		slog.Warn("kine.service: chmod 0600 kine.env", "err", err)
	}

	// Defaults mirror invocation k0s dung cho embedded kine:
	// --listen-address=unix://<KineSocketPath> + --metrics-bind-address
	// =:2380 (HUBMETRICS whitelist + hub-kine-metrics ServiceMonitor).
	listen := defStr(c.v("kine_listen_address"), "unix:///run/k0s/kine.sock")
	metrics := defStr(c.v("kine_metrics_bind_address"), ":2380")
	// unix socket: /run la tmpfs — tao parent dir truoc start (dir do
	// k0scontroller tao, ma no start SAU vi Before=), va cho socket
	// bind xong moi thoa Before= (Type=simple danh "started" ngay khi
	// exec -> k0scontroller co the chay khi socket chua ton tai).
	execPre, execPost := "", ""
	if sock := strings.TrimPrefix(listen, "unix://"); sock != listen {
		execPre = "ExecStartPre=/usr/bin/mkdir -p " + filepath.Dir(sock) + "\n"
		execPost = "ExecStartPost=/bin/sh -c 'i=0; while [ ! -S " + sock +
			" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done'\n"
	}
	unitChanged, _ := r.writeManaged("/etc/systemd/system/kine.service", []byte(fmt.Sprintf(`# Managed by node-config-agent - Phase 3: tach kine khoi k0scontroller.
# Boundary cgroup RIENG: kine OOM khong keo apiserver vao OOM loop
# (su co 2026-10-02). GOMEMLIMIT 1500MiB < MemoryMax 2G de Go GC danh
# truoc khi cham cgroup limit; GOGC=50 giam heap growth giua 2 chu ky.
[Unit]
Description=kine (etcd3 API shim -> external datastore)
Documentation=file:/etc/kine/kine.env
After=network-online.target
Wants=network-online.target
# Storage phai len TRUOC k0scontroller — apiserver khong boot khi
# endpoint chet.
Before=k0scontroller.service

[Service]
Environment=GOMEMLIMIT=1500MiB
Environment=GOGC=50
# KINE_ENDPOINT nam trong /etc/kine/kine.env (0600, chua DB password).
EnvironmentFile=/etc/kine/kine.env
%s%sExecStart=/usr/local/bin/kine --listen-address=%s --metrics-bind-address=%s
MemoryMax=2G
MemorySwapMax=0
# OOMScoreAdjust am: kernel kill cac process khac truoc kine (data-path
# cua apiserver); CPUWeight cao giu kine duoi ap luc CPU.
OOMScoreAdjust=-500
CPUWeight=2000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, execPre, execPost, listen, metrics)), 0o644)
	if unitChanged {
		r.daemonReload(ctx)
	}
	r.ensureService(ctx, "kine.service", true, true)
	// start la no-op tren unit dang chay — binary/env/unit moi chi co
	// tac dung sau restart nen moi thay doi input deu restart (pattern
	// y nhu groupAPILB cfgChanged||nftChanged).
	if binChanged || envChanged || unitChanged {
		r.restartService(ctx, "kine.service")
	}
}
