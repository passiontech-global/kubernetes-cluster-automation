// groups_hub.go — task groups ported from hub_converge.yaml
// scopes: swap safety-net
// (tasks/node_tuning_swap.yaml), hub/infra node-exporter firewall
// (tasks/node_exporter_hub.yaml) and the API-LB VM guard converge
// (tasks/api_lb_guard.yaml).
package hostconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
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

	activeOut, activeErr := r.run(ctx, "swapon", "--show=NAME", "--noheadings")
	if activeErr != nil {
		// Fail closed: with no probe result we cannot tell whether the
		// file is live swap — removing/recreating an ACTIVE swapfile
		// pulls the kernel's swap target out from under it. Skip the
		// cycle instead of guessing inactive.
		c.err("swap: swapon --show failed — cannot determine active state; skipping cycle",
			"path", path, "error", activeErr)
		return
	}
	// exact NAME-column match — a substring probe would mark /swapfile
	// active just because /swapfile-kine is listed (independent files).
	active := false
	for _, name := range strings.Split(activeOut, "\n") {
		if strings.TrimSpace(name) == path {
			active = true
			break
		}
	}

	if exists && fi.Size() != wantBytes && !active {
		logger().Info("swap: removing wrong-size inactive file", "path", path,
			"size", fi.Size(), "want", wantBytes)
		if err := os.Remove(dst); err != nil {
			c.err("swap: remove wrong-size file", "path", path, "error", err)
			return
		}
		exists = false
	}
	if !exists {
		if _, err := r.run(ctx, "fallocate", "-l", fmt.Sprintf("%dM", mb), path); err != nil {
			// Best-effort primary path — dd below is the fallback;
			// only its failure counts.
			logger().Warn("swap: fallocate failed — dd fallback", "path", path, "error", err)
			if _, derr := r.run(ctx, "dd", "if=/dev/zero", "of="+path, "bs=1M",
				fmt.Sprintf("count=%d", mb), "status=none"); derr != nil {
				c.err("swap: dd create failed", "path", path, "error", derr)
				return
			}
		}
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		c.err("swap: chmod 0600 failed", "path", path, "error", err)
		return
	}
	out, _ := r.run(ctx, "blkid", "-o", "value", "-s", "TYPE", path)
	if strings.TrimSpace(out) != "swap" {
		if _, err := r.run(ctx, "mkswap", path); err != nil {
			c.err("swap: mkswap failed", "path", path, "error", err)
			return
		}
	}
	// fstab parity (lineinfile regexp '^<path>\s').
	want := path + " none swap sw 0 0"
	fstab, fstabErr := os.ReadFile(r.hp("/etc/fstab"))
	if fstabErr != nil && !os.IsNotExist(fstabErr) {
		// Best-effort pre-warning — a failed fstab write is counted
		// by writeManaged's noteErr below.
		logger().Warn("swap: cannot read /etc/fstab — swap fstab entry will fail",
			"error", fstabErr)
	}
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
		if _, err := r.run(ctx, "swapon", path); err != nil {
			c.err("swap: swapon failed — file exists but swap not active",
				"path", path, "error", err)
		}
	}
	r.writeManaged("/etc/sysctl.d/99-kine-swap.conf",
		[]byte("# Managed by node-config-agent - swap safety-net (node_tuning_swap.yaml)\n"+
			"vm.swappiness = "+sw+"\n"), 0o644)
	r.actions.WithLabelValues("sysctl -w vm.swappiness").Inc()
	if _, err := r.run(ctx, "sysctl", "-w", "vm.swappiness="+sw); err != nil {
		c.err("swap: sysctl -w vm.swappiness failed — drop-in converged, live value unchanged",
			"value", sw, "error", err)
	}
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
	if s := c.hubMetricsScript(); s != "" {
		r.run(ctx, "sh", "-c", s)
	}
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
		if err := r.nexpDownload(ctx, url, local, sum); err != nil {
			c.err("hub-metrics-fw: node_exporter deb download failed",
				"url", url, "error", err)
			return
		}
	}
	// ansible apt deb: => apt-get on the deb path (dep resolution
	// included); the runner sees host paths, not HostRoot-joined.
	// runLong: dep resolution on a slow-egress VM outlives the
	// interactive budget.
	if _, err := r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "install", "-y", "/tmp/"+file); err != nil {
		c.err("hub-metrics-fw: node_exporter deb install failed",
			"deb", "/tmp/"+file, "error", err)
	}
}

// nexpDownload mirrors r.download (groups_tuning.go) but floors the
// client timeout at the ansible get_url timeout=300 — the api-lb/db
// infra VMs this runs on have very slow egress, and the ~4.5MB deb
// over ~15KB/s needs minutes (the 2026-09-24 hub-converge run failed
// on the default ~10s read timeout). A Config.HTTPTimeout ABOVE the
// floor still wins.
func (r *Reconciler) nexpDownload(ctx context.Context, url, dst, wantSHA256 string) error {
	to := r.cfg.HTTPTimeout
	if to < 300*time.Second {
		to = 300 * time.Second
	}
	return downloadFile(ctx, url, dst, wantSHA256, to)
}

// hubMetricsExtraPorts — hub_metrics_extra_ports from cluster.yaml
// (e.g. 2380 kine /metrics, 2381; do NOT enable on cicd — etcd owns
// 2380 there). Numeric entries only.
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
// when netfilter-persistent exists. Returns "" when a vars-derived
// IP/port fails the shell-charset gate — the whole script is skipped
// rather than interpolating a possible injection.
func (c *cyc) hubMetricsScript() string {
	var ips []string
	safe := c.shMarkerBase("interdc_marker_base", c.markerBase())
	for _, k := range c.t.Nodes.Keys() {
		nv, _ := c.t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if ip := nodeIPStr(om, "ip"); ip != "" {
			safe = c.shIPCIDR("mesh node ip", ip) && safe
			ips = append(ips, ip)
		}
	}
	ports := append([]string{"9100", "9115"}, c.hubMetricsExtraPorts()...)
	for _, p := range ports {
		// *Req: every entry lands in a --dport — an empty port is a
		// malformed rule, not "cannot inject".
		safe = c.shPortReq("hubmetrics port", p) && safe
	}
	if !safe {
		return ""
	}
	mb := c.markerBase()
	var sb strings.Builder
	sb.WriteString("iptables -N HUBMETRICS 2>/dev/null; iptables -F HUBMETRICS;")
	for _, mport := range ports {
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

// ---------- journald persistence (standalone hosts) ----------
//
// DaemonSet nodes get persistent journals as a mount side-effect:
// the pod's /var/log/journal hostPath is DirectoryOrCreate, and a
// Storage=auto journald goes persistent once the dir exists at its
// start. The standalone deployments (interdc hubs, k0s controllers,
// infra VMs) had no equivalent converge: a journald that started
// before the dir existed — or whose journal files were
// deleted/vacuumed under it — writes nowhere and never recovers on
// its own (cicd controller 103.186.101.30, 2026-11:
// /var/log/journal/<machine-id> existed but EMPTY, journalctl
// answered "No journal files were found." and the journal-unreadable
// watchdog latch fired with nothing remediating it). groupBase runs
// this on every standalone host before the integrity probe so a
// restart the probe prescribes lands on Storage=persistent.

// journaldPersistence converges the generic persistent-storage
// drop-in on standalone hosts — a no-op on DaemonSet nodes, where
// the /var/log/journal hostPath mount already flips Storage=auto.
func (c *cyc) journaldPersistence() {
	if !c.r.cfg.Standalone {
		return
	}
	c.journaldStorage("/etc/systemd/journald.conf.d/50-node-config-agent.conf",
		[]byte(`# Managed by node-config-agent — persistent journald on standalone
# hosts (no kubelet hostPath to flip Storage=auto). A journald that
# started before /var/log/journal existed, or lost its files under it,
# writes nowhere until restarted (cicd controller incident 2026-11).
[Journal]
Storage=persistent
`))
}

// journaldStorage converges one journald.conf.d drop-in plus the
// machine-id journal dir, restarts systemd-journald when the drop-in
// changed or the dir was missing — journald only re-scans storage on
// start, so a dir created under a running journald stays invisible
// without the bounce — and folds orphaned *.journal files (stale
// machine-id dirs, e.g. cloned images) into the live dir. The restart
// is recorded on c.journaldRestarted so journaldIntegrity does not
// spend its restart budget on a second bounce in the same cycle.
func (c *cyc) journaldStorage(dropinPath string, dropin []byte) {
	r, ctx := c.r, c.ctx
	r.ensureDir("/etc/systemd/journald.conf.d", 0o755)
	ch, _ := r.writeManaged(dropinPath, dropin, 0o644)
	created := c.ensureJournalDir()
	if ch || created {
		r.restartService(ctx, "systemd-journald.service")
		c.journaldRestarted = true
	}
	c.journaldOrphanFold()
}

// ensureJournalDir creates /var/log/journal/<machine-id> with the
// 02755 root:systemd-journal shape journald expects (the same
// ownership systemd's own creation uses). Returns true when the dir
// was missing before this cycle — the caller restarts journald so
// the fresh dir is actually seen. chmod/chgrp failures are
// best-effort warns: drifted perms weaken the setup but never block
// the converge.
func (c *cyc) ensureJournalDir() bool {
	r, ctx := c.r, c.ctx
	mid := r.machineID()
	if mid == "" {
		return false
	}
	dir := "/var/log/journal/" + mid
	created := !r.fileExists(dir)
	if err := os.MkdirAll(r.hp(dir), 0o755); err != nil {
		logger().Warn("journald: journal dir create failed — persistence may not take effect",
			"dir", dir, "error", err)
		return created
	}
	// os.ModeSetgid|0755, not 0o2755: os.Chmod maps the abstract
	// FileMode flags — the raw 0o2000 bit is silently dropped (the
	// api-lb block this replaces had that latent bug).
	if err := os.Chmod(r.hp(dir), os.ModeSetgid|0o755); err != nil {
		logger().Warn("journald: chmod journal dir failed", "dir", dir, "error", err)
	}
	if _, err := r.run(ctx, "chgrp", "systemd-journal", dir); err != nil {
		logger().Warn("journald: chgrp journal dir failed", "dir", dir, "error", err)
	}
	return created
}

// journaldOrphanFold moves *.journal files stranded under stale
// machine-id dirs into the live one — same mv-with-rename dance as
// ansible (incident 2026-10-09 cloned-image journals).
func (c *cyc) journaldOrphanFold() {
	r, ctx := c.r, c.ctx
	mid := r.machineID()
	if mid == "" {
		return
	}
	// sh -c runs in the host namespaces via the Runner — unjoined
	// host paths, not HostRoot-prefixed.
	r.run(ctx, "sh", "-c", fmt.Sprintf(`mid=%q
for f in /var/log/journal/*/*.journal; do
  [ -e "$f" ] || continue
  case "$f" in "/var/log/journal/$mid/"*) continue ;; esac
  base=$(basename "$f")
  dest="/var/log/journal/$mid/$base"
  [ -e "$dest" ] && dest="/var/log/journal/$mid/orphan-$base"
  mv "$f" "$dest" || echo "WARN: could not move $f"
done`, mid))
}

// machineID reads the host machine-id — the journal storage dir name.
func (r *Reconciler) machineID() string {
	if b, err := os.ReadFile(r.hp("/etc/machine-id")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
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

	// prereqs — best-effort like ansible failed_when: false. runLong:
	// apt on a slow-egress infra VM outlives the interactive budget.
	r.runLong(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "socat", "curl")

	// tmpfiles.d: recreate the bind-mount source owned by the
	// container's haproxy uid on every boot (/run is tmpfs — docker
	// auto-creating it root:root crash-loops the VIP).
	r.writeManaged("/etc/tmpfiles.d/api-lb-guard.conf",
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
	r.ensureDir("/etc/api-backend-guard", 0o700)
	if err := os.Chmod(r.hp("/etc/api-backend-guard"), 0o700); err != nil {
		c.err("api-lb-vm: chmod 0700 credential dir failed — guard token left readable",
			"error", err)
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

// ---------- etcdctl (embedded-etcd controllers) ----------
//
// k0s extracts etcd into /var/lib/k0s/bin but does NOT ship etcdctl —
// and both consumers look for it THERE, not in /usr/local/bin:
// controllerhygiene's checkEtcdQuota gates on <K0sDir>/bin/etcdctl +
// pki/etcd/ca.crt (result="no_etcdctl" on cicd's controller today) and
// the rescue-etcd subcommand execs the same path. So the managed
// binary goes to <k0s>/bin/etcdctl — pinning it in /usr/local/bin
// would not re-enable the guard.
//
// Version MUST match the etcd k0s bundles — k0s.default ->
// embedded-bins/Makefile.variables etcd_version in the fluxcd repo
// (k0s v1.37.1+k0s.0 -> etcd 3.7.3). Pins: etcdctl_version +
// etcdctl_tgz_{url,sha256,file} in defaults.yaml (synced from
// versions.yaml pins.etcdctl-tgz — sha256 of the release tarball, not
// of the extracted binary).
//
// Gate: only hosts running embedded etcd — k0scontroller.service
// exists AND pki/etcd/ca.crt is present (the same composite
// checkEtcdQuota requires). Kine-split controllers carry the unit but
// not the pki dir, so they are left alone; workers and infra VMs are
// never touched.
func (c *cyc) groupEtcdctl() {
	if !c.controller() ||
		!c.r.fileExists("/var/lib/k0s/pki/etcd/ca.crt") {
		return
	}
	c.etcdctlInstallBinary()
}

// etcdctlInstallBinary ports the nebula/coredns managed-binary
// pattern: <bin> version probe -> sha256-pinned tarball (staged or
// downloaded) -> untarInstall (tmp+rename).
func (c *cyc) etcdctlInstallBinary() {
	r, ctx := c.r, c.ctx
	ver, sum, url := c.v("etcdctl_version"), c.v("etcdctl_tgz_sha256"), c.v("etcdctl_tgz_url")
	tgz := defStr(c.v("etcdctl_tgz_file"), pathpkg.Base(url))
	if ver == "" || ver == "None" || url == "" || url == "None" ||
		sum == "" || sum == "None" {
		c.err("etcdctl: missing etcdctl_version+etcdctl_tgz_{url,sha256} pins — not converging")
		return
	}
	bin := "/var/lib/k0s/bin/etcdctl"
	if out, err := r.run(ctx, bin, "version"); err == nil &&
		strings.Contains(out, ver) {
		return
	}
	local := filepath2(r.cfg.DownloadDir, tgz)
	if fileExistsNoRoot(local) {
		// same contract as T5b/T9: verify the STAGED file every run —
		// a corrupted/operator-swapped tarball must not install.
		if !sha256FileOK(local, sum) {
			c.err("etcdctl: staged tgz sha256 mismatch — not installing",
				"file", local, "sha256", sum)
			return
		}
	} else if err := r.download(ctx, url, local, sum); err != nil {
		c.err("etcdctl: tgz download", "url", url, "file", local, "error", err)
		return
	}
	// /var/lib/k0s/bin exists on every k0s host, but untarInstall does
	// not create parents — keep the install self-contained.
	if err := r.ensureDir("/var/lib/k0s/bin", 0o755); err != nil {
		// ensureDir already counted the failure via noteErr — log
		// context only, do not count the same fault twice.
		logger().Error("etcdctl: ensure k0s bin dir", "error", err)
		return
	}
	if err := untarInstall(local, "etcdctl", r.hp(bin), 0o755); err != nil {
		c.err("etcdctl: install", "file", local, "dst", bin, "error", err)
	}
}

// ---------- Phase 3: kine.service (split kine out of k0scontroller) ----------
//
// Kine embedded in k0scontroller shares cgroup + lifecycle with the
// apiserver: one kine OOM (catch-up storm after compact) drags the
// whole controller into a metastable OOM loop (incident 2026-10-02 —
// /swapfile-kine is the band-aid for that shared cgroup). Splitting
// kine into its OWN systemd unit with its own MemoryMax/GOMEMLIMIT
// boundary means a kine OOM only kills+restarts kine — the apiserver
// loses storage temporarily but is not dragged down with it.
// k0scontroller connects over the kine socket — Before= guarantees
// storage is up before the apiserver.
//
// Hard gate: only runs when NodeName is listed in kine_service_hosts
// (defaults.yaml declares [] => fully off until cluster.yaml lists
// cutover hosts). An unlisted node is never touched.

func (c *cyc) groupKineService() {
	r, ctx := c.r, c.ctx
	if !containsSS(c.vs("kine_service_hosts"), r.cfg.NodeName) {
		// NB: no rollback — unlisting a host only stops converge, a
		// running unit keeps running (deliberate: never kill the
		// apiserver datastore just because a host left the list).
		return
	}

	// defaults.yaml contract: empty kine_endpoint = do not render the
	// unit. A kine with no DSN falls back to sqlite on the unix socket
	// the apiserver points at -> empty datastore (data loss). Fail
	// closed: keep last-good, warn so the operator fixes the vars.
	ep := c.v("kine_endpoint")
	if ep == "" || ep == "None" {
		c.err("kine.service: kine_endpoint not configured — skipping converge")
		return
	}

	// /usr/local/bin/kine is sha256-pinned — a missing pin fails
	// closed even when the file already exists (never start a binary
	// that cannot be verified).
	binPath := "/usr/local/bin/kine"
	url, sum := c.v("kine_bin_url"), c.v("kine_bin_sha256")
	if url == "" || url == "None" || sum == "" || sum == "None" {
		c.err("kine.service: missing kine_bin_url+kine_bin_sha256 pins — not converging")
		return
	}
	binChanged := false
	if !r.fileExists(binPath) || !sha256FileOK(r.hp(binPath), sum) {
		if err := r.download(ctx, url, r.hp(binPath), sum); err != nil {
			c.err("kine.service: kine binary download", "url", url, "error", err)
			return
		}
		binChanged = true
	}
	// Enforce mode drift even when the hash already matches — a 0644
	// binary cannot exec.
	if err := os.Chmod(r.hp(binPath), 0o755); err != nil {
		c.err("kine.service: chmod kine binary", "path", binPath, "error", err)
		return
	}

	// /etc/kine 0700 + kine.env 0600 — the DSN carries the DB password
	// so it must not be embedded in the unit file (a 0644 unit is
	// readable by every user).
	r.ensureDir("/etc/kine", 0o700)
	if err := os.Chmod(r.hp("/etc/kine"), 0o700); err != nil {
		c.err("kine.service: chmod 0700 /etc/kine — endpoint dir left readable",
			"path", "/etc/kine", "error", err)
	}
	envChanged, _ := r.writeManaged("/etc/kine/kine.env",
		[]byte("# Managed by node-config-agent - kine datastore endpoint (KINE_ENDPOINT)\n"+
			"KINE_ENDPOINT="+ep+"\n"), 0o600)
	// writeManaged preserves an existing file's mode — kine.env holds
	// a password so always re-enforce 0600.
	if err := os.Chmod(r.hp("/etc/kine/kine.env"), 0o600); err != nil {
		c.err("kine.service: chmod 0600 kine.env — DB password file left readable",
			"path", "/etc/kine/kine.env", "error", err)
	}

	// Defaults mirror the invocation k0s uses for embedded kine:
	// --listen-address=unix://<KineSocketPath> + --metrics-bind-address
	// =:2380 (HUBMETRICS whitelist + hub-kine-metrics ServiceMonitor).
	listen := defStr(c.v("kine_listen_address"), "unix:///run/k0s/kine.sock")
	metrics := defStr(c.v("kine_metrics_bind_address"), ":2380")
	// unix socket: /run is tmpfs — create the parent dir before start
	// (k0scontroller creates that dir, but it starts AFTER because of
	// Before=), and wait for the socket bind before Before= is
	// satisfied (Type=simple counts "started" at exec -> k0scontroller
	// could start while the socket does not exist yet).
	execPre, execPost := "", ""
	if sock := strings.TrimPrefix(listen, "unix://"); sock != listen {
		execPre = "ExecStartPre=/usr/bin/mkdir -p " + filepath.Dir(sock) + "\n"
		execPost = "ExecStartPost=/bin/sh -c 'i=0; while [ ! -S " + sock +
			" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done'\n"
	}
	unitChanged, _ := r.writeManaged("/etc/systemd/system/kine.service", []byte(fmt.Sprintf(`# Managed by node-config-agent - Phase 3: kine split out of k0scontroller.
# SEPARATE cgroup boundary: a kine OOM does not drag apiserver into
# the OOM loop (incident 2026-10-02). GOMEMLIMIT 1500MiB < MemoryMax 2G
# so Go GC fires before hitting the cgroup limit; GOGC=50 slows heap
# growth between cycles.
[Unit]
Description=kine (etcd3 API shim -> external datastore)
Documentation=file:/etc/kine/kine.env
After=network-online.target
Wants=network-online.target
# Storage must come up BEFORE k0scontroller — apiserver will not boot
# with a dead endpoint.
Before=k0scontroller.service

[Service]
Environment=GOMEMLIMIT=1500MiB
Environment=GOGC=50
# KINE_ENDPOINT lives in /etc/kine/kine.env (0600, holds DB password).
EnvironmentFile=/etc/kine/kine.env
%s%sExecStart=/usr/local/bin/kine --listen-address=%s --metrics-bind-address=%s
MemoryMax=2G
MemorySwapMax=0
# OOMScoreAdjust negative: the kernel kills other processes before
# kine (apiserver data-path); high CPUWeight protects kine under CPU
# pressure.
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
	// start is a no-op on a running unit — a new binary/env/unit only
	// takes effect after restart, so every input change restarts
	// (same pattern as groupAPILB cfgChanged||nftChanged).
	if binChanged || envChanged || unitChanged {
		r.restartService(ctx, "kine.service")
	}
}
