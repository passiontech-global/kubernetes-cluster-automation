// group_hubmetrics.go — hub/infra node-exporter converge ported from
// hub_converge.yaml (tasks/node_exporter_hub.yaml): pinned deb
// install, textfile drop-in and the HUBMETRICS iptables whitelist on
// standalone hosts the kube-prometheus-stack DS never covers.
package hostconfig

import (
	"context"
	"fmt"
	"os"
	pathpkg "path"
	"regexp"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

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
	_ = r.ensureDir("/var/lib/node-exporter/textfile", 0o755)
	_ = r.ensureDir("/etc/systemd/system/prometheus-node-exporter.service.d", 0o755)
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
		_, _ = r.run(ctx, "sh", "-c", s)
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
	// Skip only when installed >= pin — a NEWER node_exporter
	// (unattended-upgrades/security pocket) already satisfies it,
	// and apt refuses the downgrade anyway (same exit-100 loop
	// class as the T12 haproxy deb, incident 2026-11-05). Older,
	// missing or unparseable falls through to download+install.
	if strings.Contains(out, "install ok installed") {
		if f := strings.Fields(out); len(f) >= 4 {
			if _, err := r.run(ctx, "dpkg", "--compare-versions",
				f[len(f)-1], "ge", ver); err == nil {
				return // installed satisfies the pin — ansible skipped the whole chain
			}
		}
	}
	// Host path /tmp/<file> (get_url dest). Download to the
	// HostRoot-joined path so the agent fs op lands on the host file
	// the runner then installs. download() verifies the sha256 as it
	// streams (the get_url checksum + sha256sum -c tasks folded into
	// one step); a staged file that already matches the pin is not
	// re-fetched.
	local := r.hp("/tmp/" + file)
	if _, ok := c.installManagedBinary(managedBinarySpec{
		name:   "hub-metrics-fw",
		url:    url,
		sum:    sum,
		staged: local,
		// nexpDownload floors the client timeout above HTTPTimeout —
		// the slow-egress infra VMs need minutes for the ~4.5MB deb.
		download: r.nexpDownload,
		downloadErr: func(c *cyc, err error) {
			c.err("hub-metrics-fw: node_exporter deb download failed",
				"url", url, "error", err)
		},
		install: func(c *cyc, _ string) error {
			// ansible apt deb: => apt-get on the deb path (dep resolution
			// included); the runner sees host paths, not HostRoot-joined.
			// runLong: dep resolution on a slow-egress VM outlives the
			// interactive budget.
			_, err := c.r.runLong(c.ctx, "env", "DEBIAN_FRONTEND=noninteractive",
				"apt-get", "install", "-y", "/tmp/"+file)
			return err
		},
		installErr: func(c *cyc, _ string, err error) {
			c.err("hub-metrics-fw: node_exporter deb install failed",
				"deb", "/tmp/"+file, "error", err)
		},
	}); !ok {
		return
	}
}

// nexpDownload mirrors r.download (groups_tuning.go) but floors the
// client timeout at the ansible get_url timeout=300 — the api-lb/db
// infra VMs this runs on have very slow egress, and the ~4.5MB deb
// over ~15KB/s needs minutes (the 2026-09-24 hub-converge run failed
// on the default ~10s read timeout). A Config.HTTPTimeout ABOVE the
// floor still wins.
func (r *Reconciler) nexpDownload(ctx context.Context, url, dst, wantSHA256 string,
	mode os.FileMode) error {
	to := r.cfg.HTTPTimeout
	if to < 300*time.Second {
		to = 300 * time.Second
	}
	return downloadFile(ctx, url, dst, wantSHA256, mode, to)
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
		om, _ := nv.(*jinja.OMap)
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
	sb.WriteString("iptables -w 5 -N HUBMETRICS 2>/dev/null; iptables -w 5 -F HUBMETRICS;")
	for _, mport := range ports {
		for _, ip := range ips {
			fmt.Fprintf(&sb, " iptables -w 5 -A HUBMETRICS -p tcp -s %s --dport %s -j ACCEPT;", ip, mport)
		}
		fmt.Fprintf(&sb, " iptables -w 5 -A HUBMETRICS -p tcp -s %s.0/24 --dport %s -j ACCEPT;", mb, mport)
		fmt.Fprintf(&sb, " iptables -w 5 -A HUBMETRICS -p tcp --dport %s -j DROP;", mport)
		fmt.Fprintf(&sb, " iptables -w 5 -C INPUT -p tcp --dport %s -j HUBMETRICS 2>/dev/null"+
			" || iptables -w 5 -I INPUT 1 -p tcp --dport %s -j HUBMETRICS;", mport, mport)
	}
	sb.WriteString(" command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save || true")
	return sb.String()
}
