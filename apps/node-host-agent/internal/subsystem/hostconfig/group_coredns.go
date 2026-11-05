// group_coredns.go — T9 coredns stub/hub: binary install, Corefile,
// hub zone authority (db.<zone> + hash serial), resolv.conf repoint
// and the hub zone-record /etc/hosts pins.
package hostconfig

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
)

// ---------- T9 coredns stub + hub ----------
// Port of tasks/node_tuning_coredns_stub.yaml (worker local stub) +
// the hub_converge.yaml mesh-resolver section (hub zone authority).

func (c *cyc) zoneName() string {
	if z := nodeIPStr(c.t.Zone, "zone"); z != "" {
		return z
	}
	return "passiontech.internal"
}

func (c *cyc) groupCoreDNS() {
	r, ctx, t := c.r, c.ctx, c.t
	zone := c.zoneName()
	upstream := defStr(c.v("interdc_stub_public_upstream"), "1.1.1.1 8.8.8.8")
	firstUpstream := strings.Fields(upstream)
	pub1 := "1.1.1.1"
	if len(firstUpstream) > 0 {
		pub1 = firstUpstream[0]
	}
	net := defStr(c.v("interdc_nebula_net"), "interdc")
	// Stub unit After= follows the ACTIVE overlay (ansible template).
	afterUnit := "nebula@" + net + ".service"
	if t.Overlay != "nebula" {
		afterUnit = "tinc@" + defStr(c.v("interdc_tinc_net"), "interdc") + ".service"
	}
	marker := t.Markers[t.MeshName]

	isHub := t.AmLighthouse
	if !isHub && len(t.DNSResolvers) == 0 {
		return // T9 gates entirely on interdc_dns_resolvers | length > 0
	}

	c.corednsInstallBinary()
	_ = r.ensureDir("/etc/coredns", 0o755)

	var corefile, desc string
	if isHub {
		desc = "CoreDNS mesh resolver (" + zone + ")"
		corefile = fmt.Sprintf(`# Managed by hub_converge.yaml - mesh resolver
%s {
    bind %s 127.0.0.1
    file /etc/coredns/db.%s {
        reload 1m
    }
    errors
}
. {
    bind %s 127.0.0.1
    forward . %s {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`, zone, marker, zone, marker, upstream)
	} else {
		desc = "CoreDNS local stub (" + zone + " + cache)"
		resolvers := strings.Join(t.DNSResolvers, " ")
		corefile = fmt.Sprintf(`# Managed by node-config-agent (T9) - local stub, domain-aware
# routing: %s -> mesh resolvers; "." -> public
# upstreams, then the mesh (rescue via tinc).
%s {
    bind 127.0.0.1
    forward . %s {
        policy sequential
        health_check 10s
    }
    errors
}
. {
    bind 127.0.0.1
    forward . %s %s {
        policy sequential
        health_check 10s
    }
    cache 300 {
        serve_stale 1h
    }
    errors
}
`, zone, zone, resolvers, upstream, resolvers)
	}

	cfgChanged := false
	if isHub {
		if zb, err := c.renderZoneFile(); err == nil {
			if ch, _ := r.writeManaged("/etc/coredns/db."+zone, zb, 0o644); ch {
				cfgChanged = true
			}
		} else {
			c.err("T9: zone file render", "zone", zone, "error", err)
		}
	}
	if ch, _ := r.writeManaged("/etc/coredns/Corefile", []byte(corefile), 0o644); ch {
		cfgChanged = true
	}
	_, _ = r.writeManaged("/etc/systemd/system/coredns.service", []byte(fmt.Sprintf(`# Managed by %s
[Unit]
Description=%s
After=network-online.target %s
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile
Restart=always
RestartSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, map[bool]string{true: "hub_converge.yaml", false: "node-config-agent (T9)"}[isHub],
		desc, afterUnit)), 0o644)
	r.daemonReload(ctx)
	r.ensureService(ctx, "coredns.service", true, true)
	if cfgChanged {
		r.restartService(ctx, "coredns.service")
	}

	// Hub: zone record pins make the hub independent of its own
	// resolver (blockinfile interdc-zone-pins).
	if isHub {
		c.pinZoneRecords(zone)
		// dig verify BEFORE repointing resolv.conf — a dead resolver
		// must not leave the hub DNS-less (retries, like ansible until).
		ok := false
		var lastErr error
		for i := 0; i < 15; i++ {
			out, err := r.run(ctx, "dig", "@127.0.0.1", "ns1."+zone, "+short", "+time=3", "+tries=1")
			lastErr = err
			if err == nil && strings.TrimSpace(out) != "" {
				ok = true
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		if !ok {
			c.err("T9/hub: coredns did not answer — resolv.conf NOT repointed",
				"query", "ns1."+zone, "error", lastErr)
			return
		}
	} else {
		// Worker: stub must answer the internal zone before resolv.conf
		// repoints at it (single-shot, ansible failed_when parity).
		if out, err := r.run(ctx, "dig", "@127.0.0.1", c.v("cp_endpoint"), "+short", "+time=3", "+tries=1"); err != nil || strings.TrimSpace(out) == "" {
			c.err("T9: stub does not answer cp_endpoint — resolv.conf NOT repointed",
				"cp_endpoint", c.v("cp_endpoint"), "out", strings.TrimSpace(out), "error", err)
			return
		}
		if fb := c.vs("cp_endpoint_fallback_names"); len(fb) > 0 {
			if out, err := r.run(ctx, "dig", "@127.0.0.1", fb[0], "+short", "+time=3", "+tries=1"); err != nil || strings.TrimSpace(out) == "" {
				c.err("T9: stub fails external recursion — resolv.conf NOT repointed",
					"name", fb[0], "out", strings.TrimSpace(out), "error", err)
				return
			}
		}
	}
	c.writeResolvConf(isHub, pub1)
}

// writeResolvConf captures search/domain/options extras, drops the
// resolved-managed symlink, and writes the static stub resolv.conf
// (worker + hub variants).
func (c *cyc) writeResolvConf(isHub bool, pub1 string) {
	r, ctx, t := c.r, c.ctx, c.t
	extra, _ := r.run(ctx, "sh", "-c",
		`grep -E '^(search|domain|options)' /etc/resolv.conf | grep -vFx 'options timeout:2 attempts:2' || true`)
	dst := r.hp("/etc/resolv.conf")
	if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(dst)
	}
	var rc strings.Builder
	if isHub {
		fmt.Fprintf(&rc, `# Managed by hub_converge.yaml - local coredns first,
# %s + another hub resolver as fallback when the stub dies.
nameserver 127.0.0.1
nameserver %s


`, pub1, pub1)
		own := t.Markers[t.MeshName]
		for _, rz := range t.DNSResolvers {
			if rz != own {
				fmt.Fprintf(&rc, "nameserver %s\n", rz)
				break
			}
		}
	} else {
		fmt.Fprintf(&rc, `# Managed by node-config-agent (T9) - coredns stub first,
# %s + mesh resolver as fallback when the stub dies.
nameserver 127.0.0.1
nameserver %s
nameserver %s
`, pub1, pub1, t.DNSResolvers[0])
	}
	fmt.Fprintf(&rc, "options timeout:2 attempts:2\n%s\n", extra)
	_, _ = r.writeManaged("/etc/resolv.conf", []byte(rc.String()), 0o644)
}

// pinZoneRecords — hub_converge blockinfile parity: full zone records
// + node.<zone> records pinned into /etc/hosts so the hub's own
// services (kine etc.) resolve even when coredns is down.
func (c *cyc) pinZoneRecords(zone string) {
	var blk strings.Builder
	c.eachZoneRecord(func(name, ip string) {
		fmt.Fprintf(&blk, "\n%s %s.%s", ip, name, zone)
	})
	blk.WriteString("\n")
	if c.zoneNodeRecords() {
		blk.WriteString("\n")
		for _, k := range c.t.Nodes.Keys() {
			nv, _ := c.t.Nodes.Get(k)
			om, _ := nv.(*topology.OMap)
			if om == nil {
				continue
			}
			nm := nodeIPStr(om, "name")
			if nm == "" || c.t.Markers[nm] == "" {
				continue
			}
			fmt.Fprintf(&blk, "\n%s %s.node.%s", c.t.Markers[nm], nm, zone)
		}
	}
	block := "# BEGIN interdc-zone-pins managed block\n" +
		strings.TrimPrefix(blk.String(), "\n") + "\n# END interdc-zone-pins managed block\n"
	c.blockInHosts("interdc-zone-pins", block)
}

// eachZoneRecord iterates interdc_dns_zone.records (flat map
// name → {ip|<static> | node|<registry key>}), resolving node refs
// to that node's marker IP.
func (c *cyc) eachZoneRecord(fn func(name, ip string)) {
	recs, _ := c.t.Zone.Get("records")
	rom, _ := recs.(*topology.OMap)
	if rom == nil {
		return
	}
	for _, rn := range rom.Keys() {
		rv, _ := rom.Get(rn)
		rm, _ := rv.(*topology.OMap)
		if rm == nil {
			continue
		}
		if nv, ok := rm.Get("node"); ok {
			// node: <registry key> -> marker of that node's name
			if nvv, ok2 := c.t.Nodes.Get(fmt.Sprint(nv)); ok2 {
				if om, ok3 := nvv.(*topology.OMap); ok3 {
					if mk := c.t.Markers[nodeIPStr(om, "name")]; mk != "" {
						fn(rn, mk)
					}
				}
			}
		} else if iv, ok := rm.Get("ip"); ok {
			fn(rn, fmt.Sprint(iv))
		}
	}
}

func (c *cyc) zoneNodeRecords() bool {
	v, ok := c.t.Zone.Get("node_records")
	if !ok {
		return true // ansible default(true)
	}
	b, _ := v.(bool)
	return b
}

// renderZoneFile builds db.<zone> for hub nodes — hub_converge.yaml
// inline template parity (SOA/NS/A, service + node records, flat
// schema {zone, ttl, records:{name:{ip|node}}, node_records}).
func (c *cyc) renderZoneFile() ([]byte, error) {
	t, zone := c.t, c.zoneName()
	ttl := "60"
	if tv, ok := t.Zone.Get("ttl"); ok && tv != nil {
		ttl = fmt.Sprint(tv)
	}
	var hubs []string
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		if hv, ok := om.Get("hub"); ok {
			if b, _ := hv.(bool); b {
				nm := nodeIPStr(om, "name")
				// A hub without a registry marker would render
				// `nsN IN A ` with empty rdata and coredns rejects
				// the whole zone — pinZoneRecords guard parity.
				if nm == "" || t.Markers[nm] == "" {
					continue
				}
				hubs = append(hubs, nm)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL %s\n", ttl)
	fmt.Fprintf(&b, "@   IN SOA ns1.%s. admin.%s. (\n        %d ; serial=hash(records), changes only when content changes\n        60 15 604800 30 )\n",
		zone, zone, c.zoneSerial())
	b.WriteString("\n") // {% set _hubs %} line
	for i := range hubs {
		fmt.Fprintf(&b, "\n    IN NS ns%d.%s.\n", i+1, zone)
	}
	b.WriteString("\n") // {% endfor %}
	for i, h := range hubs {
		fmt.Fprintf(&b, "\n%-30s IN A %s\n", fmt.Sprintf("ns%d", i+1), t.Markers[h])
	}
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; service records: interdc_dns_zone.yaml\n")
	b.WriteString("; (do NOT use '#' — the coredns/miekg zone parser does not accept\n")
	b.WriteString("; '#' as a comment, only ';' — \"not a TTL\" crashloop 2026-09-16)\n")
	c.eachZoneRecord(func(name, ip string) {
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "%-30s IN A %s\n", name, ip)
		b.WriteString("\n")
	})
	b.WriteString("\n") // {% endfor %}
	b.WriteString("; node records: <tinc_name>.node.<zone> -> marker\n")
	if c.zoneNodeRecords() {
		b.WriteString("\n") // {% if node_records %}
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*topology.OMap)
			if om == nil {
				continue
			}
			nm := nodeIPStr(om, "name")
			if nm == "" || t.Markers[nm] == "" {
				continue
			}
			fmt.Fprintf(&b, "\n%-30s IN A %s\n", nm+".node", t.Markers[nm])
		}
		b.WriteString("\n") // {% endfor %}
	}
	return []byte(b.String()), nil
}

// zoneSerial — ansible: (interdc_nodes|to_json ~ interdc_dns_zone|to_json)
// | hash('sha256') | int(0,16) % 4294967295. Changes only when the
// inputs change (no DNS blip on every converge).
func (c *cyc) zoneSerial() int64 {
	nj, _ := json.Marshal(jsonPlain(c.t.Nodes))
	zj, _ := json.Marshal(jsonPlain(c.t.Zone))
	h := sha256.Sum256(append(nj, zj...))
	i := new(big.Int).SetBytes(h[:])
	i.Mod(i, big.NewInt(4294967295))
	return i.Int64()
}

// jsonPlain renders OMap/List as sorted-key JSON-compatible values.
func jsonPlain(v any) any {
	switch t := v.(type) {
	case *topology.OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = jsonPlain(vv)
		}
		return m
	case *topology.List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = jsonPlain(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonPlain(x)
		}
		return out
	default:
		return v
	}
}

func (c *cyc) corednsInstallBinary() {
	ver := c.v("interdc_coredns_version")
	if ver == "" || ver == "None" {
		// Same empty-pin rule as nebula: "CoreDNS-"+"" matches every
		// -version output (never upgrades) and download("") is a
		// counted bogus fetch. Not pinned = not installed.
		c.err("T9: interdc_coredns_version not pinned — coredns not installed")
		return
	}
	if out, err := c.r.run(c.ctx, "/usr/local/bin/coredns", "-version"); err == nil &&
		strings.Contains(out, "CoreDNS-"+ver) {
		return
	}
	tgz := c.v("interdc_coredns_tgz")
	sum := c.v("interdc_coredns_sha256")
	url := c.v("interdc_coredns_url")
	local := filepath.Join(c.r.cfg.DownloadDir, tgz)
	if fileExistsNoRoot(local) {
		// ansible: sha256sum -c every run when outdated.
		if !sha256FileOK(local, sum) {
			c.err("T9: staged coredns tgz sha256 mismatch — not installing",
				"file", local, "sha256", sum)
			return
		}
	} else if err := c.r.download(c.ctx, url, local, sum); err != nil {
		c.err("T9: coredns download", "url", url, "file", local, "error", err)
		return
	}
	if err := untarInstall(local, "coredns", c.r.hp("/usr/local/bin/coredns"), 0o755); err != nil {
		c.err("T9: coredns install failed — stub will not run",
			"file", local, "error", err)
	}
}
