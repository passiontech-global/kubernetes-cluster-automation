// group_coredns.go — T9 coredns stub/hub: binary install, Corefile,
// hub zone authority (db.<zone> + hash serial), resolv.conf repoint
// and the hub zone-record /etc/hosts pins.
package hostconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
	// Every scalar interpolated into the Corefile (bind/forward),
	// the unit's After= and the resolv.conf repoint passes cfgScalar
	// — the same gate the kubelet/containerd renders use. A quote,
	// newline or ':' would inject arbitrary Corefile directives (or
	// resolv.conf lines). ONE refusal fails the whole group closed:
	// nothing is written, the previous config keeps serving, the
	// refusals are already counted per value.
	cfgOK := true
	cgate := func(what, v string) string {
		if !c.cfgScalar("coredns: "+what, v) {
			cfgOK = false
			return ""
		}
		return v
	}
	zone = cgate("zone", zone)
	upstream = cgate("interdc_stub_public_upstream", upstream)
	pub1 = cgate("interdc_stub_public_upstream[0]", pub1)
	// net is consumed only through afterUnit (rendered above, gated
	// there) — gate it for the refusal accounting without re-binding
	// the variable (an assignment nothing reads is a lint failure).
	if !c.cfgScalar("coredns: interdc_nebula_net", net) {
		cfgOK = false
	}
	afterUnit = cgate("overlay unit", afterUnit)

	isHub := t.AmLighthouse
	// marker is interpolated ONLY in the hub Corefile (bind line) —
	// workers legitimately carry no marker and don't reference it.
	if isHub {
		marker = cgate("marker", marker)
		// Hub resolv.conf's fallback nameserver line interpolates one
		// DNSResolvers element — the join gate covers every element
		// (workers gate the same join for their resolv.conf branch).
		if len(t.DNSResolvers) > 0 {
			if !c.cfgScalar("coredns: interdc_dns_resolvers",
				strings.Join(t.DNSResolvers, " ")) {
				cfgOK = false
			}
		}
	}
	if !isHub && len(t.DNSResolvers) == 0 {
		return // T9 gates entirely on interdc_dns_resolvers | length > 0
	}
	if !cfgOK {
		logger().Warn("coredns: render skipped — unsafe value refused, keeping previous config")
		return
	}

	binChanged := c.corednsInstallBinary()
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
		if !c.cfgScalar("coredns: interdc_dns_resolvers", resolvers) {
			logger().Warn("coredns: render skipped — unsafe value refused, keeping previous config")
			return
		}
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
	uch, _ := r.writeManaged("/etc/systemd/system/coredns.service", []byte(fmt.Sprintf(`# Managed by %s
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
	// daemon-reload only pays its nsenter+D-Bus fork when the unit
	// content actually changed — an unchanged unit needs no reload.
	if uch {
		r.daemonReload(ctx)
	}
	r.ensureService(ctx, "coredns.service", true, true)
	// binStale: same skew probe as nebula — a binary newer than the
	// running daemon must restart even with an unchanged Corefile
	// (monoUS=0 on an inactive unit answers false; ensureService
	// already started it on the on-disk binary).
	binStale := c.binaryNewerThanService("/usr/local/bin/coredns", "coredns.service")
	if cfgChanged || binChanged || binStale {
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
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for i := 0; i < 15; i++ {
			out, err := r.run(ctx, "dig", "@127.0.0.1", "ns1."+zone, "+short", "+time=3", "+tries=1")
			lastErr = err
			if err == nil && strings.TrimSpace(out) != "" {
				ok = true
				break
			}
			timer.Reset(2 * time.Second)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
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
	// The resolved-managed symlink needs no pre-remove: writeManaged's
	// tmp+os.Rename replaces the LINK itself atomically (rename(2)
	// never follows the final component), while a remove-then-write
	// left /etc/resolv.conf absent — a DNS outage window every cycle.
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
			om, _ := nv.(*jinja.OMap)
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
	rom, _ := recs.(*jinja.OMap)
	if rom == nil {
		return
	}
	for _, rn := range rom.Keys() {
		rv, _ := rom.Get(rn)
		rm, _ := rv.(*jinja.OMap)
		if rm == nil {
			continue
		}
		if nv, ok := rm.Get("node"); ok {
			// node: <registry key> -> marker of that node's name
			if nvv, ok2 := c.t.Nodes.Get(fmt.Sprint(nv)); ok2 {
				if om, ok3 := nvv.(*jinja.OMap); ok3 {
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

// corednsInstallBinary mirrors nebulaInstallBinary: returns true when
// the coredns binary file was actually replaced this cycle so the
// caller can restart the service — a version-pin bump with an
// unchanged Corefile must still bounce the daemon onto the new image.
func (c *cyc) corednsInstallBinary() bool {
	ver := c.t.Vars.StrDef("interdc_coredns_version", "")
	if ver == "" {
		// Same empty-pin rule as nebula: "CoreDNS-"+"" matches every
		// -version output (never upgrades) and download("") is a
		// counted bogus fetch. Not pinned = not installed.
		c.err("T9: interdc_coredns_version not pinned — coredns not installed")
		return false
	}
	tgz := c.v("interdc_coredns_tgz")
	sum := c.v("interdc_coredns_sha256")
	url := c.v("interdc_coredns_url")
	installed := false
	c.installManagedBinary(managedBinarySpec{
		name:     "T9",
		artifact: "coredns tgz",
		probe: func(c *cyc) bool {
			out, err := c.r.run(c.ctx, "/usr/local/bin/coredns", "-version")
			return err == nil && strings.Contains(out, "CoreDNS-"+ver)
		},
		url:    url,
		sum:    sum,
		staged: filepath.Join(c.r.cfg.DownloadDir, tgz),
		// ansible: sha256sum -c every run when outdated.
		refuseBadStaged: true,
		downloadLine:    "T9: coredns download",
		member:          "coredns",
		dest:            "/usr/local/bin/coredns",
		mode:            0o755,
		installErr: func(c *cyc, local string, err error) {
			c.err("T9: coredns install failed — stub will not run",
				"file", local, "error", err)
		},
		onInstalled: func(c *cyc, _ string) {
			installed = true
		},
	})
	return installed
}
