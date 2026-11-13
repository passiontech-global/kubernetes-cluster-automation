// derive_stages.go — the twelve deriveStages implementations: one
// pass per row of the table in derive.go (markers/relays, marker
// dup assert, site peers, selfwin, targets/egress/probes, probe
// markers, DNS, lighthouses, nebula relays, unsafe routes, cert SAN
// subnets, bw-audit targets). Split out of derive.go so the
// pipeline file stays under the ~500-LOC bar; stage order lives in
// the table and is load-bearing.
package topology

import (
	"fmt"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// stageMarkersRelays — markers + legacy markers + relay map for
// every named node with an ip.
func stageMarkersRelays(t *Topology, c *deriveCtx) {
	t.Markers = map[string]string{}
	t.MarkersLegacy = map[string]string{}
	t.RelayMap = map[string][]RelayEntry{}
	t.walkNodes(func(_ string, om *jinja.OMap) {
		name, ip := nodeNameOf(om), om.Str("ip")
		if name != "" && ip != "" {
			t.Markers[name] = c.markerOf(om)
			if c.legacyBase != "" {
				mo := LastOctet(ip)
				if m, _ := om.Get("marker_octet"); !jinja.IsNilOrUndef(m) {
					mo = jinja.Stringify(m)
				}
				t.MarkersLegacy[name] = c.legacyBase + "." + mo
			}
		}
		if name != "" {
			t.RelayMap[name] = parseRelays(om)
		}
	})
}

// parseRelays — a node's relay table: per-entry fields override the
// node-level relay_sites/relay_mode defaults.
func parseRelays(om *jinja.OMap) []RelayEntry {
	var relays []RelayEntry
	defSites, _ := om.Get("relay_sites")
	defMode := "always"
	if dm, _ := om.Get("relay_mode"); !jinja.IsNilOrUndef(dm) {
		defMode = jinja.Stringify(dm)
	}
	addSites := func(e *RelayEntry, s any) {
		for _, x := range jinja.ToIter(s) {
			e.Sites = append(e.Sites, jinja.Stringify(x))
		}
	}
	for _, r := range om.Slice("relay") {
		e := RelayEntry{Mode: defMode}
		if rm, ok := r.(*jinja.OMap); ok {
			e.IP = rm.Str("ip")
			if s, _ := rm.Get("sites"); !jinja.IsNilOrUndef(s) {
				addSites(&e, s)
			} else if !jinja.IsNilOrUndef(defSites) {
				addSites(&e, defSites)
			}
			if m, _ := rm.Get("mode"); !jinja.IsNilOrUndef(m) {
				e.Mode = jinja.Stringify(m)
			}
			if w, _ := rm.Get("weight"); !jinja.IsNilOrUndef(w) {
				e.Weight, _ = jinja.ToInt(w)
			}
			if p, _ := rm.Get("probe"); !jinja.IsNilOrUndef(p) {
				e.Probe = jinja.Stringify(p)
			}
		} else {
			e.IP = jinja.Stringify(r)
			if !jinja.IsNilOrUndef(defSites) {
				addSites(&e, defSites)
			}
		}
		relays = append(relays, e)
	}
	return relays
}

// stageMarkerDup — marker uniqueness assert.
func stageMarkerDup(t *Topology, _ *deriveCtx) {
	seen := map[string]string{}
	for n, m := range t.Markers {
		if other, dup := seen[m]; dup {
			t.Errors = append(t.Errors, fmt.Sprintf(
				"marker IP %s duplicated between %s and %s — set marker_octet", m, other, n))
		}
		seen[m] = n
	}
}

// stageSitePeers — same-site peers of this node.
func stageSitePeers(t *Topology, c *deriveCtx) {
	t.walkNodes(func(_ string, om *jinja.OMap) {
		nm := nodeNameOf(om)
		if c.site != "" && om.Str("site") == c.site && nm != "" && nm != c.self {
			t.SitePeers = append(t.SitePeers, nm)
		}
	})
}

// relayWeight — unset weight carries tinc's default-10 semantics.
func relayWeight(w int64) int64 {
	if w == 0 {
		return 10
	}
	return w
}

// stageRelayWin — self relay ips + selfwin (the relays whose weight
// this node ties-or-beats across the whole registry).
func stageRelayWin(t *Topology, c *deriveCtx) {
	for _, r := range t.RelayMap[c.self] {
		t.SelfRelayIPs = append(t.SelfRelayIPs, r.IP)
	}
	c.selfwin = map[string]bool{}
	for _, r := range t.RelayMap[c.self] {
		w := relayWeight(r.Weight)
		min := w
		t.walkNodes(func(_ string, om *jinja.OMap) {
			for _, r2 := range t.RelayMap[nodeNameOf(om)] {
				if r2.IP == r.IP && relayWeight(r2.Weight) < min {
					min = relayWeight(r2.Weight)
				}
			}
		})
		if w <= min {
			c.selfwin[r.IP] = true
			t.SelfWinRelays = append(t.SelfWinRelays, r.IP)
		}
	}
	slices.Sort(t.SelfWinRelays)
}

// stageTargetsEgress — cross-site targets (registry ips + always
// relays), fallback egress relays + their probes.
func stageTargetsEgress(t *Topology, c *deriveCtx) {
	var targets, egress, egressProbes, probeT []string
	t.walkNodes(func(_ string, om *jinja.OMap) {
		nsite, nm := om.Str("site"), nodeNameOf(om)
		if nsite != c.site {
			if ip := om.Str("ip"); ip != "" {
				targets = append(targets, ip)
				probeT = append(probeT, ip)
			}
		}
		for _, r := range t.RelayMap[nm] {
			siteOK := r.Sites == nil || contains(r.Sites, c.site)
			if nsite != c.site && siteOK && r.Mode != "fallback" {
				targets = append(targets, r.IP)
			}
			if nsite != c.site && siteOK && r.Mode == "fallback" {
				egress = append(egress, r.IP)
				if r.Probe != "" && !c.selfwin[r.IP] {
					egressProbes = append(egressProbes, r.IP+":"+r.Probe)
				}
			}
		}
	})
	targets = difference(UniqSorted(targets), t.SelfWinRelays)
	egress = difference(UniqSorted(egress), t.SelfWinRelays)
	egressProbes = UniqSorted(egressProbes)
	t.Targets, t.EgressRelays, t.EgressProbes = targets, egress, egressProbes
	t.ProbeTargets = probeT
}

// stageProbeMarkers — probe markers for remote sites, slowpath
// markers (neither side a far site) and site-peer markers.
func stageProbeMarkers(t *Topology, c *deriveCtx) {
	var probeM, slowM, siteM []string
	t.walkNodes(func(_ string, om *jinja.OMap) {
		nsite, nm := om.Str("site"), nodeNameOf(om)
		mk, hasMk := t.Markers[nm]
		if !hasMk {
			return
		}
		if nsite != c.site {
			probeM = append(probeM, mk)
			if !contains(c.farSites, c.site) && !contains(c.farSites, nsite) {
				slowM = append(slowM, mk)
			}
		}
		if contains(t.SitePeers, nm) {
			siteM = append(siteM, mk)
		}
	})
	t.ProbeMarkers, t.SlowpathMkrs, t.SiteMarkers = probeM, slowM, siteM
}

// stageDNS — dns fallback map + resolvers from the hub nodes, own
// site first. One walk feeds both outputs (they used to duplicate
// the same hub/is-own filter).
func stageDNS(t *Topology, c *deriveCtx) {
	var ips, resolvers []string
	for _, own := range []bool{true, false} {
		t.walkNodes(func(_ string, om *jinja.OMap) {
			if !om.Bool("hub") || (om.Str("site") == c.site) != own {
				return
			}
			mk, hasMk := t.Markers[nodeNameOf(om)]
			if ip := om.Str("ip"); ip != "" {
				ips = append(ips, ip)
				// The marker is a DNS name sibling of the node IP —
				// an empty marker string would join as a "," gap and
				// parse downstream as a {"": ""} fallback entry.
				if mk != "" {
					ips = append(ips, mk)
				}
			}
			if hasMk && mk != "" {
				resolvers = append(resolvers, mk)
			}
		})
	}
	var fbEntries []string
	names := append([]string{t.Vars.Str("cp_endpoint")},
		t.Vars.StrList("cp_endpoint_fallback_names")...)
	for _, n := range names {
		if n != "" && n != "None" && len(ips) > 0 {
			fbEntries = append(fbEntries, n+":6443="+strings.Join(UniqSorted(ips), ","))
		}
	}
	fbEntries = append(fbEntries, t.Vars.StrList("interdc_dns_fallback_extra")...)
	t.DNSFallbackMap = strings.Join(fbEntries, " ")
	t.DNSResolvers = UniqSorted(resolvers)
}

// stageLighthouses — hub nodes with markers, ordered by mesh name.
// Also drives AmLighthouse: the self node's "hub" flag IS the
// am-lighthouse decision (nebula derive parity), evaluated here —
// the stage the old assignment sat ahead of.
func stageLighthouses(t *Topology, c *deriveCtx) {
	t.AmLighthouse = c.hub
	lhNames := []string{}
	lhMap := map[string]Lighthouse{}
	t.walkNodes(func(_ string, om *jinja.OMap) {
		nm := nodeNameOf(om)
		if om.Bool("hub") && nm != "" {
			if mk, ok := t.Markers[nm]; ok {
				lhMap[nm] = Lighthouse{Name: nm, Marker: mk, IP: om.Str("ip")}
				lhNames = append(lhNames, nm)
			}
		}
	})
	slices.Sort(lhNames)
	for _, n := range lhNames {
		t.Lighthouses = append(t.Lighthouses, lhMap[n])
	}
}

// stageNebulaRelays — Nebula protocol relay (>=1.6): am_relay marks
// this node as a relay; nebula_relays lists mesh names of relay
// nodes, resolved to their VPN marker IPs for the config's
// relay.relays (advertised to the lighthouse). Nebula forbids a
// relay node from using relays itself ("cannot relay to a relay"),
// and a listed node without am_relay would reject relay requests —
// both are registry errors, not silent skips.
func stageNebulaRelays(t *Topology, c *deriveCtx) {
	t.AmRelay = t.Node.Bool("nebula_am_relay")
	byName := map[string]*jinja.OMap{}
	t.walkNodes(func(_ string, om *jinja.OMap) {
		if nm := nodeNameOf(om); nm != "" {
			byName[nm] = om
		}
	})
	var ips []string
	seen := map[string]bool{}
	for _, x := range t.Node.Slice("nebula_relays") {
		name := jinja.Stringify(x)
		if name == "" || name == "None" || seen[name] {
			continue
		}
		seen[name] = true
		bad := func(format string, args ...any) {
			t.Errors = append(t.Errors, fmt.Sprintf(format, args...))
		}
		switch {
		case t.AmRelay:
			bad("node %q (mesh %q): am_relay node must not list nebula_relays — nebula forbids relay-to-relay",
				t.NodeKey, c.self)
		case name == c.self:
			bad("node %q (mesh %q): nebula_relays lists itself",
				t.NodeKey, c.self)
		default:
			target, ok := byName[name]
			switch {
			case !ok:
				bad("node %q (mesh %q): nebula_relays entry %q not in registry",
					t.NodeKey, c.self, name)
			case !target.Bool("nebula_am_relay"):
				bad("node %q (mesh %q): nebula_relays entry %q lacks nebula_am_relay — it would reject relay requests",
					t.NodeKey, c.self, name)
			default:
				if mk, hasMk := t.Markers[name]; hasMk && mk != "" {
					ips = append(ips, mk)
				} else {
					bad("node %q (mesh %q): nebula_relays entry %q has no marker IP",
						t.NodeKey, c.self, name)
				}
			}
		}
	}
	t.NebulaRelayIPs = ips
}

// stageUnsafeRoutes — remote registry ips + relays routed via the
// remote marker.
func stageUnsafeRoutes(t *Topology, c *deriveCtx) {
	t.walkNodes(func(k string, om *jinja.OMap) {
		nsite, nm := om.Str("site"), nodeNameOf(om)
		mk, hasMk := t.Markers[nm]
		if nsite == c.site || nm == "" || nm == c.self || !hasMk {
			return
		}
		if ip := om.Str("ip"); ip != "" {
			t.UnsafeRoutes = append(t.UnsafeRoutes, UnsafeRoute{ip + "/32", mk, 100})
		}
		for _, r := range t.RelayMap[nm] {
			siteOK := r.Sites == nil || contains(r.Sites, c.site)
			if siteOK && !c.selfwin[r.IP] {
				if r.IP == "" {
					// Same guard as the registry ip above — an
					// empty relay ip must not mint a "/32" route.
					t.Errors = append(t.Errors, fmt.Sprintf(
						"node %q (mesh %q): relay entry has no ip — unsafe route skipped",
						k, nm))
					continue
				}
				t.UnsafeRoutes = append(t.UnsafeRoutes,
					UnsafeRoute{r.IP + "/32", mk, relayWeight(r.Weight)})
			}
		}
	})
}

// stageCertSubnets — cert SAN subnets from the SELF node only: an
// empty registry ip must NOT produce a literal "/32" (unparseable
// subnet silently baked into a cert).
func stageCertSubnets(t *Topology, c *deriveCtx) {
	var subnets []string
	if selfIP := t.Node.Str("ip"); selfIP != "" {
		subnets = append(subnets, selfIP+"/32")
	} else {
		t.Errors = append(t.Errors, fmt.Sprintf(
			"node %q (mesh %q): registry entry has no ip — cert SAN subnets incomplete",
			t.NodeKey, c.self))
	}
	for _, r := range t.RelayMap[c.self] {
		if r.IP == "" {
			t.Errors = append(t.Errors, fmt.Sprintf(
				"node %q (mesh %q): relay entry has no ip — cert SAN subnets incomplete",
				t.NodeKey, c.self))
			continue
		}
		subnets = append(subnets, r.IP+"/32")
	}
	t.CertSubnets = UniqSorted(subnets)
}

// stageBwAudit — T11 bw audit targets (registry order, relay addrs
// deduped across the whole registry).
func stageBwAudit(t *Topology, c *deriveCtx) {
	seenAddr := map[string]bool{}
	t.walkNodes(func(k string, om *jinja.OMap) {
		nm := nodeNameOf(om)
		if nm == "" || nm == c.self || om.Str("ip") == "" {
			return
		}
		t.BwAuditTargets = append(t.BwAuditTargets,
			AuditTarget{nm, om.Str("ip")})
		mk := t.Markers[nm]
		if mk == "" {
			mk = c.markerOf(om)
		}
		t.BwAuditTargets = append(t.BwAuditTargets, AuditTarget{nm + "-marker", mk})
		for _, r := range om.Slice("relay") {
			var rip string
			if rm, ok := r.(*jinja.OMap); ok {
				rip = rm.Str("ip")
			} else {
				rip = jinja.Stringify(r)
			}
			if !seenAddr[rip] {
				seenAddr[rip] = true
				t.BwAuditTargets = append(t.BwAuditTargets, AuditTarget{"relay-" + rip, rip})
			}
		}
	})
}
