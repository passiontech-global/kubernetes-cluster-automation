// derive.go — the derived-topology pass over the resolved vars +
// node registry: markers, relay map, site peers, targets/egress/
// probes, DNS fallback + resolvers, lighthouses, unsafe routes,
// cert SAN subnets and the bw-audit target list.
//
// Each pass over the registry is one row of deriveStages below —
// the original derive() had 8 near-identical `t.Nodes.Keys()` loops;
// they now share walkNodes and stage order IS the dependency order
// of the original loops.
package topology

import (
	"fmt"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// deriveCtx carries the per-node pass inputs computed once from the
// self node + vars: self identity/site, marker derivation and the
// selfwin set the later passes consult.
type deriveCtx struct {
	site       string // this node's site ("" = unknown)
	self       string // this node's mesh name
	hub        bool   // this node's "hub" flag — the AmLighthouse decision
	farSites   []string
	markerOf   func(nv *jinja.OMap) string
	legacyBase string
	selfwin    map[string]bool // relay ips this node wins
}

// walkNodes visits every registry entry that decodes to a node
// mapping, in registry key order — the shared shape of every
// derive() pass (non-mapping entries, e.g. bare anchors, are
// skipped exactly as the original loops did).
func (t *Topology) walkNodes(visit func(k string, om *jinja.OMap)) {
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*jinja.OMap)
		if om == nil {
			continue
		}
		visit(k, om)
	}
}

// deriveStage — one pass of the derivation pipeline. Table order IS
// load-bearing: later stages consume t.Markers / t.RelayMap /
// c.selfwin / t.SitePeers built by earlier ones.
type deriveStage struct {
	name string
	run  func(t *Topology, c *deriveCtx)
}

var deriveStages = []deriveStage{
	{"markers+relays", stageMarkersRelays},
	{"marker dup assert", stageMarkerDup},
	{"site peers", stageSitePeers},
	{"self relays + selfwin", stageRelayWin},
	{"targets/egress/probes", stageTargetsEgress},
	{"probe/slowpath/site markers", stageProbeMarkers},
	{"dns fallback + resolvers", stageDNS},
	{"lighthouses", stageLighthouses},
	{"unsafe routes", stageUnsafeRoutes},
	{"cert SAN subnets", stageCertSubnets},
	{"bw audit targets", stageBwAudit},
}

// derive ports interdc_derive.yaml + interdc_nebula_derive.yaml.
func (t *Topology) derive() {
	v := t.Vars
	enabled := v.Bool("interdc_nebula_enabled")

	// interdc_node = registry[hostname] | default({})
	node := jinja.NewOMap()
	if nv, ok := t.Nodes.Get(t.NodeKey); ok {
		if om, ok := nv.(*jinja.OMap); ok {
			node = om
		}
	}
	t.Node = node
	t.Found = node.Len() > 0
	t.MeshName = nodeNameOf(node)

	// overlay selector
	overlay := "nebula"
	if od := v.get("interdc_overlay_default"); !jinja.IsNilOrUndef(od) {
		overlay = jinja.Stringify(od)
	}
	if ov, _ := node.Get("overlay"); !jinja.IsNilOrUndef(ov) {
		overlay = jinja.Stringify(ov)
	}
	t.Overlay = overlay

	if !enabled || !t.Found {
		return
	}

	base := jinja.Stringify(v.get("interdc_marker_base"))
	if base == "" || base == "None" {
		base = "172.29.0"
	}
	c := &deriveCtx{
		site:     node.Str("site"),
		self:     t.MeshName,
		hub:      node.Bool("hub"),
		farSites: v.StrList("interdc_far_sites"),
	}
	c.markerOf = func(nv *jinja.OMap) string {
		if mo, _ := nv.Get("marker_octet"); !jinja.IsNilOrUndef(mo) {
			return base + "." + jinja.Stringify(mo)
		}
		return base + "." + LastOctet(nv.Str("ip"))
	}
	c.legacyBase = jinja.Stringify(v.get("interdc_marker_base_legacy"))

	for _, st := range deriveStages {
		st.run(t, c)
	}
}

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
	sort.Strings(t.SelfWinRelays)
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
	sort.Strings(lhNames)
	for _, n := range lhNames {
		t.Lighthouses = append(t.Lighthouses, lhMap[n])
	}
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
