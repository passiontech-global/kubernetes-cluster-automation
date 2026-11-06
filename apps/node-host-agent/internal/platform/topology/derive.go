// derive.go — the derived-topology pass over the resolved vars +
// node registry: markers, relay map, site peers, targets/egress/
// probes, DNS fallback + resolvers, lighthouses, unsafe routes,
// cert SAN subnets and the bw-audit target list.
package topology

import (
	"fmt"
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/jinja"
)

// derive ports interdc_derive.yaml + interdc_nebula_derive.yaml.
func (t *Topology) derive() {
	v := t.Vars
	enabled := v.Bool("interdc_nebula_enabled")

	// interdc_node = registry[hostname] | default({})
	node := NewOMap()
	if nv, ok := t.Nodes.Get(t.NodeKey); ok {
		if om, ok := nv.(*OMap); ok {
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
	if ov := mapGet(node, "overlay"); !jinja.IsNilOrUndef(ov) {
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
	markerOf := func(nv *OMap) string {
		if mo := mapGet(nv, "marker_octet"); !jinja.IsNilOrUndef(mo) {
			return base + "." + jinja.Stringify(mo)
		}
		return base + "." + lastOctet(mapStr(nv, "ip"))
	}

	// --- markers + relay map ---
	t.Markers = map[string]string{}
	t.MarkersLegacy = map[string]string{}
	t.RelayMap = map[string][]RelayEntry{}
	legacyBase := jinja.Stringify(v.get("interdc_marker_base_legacy"))
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		name, ip := nodeNameOf(om), mapStr(om, "ip")
		if name != "" && ip != "" {
			t.Markers[name] = markerOf(om)
			if legacyBase != "" {
				mo := lastOctet(ip)
				if m := mapGet(om, "marker_octet"); !jinja.IsNilOrUndef(m) {
					mo = jinja.Stringify(m)
				}
				t.MarkersLegacy[name] = legacyBase + "." + mo
			}
		}
		var relays []RelayEntry
		defSites := mapGet(om, "relay_sites")
		defMode := "always"
		if dm := mapGet(om, "relay_mode"); !jinja.IsNilOrUndef(dm) {
			defMode = jinja.Stringify(dm)
		}
		for _, r := range mapList(om, "relay") {
			e := RelayEntry{Mode: defMode}
			if rm, ok := r.(*OMap); ok {
				e.IP = mapStr(rm, "ip")
				if s := mapGet(rm, "sites"); !jinja.IsNilOrUndef(s) {
					for _, x := range jinja.ToIter(s) {
						e.Sites = append(e.Sites, jinja.Stringify(x))
					}
				} else if !jinja.IsNilOrUndef(defSites) {
					for _, x := range jinja.ToIter(defSites) {
						e.Sites = append(e.Sites, jinja.Stringify(x))
					}
				}
				if m := mapGet(rm, "mode"); !jinja.IsNilOrUndef(m) {
					e.Mode = jinja.Stringify(m)
				}
				if w := mapGet(rm, "weight"); !jinja.IsNilOrUndef(w) {
					e.Weight, _ = jinja.ToInt(w)
				}
				if p := mapGet(rm, "probe"); !jinja.IsNilOrUndef(p) {
					e.Probe = jinja.Stringify(p)
				}
			} else {
				e.IP = jinja.Stringify(r)
				if !jinja.IsNilOrUndef(defSites) {
					for _, x := range jinja.ToIter(defSites) {
						e.Sites = append(e.Sites, jinja.Stringify(x))
					}
				}
			}
			relays = append(relays, e)
		}
		if name != "" {
			t.RelayMap[name] = relays
		}
	}

	// marker uniqueness assert
	seen := map[string]string{}
	for n, m := range t.Markers {
		if other, dup := seen[m]; dup {
			t.Errors = append(t.Errors, fmt.Sprintf(
				"marker IP %s duplicated between %s and %s — set marker_octet", m, other, n))
		}
		seen[m] = n
	}

	site := mapStr(node, "site")
	self := t.MeshName

	// same-site peers
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nm := nodeNameOf(om)
		if site != "" && mapStr(om, "site") == site && nm != "" && nm != self {
			t.SitePeers = append(t.SitePeers, nm)
		}
	}

	// self relay ips + selfwin
	for _, r := range t.RelayMap[self] {
		t.SelfRelayIPs = append(t.SelfRelayIPs, r.IP)
	}
	selfwin := map[string]bool{}
	for _, r := range t.RelayMap[self] {
		w := r.Weight
		if w == 0 {
			w = 10
		}
		min := w
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*OMap)
			if om == nil {
				continue
			}
			for _, r2 := range t.RelayMap[nodeNameOf(om)] {
				if r2.IP == r.IP {
					w2 := r2.Weight
					if w2 == 0 {
						w2 = 10
					}
					if w2 < min {
						min = w2
					}
				}
			}
		}
		if w <= min {
			selfwin[r.IP] = true
			t.SelfWinRelays = append(t.SelfWinRelays, r.IP)
		}
	}
	sort.Strings(t.SelfWinRelays)

	// targets / egress / probes
	var targets, egress, egressProbes, probeT, probeM, slowM, siteM []string
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nsite, nm := mapStr(om, "site"), nodeNameOf(om)
		if nsite != site {
			if ip := mapStr(om, "ip"); ip != "" {
				targets = append(targets, ip)
				probeT = append(probeT, ip)
			}
		}
		for _, r := range t.RelayMap[nm] {
			siteOK := r.Sites == nil || contains(r.Sites, site)
			if nsite != site && siteOK && r.Mode != "fallback" {
				targets = append(targets, r.IP)
			}
			if nsite != site && siteOK && r.Mode == "fallback" {
				egress = append(egress, r.IP)
				if r.Probe != "" && !selfwin[r.IP] {
					egressProbes = append(egressProbes, r.IP+":"+r.Probe)
				}
			}
		}
	}
	targets = uniqSorted(targets)
	targets = difference(targets, t.SelfWinRelays)
	egress = uniqSorted(egress)
	egress = difference(egress, t.SelfWinRelays)
	egressProbes = uniqSorted(egressProbes)
	t.Targets, t.EgressRelays, t.EgressProbes = targets, egress, egressProbes
	t.ProbeTargets = probeT

	farSites := v.StrList("interdc_far_sites")
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nsite, nm := mapStr(om, "site"), nodeNameOf(om)
		mk, hasMk := t.Markers[nm]
		if !hasMk {
			continue
		}
		if nsite != site {
			probeM = append(probeM, mk)
			if !contains(farSites, site) && !contains(farSites, nsite) {
				slowM = append(slowM, mk)
			}
		}
		if contains(t.SitePeers, nm) {
			siteM = append(siteM, mk)
		}
	}
	t.ProbeMarkers, t.SlowpathMkrs, t.SiteMarkers = probeM, slowM, siteM

	// dns fallback map + resolvers
	var ips []string
	for _, own := range []bool{true, false} {
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*OMap)
			if om == nil {
				continue
			}
			isOwn := mapStr(om, "site") == site
			if mapBool(om, "hub") && isOwn == own {
				if ip := mapStr(om, "ip"); ip != "" {
					ips = append(ips, ip, t.Markers[nodeNameOf(om)])
				}
			}
		}
	}
	var fbEntries []string
	names := append([]string{v.Str("cp_endpoint")}, v.StrList("cp_endpoint_fallback_names")...)
	for _, n := range names {
		if n != "" && n != "None" && len(ips) > 0 {
			fbEntries = append(fbEntries, n+":6443="+strings.Join(uniqSorted(ips), ","))
		}
	}
	fbEntries = append(fbEntries, v.StrList("interdc_dns_fallback_extra")...)
	t.DNSFallbackMap = strings.Join(fbEntries, " ")

	var resolvers []string
	for _, own := range []bool{true, false} {
		for _, k := range t.Nodes.Keys() {
			nv, _ := t.Nodes.Get(k)
			om, _ := nv.(*OMap)
			if om == nil {
				continue
			}
			isOwn := mapStr(om, "site") == site
			if mapBool(om, "hub") && isOwn == own {
				if mk, ok := t.Markers[nodeNameOf(om)]; ok {
					resolvers = append(resolvers, mk)
				}
			}
		}
	}
	t.DNSResolvers = uniqSorted(resolvers)

	// --- nebula derive ---
	t.AmLighthouse = mapBool(node, "hub")
	lhNames := []string{}
	lhMap := map[string]Lighthouse{}
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nm := nodeNameOf(om)
		if mapBool(om, "hub") && nm != "" {
			if mk, ok := t.Markers[nm]; ok {
				lhMap[nm] = Lighthouse{Name: nm, Marker: mk, IP: mapStr(om, "ip")}
				lhNames = append(lhNames, nm)
			}
		}
	}
	sort.Strings(lhNames)
	for _, n := range lhNames {
		t.Lighthouses = append(t.Lighthouses, lhMap[n])
	}

	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nsite, nm := mapStr(om, "site"), nodeNameOf(om)
		mk, hasMk := t.Markers[nm]
		if nsite == site || nm == "" || nm == self || !hasMk {
			continue
		}
		if ip := mapStr(om, "ip"); ip != "" {
			t.UnsafeRoutes = append(t.UnsafeRoutes, UnsafeRoute{ip + "/32", mk, 100})
		}
		for _, r := range t.RelayMap[nm] {
			siteOK := r.Sites == nil || contains(r.Sites, site)
			if siteOK && !selfwin[r.IP] {
				if r.IP == "" {
					// Same guard as the registry ip above — an
					// empty relay ip must not mint a "/32" route.
					t.Errors = append(t.Errors, fmt.Sprintf(
						"node %q (mesh %q): relay entry has no ip — unsafe route skipped",
						k, nm))
					continue
				}
				metric := r.Weight
				if metric == 0 {
					metric = 10
				}
				t.UnsafeRoutes = append(t.UnsafeRoutes, UnsafeRoute{r.IP + "/32", mk, metric})
			}
		}
	}

	// cert SAN subnets — an empty registry ip must NOT produce a
	// literal "/32" (unparseable subnet silently baked into a cert).
	var subnets []string
	if selfIP := mapStr(node, "ip"); selfIP != "" {
		subnets = append(subnets, selfIP+"/32")
	} else {
		t.Errors = append(t.Errors, fmt.Sprintf(
			"node %q (mesh %q): registry entry has no ip — cert SAN subnets incomplete",
			t.NodeKey, self))
	}
	for _, r := range t.RelayMap[self] {
		if r.IP == "" {
			t.Errors = append(t.Errors, fmt.Sprintf(
				"node %q (mesh %q): relay entry has no ip — cert SAN subnets incomplete",
				t.NodeKey, self))
			continue
		}
		subnets = append(subnets, r.IP+"/32")
	}
	t.CertSubnets = uniqSorted(subnets)

	// T11 bw audit targets (registry order, relay addrs deduped)
	seenAddr := map[string]bool{}
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*OMap)
		if om == nil {
			continue
		}
		nm := nodeNameOf(om)
		if nm == "" || nm == self || mapStr(om, "ip") == "" {
			continue
		}
		t.BwAuditTargets = append(t.BwAuditTargets,
			AuditTarget{nm, mapStr(om, "ip")})
		mk := t.Markers[nm]
		if mk == "" {
			mk = markerOf(om)
		}
		t.BwAuditTargets = append(t.BwAuditTargets, AuditTarget{nm + "-marker", mk})
		for _, r := range mapList(om, "relay") {
			var rip string
			if rm, ok := r.(*OMap); ok {
				rip = mapStr(rm, "ip")
			} else {
				rip = jinja.Stringify(r)
			}
			if !seenAddr[rip] {
				seenAddr[rip] = true
				t.BwAuditTargets = append(t.BwAuditTargets, AuditTarget{"relay-" + rip, rip})
			}
		}
	}
}
