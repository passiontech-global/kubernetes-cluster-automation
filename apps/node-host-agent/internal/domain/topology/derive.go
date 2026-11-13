// derive.go — the derived-topology pass over the resolved vars +
// node registry: the derive() entry point, the deriveCtx pass
// inputs and the deriveStages table whose order IS the dependency
// order of the original derive() loops (later stages consume
// t.Markers / t.RelayMap / c.selfwin / t.SitePeers built by earlier
// ones). The twelve stage implementations live in derive_stages.go.
package topology

import (
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
	{"nebula relays", stageNebulaRelays},
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
