// Package topology ports the inter-DC derivation logic of
// playbooks/defaults.yaml + tasks/interdc_derive.yaml +
// tasks/interdc_nebula_derive.yaml to deterministic pure functions.
//
// Inputs are the four vars files mounted from ConfigMap
// node-config-vars at /config/vars:
//
//	defaults.yaml, cluster.yaml, interdc_nodes.yaml, interdc_dns_zone.yaml
//
// Var values may embed Jinja2 expressions (evaluated lazily with cycle
// detection, same net effect as ansible's late binding) — including
// `lookup('file', ...)` resolved against the vars dir.
package topology

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config: paths + node identity.
type Config struct {
	VarsDir  string // dir containing the four vars files (+ nebula certs)
	NodeName string // registry key = OS hostname = k8s node name
	NowFn    func() time.Time
}

// Vars is a lazily-resolved view over the merged vars maps.
type Vars struct {
	raw       *OMap
	extra     map[string]any // interdc_nodes / interdc_dns_zone preloaded
	resolved  map[string]any
	resolving map[string]bool
	cur       string // var being resolved (for error attribution)
	errs      []string
	env       *Env
}

// Errors returns the accumulated resolution failures (eval errors,
// reference cycles). Consumers should surface these — ansible failed
// the converge on the same inputs.
func (v *Vars) Errors() []string { return v.errs }

func (v *Vars) get(name string) any {
	if x, ok := v.resolved[name]; ok {
		return x
	}
	if x, ok := v.extra[name]; ok {
		return x
	}
	if v.resolving[name] {
		v.errs = append(v.errs, "var "+name+": reference cycle")
		return Undefined{name + "(cycle)"}
	}
	rv, ok := v.raw.Get(name)
	if !ok {
		return Undefined{name}
	}
	v.resolving[name] = true
	prev := v.cur
	v.cur = name
	v.resolved[name] = v.resolve(rv)
	v.cur = prev
	delete(v.resolving, name)
	return v.resolved[name]
}

func (v *Vars) resolve(x any) any {
	switch t := x.(type) {
	case string:
		if strings.Contains(t, "{{") || strings.Contains(t, "{%") || strings.Contains(t, "{#") {
			s := &scope{vars: map[string]any{}, env: v.env, lookup: v.get}
			out, err := renderParsed(t, s)
			if err != nil {
				// Fail-closed: raw {{...}} text written into rendered
				// config files is worse than undefined — record and
				// return Undefined (falsy, default()-able).
				v.errs = append(v.errs,
					"var "+v.cur+": eval failed: "+err.Error())
				return Undefined{v.cur}
			}
			return out
		}
		return t
	case *OMap:
		m := NewOMap()
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m.Set(k, v.resolve(vv))
		}
		return m
	case *List:
		out := &List{make([]any, len(t.V))}
		for i, x := range t.V {
			out.V[i] = v.resolve(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = v.resolve(x)
		}
		return out
	}
	return x
}

// renderParsed renders a template string in a pre-built scope.
func renderParsed(text string, s *scope) (string, error) {
	nodes, err := parseTemplate(text)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := renderNodes(nodes, s, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Accessors.
func (v *Vars) Get(name string) any { return v.get(name) }

func (v *Vars) Str(name string) string { return stringify(v.get(name)) }

func (v *Vars) Bool(name string) bool { return truthy(v.get(name)) }

func (v *Vars) Int(name string) int64 {
	i, _ := toInt(v.get(name))
	return i
}

func (v *Vars) List(name string) []any { return toIter(v.get(name)) }

func (v *Vars) StrList(name string) []string {
	var out []string
	for _, it := range v.List(name) {
		out = append(out, stringify(it))
	}
	return out
}

// ---- derived topology ----

type RelayEntry struct {
	IP     string
	Sites  []string // nil = all sites
	Mode   string   // always|fallback
	Weight int64    // 0 = unset (tinc default 10 semantics handled by caller)
	Probe  string   // "" = none
}

type Lighthouse struct {
	Name   string
	Marker string
	IP     string
}

type UnsafeRoute struct {
	Route  string
	Via    string
	Metric int64
}

type AuditTarget struct {
	Label string
	Addr  string
}

// Topology is the fully derived per-node view.
type Topology struct {
	Vars     *Vars
	Nodes    *OMap  // raw registry (ordered)
	Node     *OMap  // this node's registry entry (empty when absent)
	Found    bool   // node present in registry
	Overlay  string // 'nebula'|'tinc'
	Zone     *OMap  // interdc_dns_zone
	NodeKey  string // registry key (hostname)
	MeshName string // node.name (nebula cert name)

	Markers        map[string]string
	MarkersLegacy  map[string]string
	RelayMap       map[string][]RelayEntry
	SelfRelayIPs   []string
	SelfWinRelays  []string
	SitePeers      []string
	Targets        []string // always-routed via table 100
	EgressRelays   []string // mode=fallback
	EgressProbes   []string // "ip:port"
	ProbeTargets   []string
	ProbeMarkers   []string
	SlowpathMkrs   []string
	SiteMarkers    []string
	DNSFallbackMap string
	DNSResolvers   []string

	Lighthouses    []Lighthouse // ordered by node name
	AmLighthouse   bool
	UnsafeRoutes   []UnsafeRoute
	CertSubnets    []string
	BwAuditTargets []AuditTarget

	Errors []string // non-fatal derivations notes (e.g. marker dup)
}

// NewEnv builds the render-time lookup hooks rooted at varsDir:
// lookup('file', p) reads filepath.Base(p) inside varsDir (the
// ansible convention of resolving file lookups against the vars dir)
// and lookup('pipe', 'date +%s') returns the unix epoch (nowFn
// injectable for tests; nil → time.Now). No other pipe command is
// honoured.
func NewEnv(varsDir string, nowFn func() time.Time) *Env {
	return &Env{
		FileLookup: func(p string) (string, error) {
			b, err := os.ReadFile(filepath.Join(varsDir, filepath.Base(p)))
			return string(b), err
		},
		PipeLookup: func(cmd string) (string, error) {
			if strings.TrimSpace(cmd) == "date +%s" {
				now := time.Now()
				if nowFn != nil {
					now = nowFn()
				}
				return strconv.FormatInt(now.Unix(), 10), nil
			}
			return "", fmt.Errorf("unsupported pipe lookup %q", cmd)
		},
	}
}

// Load reads the vars dir and derives topology for cfg.NodeName.
// A node absent from the registry still gets the shared defaults
// (interdc_node == {} → most mesh groups self-gate off, mirroring
// the ansible `interdc_node | length > 0` guards).
func Load(cfg Config) (*Topology, error) {
	t := &Topology{NodeKey: cfg.NodeName}
	rd := func(name string) (any, error) {
		b, err := os.ReadFile(filepath.Join(cfg.VarsDir, name))
		if err != nil {
			return nil, err
		}
		return DecodeYAML(b)
	}

	nodesV, err := rd("interdc_nodes.yaml")
	if err != nil {
		return nil, fmt.Errorf("interdc_nodes.yaml: %w", err)
	}
	nodes, ok := nodesV.(*OMap)
	if !ok || nodes == nil {
		return nil, fmt.Errorf("interdc_nodes.yaml: not a mapping")
	}
	t.Nodes = nodes

	var zone *OMap
	if zv, zerr := rd("interdc_dns_zone.yaml"); zerr == nil {
		zone, _ = zv.(*OMap)
		if zv != nil && zone == nil {
			t.Errors = append(t.Errors,
				"interdc_dns_zone.yaml: top level is not a mapping — treating as empty zone")
		}
	} else if !os.IsNotExist(zerr) {
		// A file that exists but cannot be decoded/read is silently
		// swapped for an empty zone — surface it (missing file may be
		// a deliberate "no zone" deployment).
		t.Errors = append(t.Errors,
			fmt.Sprintf("interdc_dns_zone.yaml: %v — treating as empty zone", zerr))
	}
	if zone == nil {
		zone = NewOMap()
	}
	t.Zone = zone

	env := NewEnv(cfg.VarsDir, cfg.NowFn)

	raw := NewOMap()
	for _, f := range []string{"defaults.yaml", "cluster.yaml"} {
		if dv, err := rd(f); err == nil {
			if m, ok := dv.(*OMap); ok {
				for _, k := range m.Keys() {
					vv, _ := m.Get(k)
					raw.Set(k, vv)
				}
			}
		} else if f == "cluster.yaml" {
			return nil, fmt.Errorf("cluster.yaml: %w", err)
		} else {
			// defaults.yaml unreadable: every default var resolves to
			// Undefined and most groups silently self-gate off —
			// the agent would converge nothing without a trace.
			t.Errors = append(t.Errors,
				fmt.Sprintf("%s: %v — vars defaults unavailable", f, err))
		}
	}
	t.Vars = &Vars{
		raw:       raw,
		extra:     map[string]any{"interdc_nodes": nodes, "interdc_dns_zone": zone},
		resolved:  map[string]any{},
		resolving: map[string]bool{},
		env:       env,
	}
	t.derive()
	t.Errors = append(t.Errors, t.Vars.Errors()...)
	return t, nil
}

// --- helpers over jinja values ---

func mapGet(m any, key string) any {
	if om, ok := m.(*OMap); ok {
		if v, ok := om.Get(key); ok {
			return v
		}
	}
	return Undefined{key}
}

func mapStr(m any, key string) string { return stringify(mapGet(m, key)) }

func mapBool(m any, key string) bool { return truthy(mapGet(m, key)) }

func mapInt(m any, key string) int64 {
	i, _ := toInt(mapGet(m, key))
	return i
}

func mapList(m any, key string) []any { return toIter(mapGet(m, key)) }

func nodeNameOf(v any) string { return mapStr(v, "name") }

func lastOctet(ip string) string {
	if i := strings.LastIndex(ip, "."); i >= 0 {
		return ip[i+1:]
	}
	return ip
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func difference(in, excl []string) []string {
	set := map[string]bool{}
	for _, e := range excl {
		set[e] = true
	}
	var out []string
	for _, x := range in {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

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
	if od := v.get("interdc_overlay_default"); !isNilOrUndef(od) {
		overlay = stringify(od)
	}
	if ov := mapGet(node, "overlay"); !isNilOrUndef(ov) {
		overlay = stringify(ov)
	}
	t.Overlay = overlay

	if !enabled || !t.Found {
		return
	}

	base := stringify(v.get("interdc_marker_base"))
	if base == "" || base == "None" {
		base = "172.29.0"
	}
	markerOf := func(nv *OMap) string {
		if mo := mapGet(nv, "marker_octet"); !isNilOrUndef(mo) {
			return base + "." + stringify(mo)
		}
		return base + "." + lastOctet(mapStr(nv, "ip"))
	}

	// --- markers + relay map ---
	t.Markers = map[string]string{}
	t.MarkersLegacy = map[string]string{}
	t.RelayMap = map[string][]RelayEntry{}
	legacyBase := stringify(v.get("interdc_marker_base_legacy"))
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
				if m := mapGet(om, "marker_octet"); !isNilOrUndef(m) {
					mo = stringify(m)
				}
				t.MarkersLegacy[name] = legacyBase + "." + mo
			}
		}
		var relays []RelayEntry
		defSites := mapGet(om, "relay_sites")
		defMode := "always"
		if dm := mapGet(om, "relay_mode"); !isNilOrUndef(dm) {
			defMode = stringify(dm)
		}
		for _, r := range mapList(om, "relay") {
			e := RelayEntry{Mode: defMode}
			if rm, ok := r.(*OMap); ok {
				e.IP = mapStr(rm, "ip")
				if s := mapGet(rm, "sites"); !isNilOrUndef(s) {
					for _, x := range toIter(s) {
						e.Sites = append(e.Sites, stringify(x))
					}
				} else if !isNilOrUndef(defSites) {
					for _, x := range toIter(defSites) {
						e.Sites = append(e.Sites, stringify(x))
					}
				}
				if m := mapGet(rm, "mode"); !isNilOrUndef(m) {
					e.Mode = stringify(m)
				}
				if w := mapGet(rm, "weight"); !isNilOrUndef(w) {
					e.Weight, _ = toInt(w)
				}
				if p := mapGet(rm, "probe"); !isNilOrUndef(p) {
					e.Probe = stringify(p)
				}
			} else {
				e.IP = stringify(r)
				if !isNilOrUndef(defSites) {
					for _, x := range toIter(defSites) {
						e.Sites = append(e.Sites, stringify(x))
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
				metric := r.Weight
				if metric == 0 {
					metric = 10
				}
				t.UnsafeRoutes = append(t.UnsafeRoutes, UnsafeRoute{r.IP + "/32", mk, metric})
			}
		}
	}

	subnets := []string{mapStr(node, "ip") + "/32"}
	for _, r := range t.RelayMap[self] {
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
				rip = stringify(r)
			}
			if !seenAddr[rip] {
				seenAddr[rip] = true
				t.BwAuditTargets = append(t.BwAuditTargets, AuditTarget{"relay-" + rip, rip})
			}
		}
	}
}
