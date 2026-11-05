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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/jinja"
)

// ---- re-exported jinja engine surface ----
//
// The mini-Jinja2 evaluator + its ordered-map/YAML values live in
// internal/platform/jinja. These aliases and thin forwarders keep
// the historical topology.X API so consumers (hostconfig, hubsync,
// ops/nebulasign, workerhygiene) compile unchanged.
type (
	// OMap is an insertion-ordered string-keyed map (see jinja.OMap).
	OMap = jinja.OMap
	// List wraps a slice so in-place mutation behaves like python
	// lists across scope bindings (see jinja.List).
	List = jinja.List
	// Undefined is the jinja `undefined` — falsy, default()-able
	// (see jinja.Undefined).
	Undefined = jinja.Undefined
	// Env carries render-time hooks (see jinja.Env).
	Env = jinja.Env
)

// NewOMap returns an empty insertion-ordered map (see jinja.NewOMap).
func NewOMap() *OMap { return jinja.NewOMap() }

// DecodeYAML parses a YAML document into jinja values (see
// jinja.DecodeYAML).
func DecodeYAML(data []byte) (any, error) { return jinja.DecodeYAML(data) }

// Render evaluates template text against ctx (see jinja.Render).
func Render(text string, ctx map[string]any, env *Env) (string, error) {
	return jinja.Render(text, ctx, env)
}

// Config carries paths + node identity.
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
	if v.resolving[name] {
		v.errs = append(v.errs, "var "+name+": reference cycle")
		return jinja.NewUndefined(name + "(cycle)")
	}
	if x, ok := v.extra[name]; ok {
		// Preloaded files (interdc_nodes/interdc_dns_zone) go
		// through the same jinja resolution as defaults/cluster
		// values — they used to bypass it, so embedded {{ }}
		// never rendered. Cached under resolved like a raw var,
		// with the same cycle protection.
		v.resolving[name] = true
		prev := v.cur
		v.cur = name
		v.resolved[name] = v.resolve(x)
		v.cur = prev
		delete(v.resolving, name)
		return v.resolved[name]
	}
	rv, ok := v.raw.Get(name)
	if !ok {
		return jinja.NewUndefined(name)
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
			out, err := jinja.RenderScoped(t, v.env, v.get)
			if err != nil {
				// Fail-closed: raw {{...}} text written into rendered
				// config files is worse than undefined — record and
				// return Undefined (falsy, default()-able).
				v.errs = append(v.errs,
					"var "+v.cur+": eval failed: "+err.Error())
				return jinja.NewUndefined(v.cur)
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
		out := &List{V: make([]any, len(t.V))}
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

// Accessors.
func (v *Vars) Get(name string) any { return v.get(name) }

func (v *Vars) Str(name string) string { return jinja.Stringify(v.get(name)) }

func (v *Vars) Bool(name string) bool { return jinja.Truthy(v.get(name)) }

func (v *Vars) Int(name string) int64 {
	i, _ := jinja.ToInt(v.get(name))
	return i
}

func (v *Vars) List(name string) []any { return jinja.ToIter(v.get(name)) }

func (v *Vars) StrList(name string) []string {
	var out []string
	for _, it := range v.List(name) {
		out = append(out, jinja.Stringify(it))
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
		return nil, errors.New("interdc_nodes.yaml: not a mapping")
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
	// Pull the preloaded registries through the resolution path —
	// get() resolves+caches extras so embedded {{ }} renders (they
	// used to reach jinja lookups raw), and derive() works on the
	// same resolved copies.
	if rn, ok := t.Vars.get("interdc_nodes").(*OMap); ok && rn != nil {
		t.Nodes = rn
	}
	if zr, ok := t.Vars.get("interdc_dns_zone").(*OMap); ok && zr != nil {
		t.Zone = zr
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
	return jinja.NewUndefined(key)
}

func mapStr(m any, key string) string { return jinja.Stringify(mapGet(m, key)) }

func mapBool(m any, key string) bool { return jinja.Truthy(mapGet(m, key)) }

func mapInt(m any, key string) int64 {
	i, _ := jinja.ToInt(mapGet(m, key))
	return i
}

func mapList(m any, key string) []any { return jinja.ToIter(mapGet(m, key)) }

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
