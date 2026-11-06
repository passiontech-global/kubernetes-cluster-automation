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

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Config carries paths + node identity.
type Config struct {
	VarsDir  string // dir containing the four vars files (+ nebula certs)
	NodeName string // registry key = OS hostname = k8s node name
	NowFn    timex.Clock
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
