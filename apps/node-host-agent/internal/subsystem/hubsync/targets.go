package hubsync

import (
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
)

// Target is one SSH-converge destination. Source flags are OR-merged
// when several sources name the same IP (dedup by IP).
type Target struct {
	Name      string // inventory name → --node-name + `target` metric label
	IP        string
	SSHUser   string // resolved user (ssh_user → by-site map → default → root)
	ProxyJump string // `ssh_proxyjump` "user@host" bastion ("" = direct)

	// Source flags — hub_converge group membership, kept for the
	// converge steps that differ per source and surfaced to callers
	// (e.g. controller nodes get nebula certs).
	InterDC bool // interdc_nodes.yaml entry with agent:false (k0s controller / nebula hub)
	Hub     bool // registry `hub: true` (nebula lighthouse)
	KineDB  bool // node_exporter_extra_hosts entry with kine_db:true
	APILB   bool // api_lb_guard_vms entry → push guard token/ca
}

// loadTargets re-parses the vars dir every cycle — ConfigMap updates
// land as file changes and must apply without an agent restart.
// notes carries topology.Load's NON-FATAL resolution notes (marker
// dups, zone decode / jinja eval failures); err is reserved for a
// genuine load/aggregation failure that must abort the cycle.
// dropped lists the inventory names that resolved to an EMPTY ip —
// not targets, but still known hosts the caller must mark down
// rather than silently lose.
func loadTargets(varsDir string) (targets []Target, dropped, notes []string, err error) {
	t, err := topology.Load(topology.Config{VarsDir: varsDir})
	if err != nil {
		return nil, nil, nil, err
	}
	targets, dropped = aggregateTargets(t)
	return targets, dropped, t.Errors, nil
}

// aggregateTargets merges the three hub_converge inventory sources
// into deduped targets:
//
//	a. interdc_nodes registry entries with `agent: false` — k0s
//	   controllers / nebula hubs converged by the removed CronJob.
//	b. node_exporter_extra_hosts (cluster.yaml) — infra VMs; a
//	   `kine_db: true` flag is carried through.
//	c. api_lb_guard_vms (cluster.yaml) — API LB VMs; flagged APILB so
//	   the cycle pushes the guard token/ca.
//
// Dedup is by IP; later sources override scalar fields when non-empty
// and OR the flags (hub_converge add_host last-registration-wins
// parity). t.Errors stays with the caller — those notes are non-fatal
// and must not suppress the targets that did resolve.
// The second return records the NAMES of inventory entries dropped
// for an empty ip: a target that vanishes from the list without a
// trace would get its metric series pruned, hiding the broken
// resolution — the caller marks those names down instead.
func aggregateTargets(t *topology.Topology) (targets []Target, dropped []string) {
	defUser := t.Vars.Str("interdc_ssh_default_user")
	if defUser == "" {
		defUser = "root"
	}
	bySite := strMap(t.Vars.Get("interdc_ssh_user_by_site"))

	// ssh_user resolution, 1:1 with hub_converge's add_host chains:
	//   interdc/api-lb: ssh_user → by_site[site] → default_user
	//   extra_hosts:    ssh_user → default_user   (no site lookup)
	userOf := func(om *topology.OMap, siteMap bool) string {
		if u := omStr(om, "ssh_user"); u != "" {
			return u
		}
		if siteMap {
			if u := bySite[omStr(om, "site")]; u != "" {
				return u
			}
		}
		return defUser
	}

	var order []string
	byIP := map[string]*Target{}
	droppedSet := map[string]bool{}
	add := func(nt Target) {
		if nt.IP == "" {
			// No dialable address — record the name so the cycle
			// can keep its series and mark it down. Deduped: a
			// host in two sources (extra_hosts + api_lb_guard_vms)
			// must not be recorded twice.
			if nt.Name != "" && !droppedSet[nt.Name] {
				droppedSet[nt.Name] = true
				dropped = append(dropped, nt.Name)
			}
			return
		}
		if ex, ok := byIP[nt.IP]; ok {
			ex.InterDC = ex.InterDC || nt.InterDC
			ex.Hub = ex.Hub || nt.Hub
			ex.KineDB = ex.KineDB || nt.KineDB
			ex.APILB = ex.APILB || nt.APILB
			if nt.Name != "" {
				ex.Name = nt.Name
			}
			if nt.SSHUser != "" && nt.SSHUser != defUser {
				ex.SSHUser = nt.SSHUser
			} else if ex.SSHUser == "" {
				ex.SSHUser = nt.SSHUser
			}
			if nt.ProxyJump != "" {
				ex.ProxyJump = nt.ProxyJump
			}
			return
		}
		cp := nt
		byIP[nt.IP] = &cp
		order = append(order, nt.IP)
	}

	// a. interdc registry — `agent | default(true)` gating.
	for _, k := range t.Nodes.Keys() {
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil || omBool(om, "agent", true) {
			continue
		}
		name := k // registry key = OS hostname = --node-name
		add(Target{
			Name:      name,
			IP:        omStr(om, "ip"),
			SSHUser:   userOf(om, true),
			ProxyJump: omStr(om, "ssh_proxyjump"),
			InterDC:   true,
			Hub:       omBool(om, "hub", false),
		})
	}

	// b. infra VMs needing node_exporter (+ kine_db flag).
	for _, e := range t.Vars.List("node_exporter_extra_hosts") {
		om, _ := e.(*topology.OMap)
		if om == nil {
			continue
		}
		add(Target{
			Name:    omStr(om, "name"),
			IP:      omStr(om, "ip"),
			SSHUser: userOf(om, false),
			KineDB:  omBool(om, "kine_db", false),
		})
	}

	// c. API LB VMs — guard credentials + flag.
	for _, e := range t.Vars.List("api_lb_guard_vms") {
		om, _ := e.(*topology.OMap)
		if om == nil {
			continue
		}
		add(Target{
			Name:    omStr(om, "name"),
			IP:      omStr(om, "ip"),
			SSHUser: userOf(om, true),
			APILB:   true,
		})
	}

	out := make([]Target, 0, len(order))
	for _, ip := range order {
		out = append(out, *byIP[ip])
	}
	return out, dropped
}

// --- jinja value helpers (topology keeps its coercions unexported) ---

func omStr(m *topology.OMap, key string) string {
	v, ok := m.Get(key)
	if !ok {
		return ""
	}
	return strOf(v)
}

func omBool(m *topology.OMap, key string, def bool) bool {
	v, ok := m.Get(key)
	if !ok {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		// YAML "True"/"Yes"/"1"-style scalars decode as strings —
		// coerce the ansible truthy/falsy spellings (kineDBHost
		// parity) and fall back to def on anything unrecognized.
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1", "on":
			return true
		case "false", "no", "0", "off":
			return false
		}
	case int64:
		return t != 0
	}
	return def
}

func strOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

// strMap flattens a resolved *topology.OMap var into a plain
// string map (interdc_ssh_user_by_site).
func strMap(v any) map[string]string {
	out := map[string]string{}
	if om, ok := v.(*topology.OMap); ok && om != nil {
		for _, k := range om.Keys() {
			vv, _ := om.Get(k)
			out[k] = strOf(vv)
		}
	}
	return out
}
