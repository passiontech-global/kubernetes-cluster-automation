package hubsync

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
	bySite := map[string]string{}
	if som, _ := t.Vars.Get("interdc_ssh_user_by_site").(*jinja.OMap); som != nil {
		for _, k := range som.Keys() {
			bySite[k] = som.Str(k)
		}
	}

	// ssh_user resolution, 1:1 with hub_converge's add_host chains:
	//   interdc/api-lb: ssh_user → by_site[site] → default_user
	//   extra_hosts:    ssh_user → default_user   (no site lookup)
	userOf := func(om *jinja.OMap, siteMap bool) string {
		if u := om.Str("ssh_user"); u != "" {
			return u
		}
		if siteMap {
			if u := bySite[om.Str("site")]; u != "" {
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
		om, _ := nv.(*jinja.OMap)
		if om == nil || om.BoolDef("agent", true) {
			continue
		}
		name := k // registry key = OS hostname = --node-name
		add(Target{
			Name:      name,
			IP:        om.Str("ip"),
			SSHUser:   userOf(om, true),
			ProxyJump: om.Str("ssh_proxyjump"),
			InterDC:   true,
			Hub:       om.BoolDef("hub", false),
		})
	}

	// b. infra VMs needing node_exporter (+ kine_db flag).
	for _, e := range t.Vars.List("node_exporter_extra_hosts") {
		om, _ := e.(*jinja.OMap)
		if om == nil {
			continue
		}
		add(Target{
			Name:    om.Str("name"),
			IP:      om.Str("ip"),
			SSHUser: userOf(om, false),
			KineDB:  om.BoolDef("kine_db", false),
		})
	}

	// c. API LB VMs — guard credentials + flag.
	for _, e := range t.Vars.List("api_lb_guard_vms") {
		om, _ := e.(*jinja.OMap)
		if om == nil {
			continue
		}
		add(Target{
			Name:    om.Str("name"),
			IP:      om.Str("ip"),
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
//
// The strOf/strMap/omStr/omBool shims this package used to carry are
// gone: the typed getters on *jinja.OMap (Str/StrMap/BoolDef) are
// that family's single home now.
