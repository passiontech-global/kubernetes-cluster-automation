package apiprober

import (
	"net"
	"strings"
)

// backend is one server row discovered from `show stat`.
type backend struct {
	Name   string
	Addr   string // ip:port for direct API queries
	Status string // haproxy-reported status (UP, DOWN, MAINT, ...)
	// discovered marks a real `show stat` row: Name is a HAProxy
	// svname and Status is live. Static-merged rows leave it false —
	// their Name is the configured API_BACKENDS name (possibly a raw
	// addr), which may not be a svname in ANY HAProxy backend, so
	// socket actions on it tolerate "No such server" replies.
	discovered bool
}

// up reports whether HAProxy considers the backend usable. An
// admin-disabled server reports MAINT — it must not count toward the
// drain fence even if its API probes are fresh.
func (b backend) up() bool { return strings.HasPrefix(b.Status, "UP") }

// maint reports an admin-disabled server (disable via socket, or the
// disable restored from server-state-file after a HAProxy restart).
// Treated like a drain for the recovery path: a backend stays
// re-enableable after RecoverCycles fresh probes even when the
// process-memory drained flag was lost to an agent restart — the
// alternative is a healthy apiserver stranded in MAINT forever.
// Caveat: this also undoes deliberate manual drains (the shell guard
// used on-disk drained-* marker files for that distinction).
func (b backend) maint() bool { return strings.HasPrefix(b.Status, "MAINT") }

// vip reports a load-balancer VIP server entry (suffix "_lb", e.g.
// api_datahub_lb in worker api-local-lb). VIP entries round-robin
// across multiple controllers, so their cached/live queries can land on
// different backends and must not be probed directly or counted toward
// the drain fence. Instead they follow sig14b semantics: disabled when
// any direct controller is wedged while >=1 direct controller remains
// fresh, and re-enabled when all controllers are healthy or when no
// direct controller is usable (least-bad).
func (b backend) vip() bool { return strings.HasSuffix(b.Name, "_lb") }

// statics returns the effective static backend set: the
// guard-conf-overlaid set (eff.statics, already deduped by name —
// conf first) plus, when WatchdogSrc is wired, node-watchdog.conf's
// API_BACKENDS re-read this call (the runner re-sourced the conf
// every run).
func (p *Prober) statics() []StaticBackend {
	out := append([]StaticBackend{}, p.eff.statics...)
	if p.cfg.WatchdogSrc != nil {
		for _, b := range p.cfg.WatchdogSrc.Get().APIBackends {
			out = append(out, StaticBackend{Name: b.Name, Addr: b.Addr})
		}
	}
	return out
}

// staticAddr resolves a server name to its static-backend Addr ("" =
// not configured), normalized with the bash default port. Inside
// Cycle it reads the per-cycle snapshot — resolving via statics()
// per empty-addr row would re-parse the watchdog conf once per row.
func (p *Prober) staticAddr(name string) string {
	set := p.cycleStatics
	if set == nil {
		set = p.statics() // outside Cycle (tests/direct calls)
	}
	for _, sb := range set {
		if sb.Name == name {
			return withDefaultPort(sb.Addr)
		}
	}
	return ""
}

// withDefaultPort fills the port on a bare-IP/-host backend address
// — api-backend-guard.sh defaulted API_BACKENDS entries without a
// port to 443. A missing port made every TCP preflight fail with
// "missing port in address" → the backend counted unreachable
// forever, never probed.
func withDefaultPort(addr string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), "443")
}

// mergeStatic appends StaticBackends entries missing from discovery
// as UP servers — they take traffic via their LB so they count toward
// the drain fence like any discovered UP backend. Entries collapse
// onto discovery two ways: same name (discovery wins — it carries
// the live HAProxy status) and same normalized addr — the same
// physical apiserver must be tracked ONCE: a second identity keyed
// by its raw addr is probed twice per cycle under its own counters
// and, when wedged, drains under a name HAProxy does not know
// (`disable server <backend>/<addr>` → "No such server" on every
// cycle — incident: API_BACKENDS carries bare "ip:port" entries that
// name themselves). Static-vs-static duplicates collapse the same
// way: named entries claim their addr first, so a bare self-named
// "ip:port" entry never shadows a configured name for the same
// apiserver; within each class first entry wins (ordering decides
// precedence, see refreshGuard).
func mergeStatic(backends []backend, static []StaticBackend) []backend {
	seen := make(map[string]bool, len(backends))
	seenAddr := make(map[string]bool, len(backends))
	for _, b := range backends {
		seen[b.Name] = true
		seenAddr[withDefaultPort(b.Addr)] = true
	}
	appendStatic := func(sb StaticBackend) {
		addr := withDefaultPort(sb.Addr)
		if seen[sb.Name] || seenAddr[addr] {
			return
		}
		seen[sb.Name] = true
		seenAddr[addr] = true
		backends = append(backends, backend{
			Name: sb.Name, Addr: addr, Status: "UP",
		})
	}
	var bare []StaticBackend
	for _, sb := range static {
		if sb.Name == "" || sb.Addr == "" {
			continue
		}
		// Char-spray guard: a jinja-scalar var that resolved to a
		// STRING reaches the caller as rune-by-rune elements — skip
		// anything that can't be a real backend name/addr.
		if len(sb.Name) < 2 ||
			strings.ContainsAny(sb.Name+sb.Addr, " \t'\"[]{}(),") {
			logger().Warn("apiprober: skipping malformed API_BACKENDS entry",
				"name", sb.Name, "addr", sb.Addr,
			)
			continue
		}
		// Bare "ip:port" API_BACKENDS entries parse self-named
		// (Name == Addr — watchdogconf parity). Hold them back so a
		// configured name for the same addr claims it first.
		if sb.Name == sb.Addr {
			bare = append(bare, sb)
			continue
		}
		appendStatic(sb)
	}
	for _, sb := range bare {
		appendStatic(sb)
	}
	return backends
}

// actionTarget resolves the HAProxy server name a guard action must
// use for backend b, and whether the resolved name is a svname of
// the primary backend. Discovered rows name themselves; a
// static-merged entry that shadows a discovered addr resolves to
// that row's svname — an addr is never a valid svname. A
// static-only name returns (name, false): absent from the primary
// backend, so a "No such server" reply there is an expected no-op
// (the name may still exist on a companion backend — the action is
// still issued there).
func actionTarget(b backend, svnameByAddr map[string]string) (svname string, inPrimary bool) {
	if b.discovered {
		return b.Name, true
	}
	if sv, ok := svnameByAddr[withDefaultPort(b.Addr)]; ok {
		return sv, true
	}
	return b.Name, false
}
