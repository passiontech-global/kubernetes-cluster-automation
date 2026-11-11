// Drain phase: re-apply forgotten disables and drain the stale set.
// Split out of cycle.go (pure move).

package apiprober

import (
	"context"
	"maps"
	"slices"
)

// reapplyDrains re-applies disables HAProxy forgot — runtime
// disables are not persistent, so after a HAProxy restart a
// previously-drained wedged backend shows UP again. This pass
// covers ALL drained backends, not just ones flagged stale: a
// probe-side outage keeps a wedged backend out of `stale`, and
// without it the backend silently rejoins traffic for the whole
// outage. The stale loop below owns re-apply for its own entries
// (skip duplicates). Only discovered rows can show UP again —
// statics are constants with no HAProxy state to forget.
func (p *Prober) reapplyDrains(ctx context.Context, stale map[string]bool,
	statusByName map[string]backend, svnameByAddr map[string]string,
	fresh int) {

	log := logger()
	for _, name := range slices.Sorted(maps.Keys(p.states)) {
		st := p.states[name]
		if !st.drained {
			continue
		}
		if _, inStale := stale[name]; inStale {
			continue // the stale loop below re-applies these
		}
		b := statusByName[name]
		if !b.discovered || !b.up() {
			continue
		}
		svname, inPrimary := actionTarget(b, svnameByAddr)
		// apiprober-last-standing-fence: same last-standing fence as the drain phase —
		// when fresh < 1 a HAProxy restart may have resurrected
		// this server as the ONLY usable backend; re-disabling it
		// would take the VIP down with it.
		if fresh < 1 {
			continue
		}
		if p.eff.mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable",
				svname, !inPrimary); err != nil {
				log.Error("re-apply disable failed",
					"backend", name, "server", svname, "error", err)
			} else {
				log.Info("ACTION: re-applied disable — HAProxy forgot drained server",
					"backend", name)
				p.actions.WithLabelValues(name, "disable").Inc()
			}
		}
	}
}

// drainStale runs the drain phase over the stale set in name
// order: latch each stale backend's watchdog file, re-apply
// disables HAProxy forgot for entries already drained, fence on
// the last usable backend, then issue the disable. Each successful
// disable spends one fresh slot (*fresh--), so a run drains at
// most `fresh` stale backends — the fence then still has a usable
// backend to protect.
func (p *Prober) drainStale(ctx context.Context, stale map[string]bool,
	statusByName map[string]backend, svnameByAddr map[string]string,
	wdir string, fresh *int) {

	log := logger()
	for _, name := range slices.Sorted(maps.Keys(stale)) {
		st := p.states[name]
		b := statusByName[name]
		svname, inPrimary := actionTarget(b, svnameByAddr)
		if wdir != "" {
			// Wedged/dead this cycle → state_enter parity (the latch
			// gates 06-kubelet-watch-wedge's k0sworker restart).
			p.latchStale(wdir, b)
		}
		if st.drained {
			// Already drained — but a HAProxy restart forgets runtime
			// disables (socket state is not persistent). Re-apply
			// while HAProxy reports the server usable again; the
			// recovery path above re-enables via the drained flag.
			// Only discovered rows can show UP again — a static-only
			// backend is a constant "UP" with no HAProxy state to
			// forget, so re-applying would just repeat the socket
			// command every cycle.
			// apiprober-last-standing-fence: fence on fresh < 1 — same last-standing
			// protection as the drain phase below.
			if p.eff.mode == ModeEnforce && b.discovered && b.up() &&
				*fresh >= 1 {
				if err := p.haproxyServer(ctx, "disable",
					svname, !inPrimary); err != nil {
					log.Error("re-apply disable failed",
						"backend", name, "server", svname, "error", err)
				} else {
					log.Info("ACTION: re-applied disable — HAProxy forgot drained server",
						"backend", name)
					p.actions.WithLabelValues(name, "disable").Inc()
				}
			}
			continue
		}
		// FENCE: never disable the last usable backend. If every other
		// backend is stale/unreachable this cycle, draining more only
		// takes the VIP down with them — keep it, escalate via log.
		if *fresh < 1 {
			log.Info("FENCE: backend wedged but no fresh backend remains — not draining, manual action needed",
				"backend", name)
			p.actions.WithLabelValues(name, "fence_skip").Inc()
			continue
		}
		if p.eff.mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable",
				svname, !inPrimary); err != nil {
				log.Error("disable via HAProxy socket failed",
					"backend", name, "server", svname, "error", err)
				continue
			}
			st.drained = true
			// Staged drain (shell `fresh=$((fresh - 1))` parity):
			// every successful disable spends one fresh slot, so a
			// run drains at most `fresh` stale backends — the fence
			// above then still has a usable backend to protect.
			*fresh--
			p.actions.WithLabelValues(name, "disable").Inc()
			log.Info("ACTION: disabled backend — watch-cache wedge",
				"backend", name, "server", svname,
				"haproxyBackend", p.eff.backend,
				"freshRemaining", *fresh)
			if !inPrimary {
				// The name is not a svname of the primary backend
				// (static-only API_BACKENDS entry): the action was
				// issued to every configured backend but only a
				// companion could have carried it — the primary
				// "No such server" was a no-op, not a drain.
				log.Warn("backend is not a server of the primary HAProxy backend — drain reached companion backends only",
					"backend", name, "haproxyBackend", p.eff.backend)
			}
		} else {
			log.Info("DRY-RUN: would disable backend — watch-cache wedge",
				"backend", name, "freshRemaining", *fresh)
			p.actions.WithLabelValues(name, "dryrun_disable").Inc()
		}
	}
}
