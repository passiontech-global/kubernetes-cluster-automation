// VIP phase and per-backend enabled-gauge export.
// Split out of cycle.go (pure move).

package apiprober

import (
	"context"
)

// syncVIP is the VIP phase: *_lb entries round-robin across
// controllers, so when any direct controller is wedged/drained
// AND >=1 direct controller is fresh (usableFresh — the pre-drain
// snapshot), disable the VIP entry so traffic goes straight to
// the healthy controller(s). Re-enable when all direct
// controllers are healthy again, or when fresh == 0 (least-bad).
// fresh here is the post-drain remainder, used for log fields
// only — the gate reads usableFresh.
func (p *Prober) syncVIP(ctx context.Context, backends, vips []backend,
	stale map[string]bool, usableFresh, fresh int) {

	log := logger()
	staleCtrlCount := 0
	for _, b := range backends {
		if b.vip() {
			continue
		}
		if stale[b.Name] || p.states[b.Name].drained {
			staleCtrlCount++
		}
	}
	wantVIPDisable := staleCtrlCount > 0 && usableFresh > 0
	for _, vip := range vips {
		st := p.states[vip.Name]
		if wantVIPDisable {
			if p.eff.mode == ModeEnforce {
				if !st.drained || vip.up() {
					if err := p.haproxyServer(ctx, "disable",
						vip.Name, false); err != nil {
						log.Error("disable VIP via HAProxy socket failed",
							"backend", vip.Name, "error", err)
						continue
					}
					st.drained = true
					p.actions.WithLabelValues(vip.Name, "disable").Inc()
					log.Info("ACTION: disabled VIP backend — direct controller wedged while fresh controller available",
						"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				}
			} else if !st.drained {
				st.drained = true
				log.Info("DRY-RUN: would disable VIP backend — direct controller wedged",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_disable").Inc()
			}
		} else if st.drained || vip.maint() {
			if p.eff.mode == ModeEnforce {
				if err := p.haproxyServer(ctx, "enable",
					vip.Name, false); err != nil {
					log.Error("enable VIP via HAProxy socket failed",
						"backend", vip.Name, "error", err)
					continue
				}
				st.drained = false
				p.actions.WithLabelValues(vip.Name, "enable").Inc()
				log.Info("ACTION: enabled VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
			} else {
				st.drained = false
				log.Info("DRY-RUN: would enable VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_enable").Inc()
			}
		}
	}
}

// exportEnabled writes the per-backend enabled gauge after all
// transitions: 1 while HAProxy reports the server UP and no drain
// is tracking it.
func (p *Prober) exportEnabled(backends []backend) {
	for _, b := range backends {
		v := 0.0
		if b.up() && !p.states[b.Name].drained {
			v = 1
		}
		p.enabled.WithLabelValues(b.Name).Set(v)
	}
}
