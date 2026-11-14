// restart_gate.go — shared controller restart gate ladder
// (peer quorum -> cluster maintenance hold -> cooldown -> atomic spend + restart).
package cdeps

import (
	"context"
	"fmt"
	"time"
)

// RestartGateSpec configures the shared controller restart gate ladder.
type RestartGateSpec struct {
	Check         string
	State         string
	Budget        string
	Cooldown      time.Duration
	NeedQuorum    bool
	HoldPrefix    string
	Unit          string
	Mode          string
	ActionLine    string
	DryRunLine    string
	ActionLabel   string
	DryRunLabel   string
	BeforeRestart func()
}

// RestartWithGates evaluates the quorum/maintenance/cooldown gates and,
// when open, restarts Unit in ModeEnforce (atomically spending Budget via
// RateTrySpend) or logs in ModeDryRun. It returns the cycle outcome label
// ("quorum_hold", "maint_hold", "cooldown", or "ok") and whether a restart
// or dry-run action ran.
func (d *Deps) RestartWithGates(ctx context.Context, s RestartGateSpec) (string, bool) {
	mode := s.Mode
	if mode == "" {
		mode = d.Cfg.Sig13.Mode
	}
	if s.NeedQuorum && !d.ControllerQuorumReady(ctx) {
		d.State.SuspectLog(s.State, fmt.Sprintf(
			"suspect: %s but default/kubernetes reports <2 ready endpoints — holding restart",
			s.HoldPrefix), d.Cfg.SuspectLogCadence)
		return "quorum_hold", false
	}
	if d.HoldEmergencyHeal(ctx) {
		d.State.SuspectLog(s.State, fmt.Sprintf(
			"suspect: %s but cluster maintenance in progress — holding restart",
			s.HoldPrefix), d.Cfg.SuspectLogCadence)
		return "maint_hold", false
	}
	if !d.State.RateOK(s.Budget, s.Cooldown) {
		d.State.SuspectLog(s.State, fmt.Sprintf(
			"suspect: %s but in restart cooldown (<%dm), skip",
			s.HoldPrefix, int(s.Cooldown.Minutes())), d.Cfg.SuspectLogCadence)
		return "cooldown", false
	}
	switch mode {
	case ModeEnforce:
		if !d.State.RateTrySpend(s.Budget, s.Cooldown) {
			d.State.SuspectLog(s.State, fmt.Sprintf(
				"suspect: %s but in restart cooldown (<%dm), skip",
				s.HoldPrefix, int(s.Cooldown.Minutes())), d.Cfg.SuspectLogCadence)
			return "cooldown", false
		}
		d.State.AppendLog(s.ActionLine)
		if s.BeforeRestart != nil {
			s.BeforeRestart()
		}
		if err := d.Restart(ctx, s.Unit); err != nil {
			d.State.AppendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", s.Unit, err))
		}
		d.Actions.WithLabelValues(s.Check, s.ActionLabel).Inc()
		return "ok", true
	case ModeDryRun:
		d.State.AppendLog(s.DryRunLine)
		d.Actions.WithLabelValues(s.Check, s.DryRunLabel).Inc()
		return "ok", true
	}
	return "ok", false
}
