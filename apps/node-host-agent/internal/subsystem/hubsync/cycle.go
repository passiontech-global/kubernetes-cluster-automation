// cycle.go — one hubsync converge cycle: re-parse targets, fetch the
// guard secret once, fan out the serial per-target converges and keep
// the per-target metric series honest (up/last_success/cycles).
package hubsync

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

// Cycle is one full converge round — the hub_converge CronJob run:
// re-parse targets (vars drift), fetch the guard credentials when an
// api-lb VM is in scope, then converge each target serially.
// hub_converge used serial:1 — two controllers/lighthouses are never
// in the restart window together, and SSH fan-out stays trivially
// debuggable in logs.
func (s *Syncer) Cycle(ctx context.Context) {
	// A cycle attempt while holding the lease counts — failures are
	// metered + logged, and the retry cadence is SyncInterval /
	// watcher edges, not the renew tick.
	s.markSynced()
	targets, dropped, notes, err := loadTargets(s.cfg.VarsDir)
	if err != nil {
		s.cfg.Log.Error("hubsync: target aggregation failed", "error", err)
		s.cycles.WithLabelValues("all", "parse_error").Inc()
		s.markAllKnownDown()
		return
	}
	if len(notes) > 0 {
		// topology.Load reports non-fatal resolution notes (marker
		// dups, zone/jinja eval failures) — surface and meter them,
		// but still converge the targets that did resolve.
		s.cfg.Log.Warn("hubsync: vars resolution notes — converging anyway",
			"notes", notes)
		s.cycles.WithLabelValues("all", "parse_note").Inc()
	}
	s.pruneStaleTargets(targets, dropped)
	s.lastTargets = s.lastTargets[:0]
	for _, t := range targets {
		s.lastTargets = append(s.lastTargets, t.Name)
	}
	for _, name := range dropped {
		// Inventory entry resolved to an EMPTY ip — nothing to
		// dial, but the host is still declared: keep its series
		// (last_success stays as evidence of the last good
		// converge) and read it DOWN. Dropping it from lastTargets
		// would prune the series entirely — the old loud failure
		// mode replaced by silent disappearance.
		s.lastTargets = append(s.lastTargets, name)
		s.targetUp.WithLabelValues(name).Set(0)
		s.cycles.WithLabelValues(name, "unresolved").Inc()
		s.cfg.Log.Warn("hubsync: target resolved to no ip — marked down, series kept",
			"target", name)
	}

	var token, ca []byte
	guardOK := true
	if anyAPILB(targets) {
		token, ca, err = s.guardCreds(ctx)
		if err != nil {
			// Only api-lb targets consume the guard credentials —
			// the failure scopes to them; interdc/infra targets
			// still converge this cycle.
			s.cfg.Log.Error("hubsync: api-backend-guard secret fetch failed — api-lb targets skipped",
				"secret", s.cfg.SecretNamespace+"/"+s.cfg.SecretName, "error", err)
			s.cycles.WithLabelValues("all", "secret_error").Inc()
			guardOK = false
		}
	}

	// The local binary hash is computed ONCE per cycle — the old
	// per-target sha256File ran 10x ~15MiB disk reads per cycle on a
	// 10-target inventory (pagecache.Drop after it re-faulted the
	// same pages anyway). A hash failure aborts the whole cycle:
	// every target's binary compare needs it, same blast radius as
	// the parse error above.
	localSum, err := sha256File(s.cfg.LocalBinary)
	if err != nil {
		s.cfg.Log.Error("hubsync: local binary hash failed — cycle aborted",
			"path", s.cfg.LocalBinary, "error", err)
		s.cycles.WithLabelValues("all", "error").Inc()
		s.markAllKnownDown()
		return
	}

	converged, skipped, failed, complete := s.convergeTargets(ctx, targets, token, ca, localSum, guardOK)
	if complete {
		s.cfg.Log.Info("hubsync: converge cycle complete",
			"targets", len(targets), "converged", converged,
			"skipped", skipped, "failed", failed)
	}
}

// markAllKnownDown reads every last-known target DOWN — the shared
// abort path (parse failure, local-binary-hash failure): nothing
// converged this cycle, so every last-known target must read down
// until a good cycle runs again, otherwise target_up{...}=1 stays
// stale forever.
func (s *Syncer) markAllKnownDown() {
	for _, name := range s.lastTargets {
		s.targetUp.WithLabelValues(name).Set(0)
	}
}

// convergeTargets runs syncTarget across the cycle's targets
// serially — hub_converge used serial:1 — with the per-target
// bookkeeping: the lease re-check (split-brain guard), the api-lb
// skip when the guard credentials are unavailable, and the
// up/last_success/counter updates. It reports the tally and whether
// the loop ran to the end; a mid-cycle ctx cancellation or lost
// lease aborts silently — no summary line, same as before the split.
func (s *Syncer) convergeTargets(ctx context.Context, targets []Target,
	token, ca []byte, localSum string, guardOK bool) (converged, skipped, failed int, complete bool) {
	for i, t := range targets {
		if ctx.Err() != nil {
			return
		}
		// Re-check the hold before EVERY target — a multi-minute
		// WAN converge can easily outlive the 60s LeaseDuration if
		// the renewer stalls, and continuing would have two holders
		// SSH-converging the same fleet (split-brain).
		if !s.leaseHeld() {
			s.cfg.Log.Warn("hubsync: lease lost or lapsed mid-cycle — "+
				"aborting converge", "done", i, "remaining",
				len(targets)-i)
			return
		}
		// Per-target heartbeat: a long serial fan-out (SSH timeouts,
		// slow remote agents) must not look like a wedged watcher —
		// the liveness stamp proves the cycle is alive between
		// targets, not just at the outer loop's edges.
		cycle.Heartbeat(ctx)
		if t.APILB && !guardOK {
			s.cfg.Log.Error("hubsync: api-lb target skipped — guard credentials unavailable",
				"target", t.Name, "ip", t.IP)
			s.cycles.WithLabelValues(t.Name, "secret_error").Inc()
			s.targetUp.WithLabelValues(t.Name).Set(0)
			skipped++
			continue
		}
		if err := s.syncTarget(ctx, t, token, ca, localSum); err != nil {
			s.cfg.Log.Error("hubsync: target converge failed",
				"target", t.Name, "ip", t.IP, "error", err)
			s.cycles.WithLabelValues(t.Name, "error").Inc()
			s.targetUp.WithLabelValues(t.Name).Set(0)
			failed++
			continue
		}
		s.cycles.WithLabelValues(t.Name, "ok").Inc()
		s.lastSuccess.WithLabelValues(t.Name).SetToCurrentTime()
		s.targetUp.WithLabelValues(t.Name).Set(1)
		s.cfg.Log.Info("hubsync: target converged", "target", t.Name, "ip", t.IP)
		converged++
	}
	complete = true
	return
}

// pruneStaleTargets drops the metric series of targets no longer in
// the vars-derived set — a renamed/removed host would otherwise keep
// its target_up/last_success label values (and last value) on the
// registry forever. Runs only after a successful loadTargets, so a
// parse failure never prunes (the abort path zeroes instead).
// keep names hosts that ARE still in the inventory but resolved to
// no ip this cycle — they are not in targets yet their series must
// survive (they read target_up=0 as evidence, not vanish).
// (apiprober.pruneStaleBackends pattern.)
func (s *Syncer) pruneStaleTargets(targets []Target, keep []string) {
	live := make(map[string]bool, len(targets)+len(keep))
	for _, t := range targets {
		live[t.Name] = true
	}
	for _, name := range keep {
		live[name] = true
	}
	for _, name := range s.lastTargets {
		if live[name] {
			continue
		}
		s.lastSuccess.DeleteLabelValues(name)
		s.targetUp.DeleteLabelValues(name)
		// cycles carries a second label (result) — drop every series
		// whose target label matches.
		s.cycles.DeletePartialMatch(prometheus.Labels{"target": name})
		s.cfg.Log.Info("hubsync: target left vars — pruned metric series",
			"target", name)
	}
}

func anyAPILB(targets []Target) bool {
	for _, t := range targets {
		if t.APILB {
			return true
		}
	}
	return false
}

// guardCreds reads the api-backend-guard Secret — hub_converge fetched
// the same secret via the in-cluster API to push token+ca.crt to the
// api-lb VM.
func (s *Syncer) guardCreds(ctx context.Context) (token, ca []byte, err error) {
	sec, err := s.cfg.Client.CoreV1().Secrets(s.cfg.SecretNamespace).
		Get(ctx, s.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	token, ca = sec.Data["token"], sec.Data["ca.crt"]
	if len(token) == 0 || len(ca) == 0 {
		// A secret that exists but lacks the keys would otherwise
		// converge "ok" while pushing nothing — surface it as a
		// secret_error like a missing secret.
		return nil, nil, fmt.Errorf("secret %s/%s missing token/ca.crt data",
			s.cfg.SecretNamespace, s.cfg.SecretName)
	}
	return token, ca, nil
}
