// apiprober_refresh.go — the apiprober client refresh path:
// refreshGuard re-derives the guard conf, refreshClient rebuilds
// the http.Client when CA/statics change, plus the small helpers
// (firstNonEmpty/dedupStatic). Split out of
// apiprober.go — the prober loop and backend dispatch stay there.

package apiprober

import (
	"net/http"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// refreshGuard re-reads the guard conf (GuardSrc) and re-derives
// p.eff. Called once per Cycle — a conf written by hostconfig's
// first converge, or edited later via api_lb_guard_vms, applies on
// the NEXT cycle, not the next agent restart (the incident shape:
// an agent booted before the conf existed pinned the SA-path token
// fallback → every probe qfailed → enforce-mode drain ~60s in).
//
// Overlay rule: a key the conf carries wins over the startup Config
// value (the conf is the managed contract — hostconfig owns it)
// UNLESS env set that field — the documented chain is env >
// guard.conf > default, so ConfigFromEnv records which knobs env
// carried in cfg.envSet and those are never shadowed; keys absent
// from the conf fall through to Config. A garbage MODE degrades to
// the non-enforce (dry-run) paths — fail-safe.
func (p *Prober) refreshGuard() {
	var g GuardDefaults
	if p.cfg.GuardSrc != nil {
		g = p.cfg.GuardSrc.Get()
	}
	e := &p.eff
	s := p.cfg.envSet
	// env > guard.conf > default: a knob env explicitly set keeps
	// cfg's value — the live conf overlay only reaches fields env
	// left unset (cfg then holds the startup conf/default value,
	// which a later conf edit may still override).
	str := func(set bool, cfgVal, confVal string) string {
		if set || confVal == "" {
			return cfgVal
		}
		return confVal
	}
	num := func(set bool, cfgVal, confVal int64) int64 {
		if set || confVal <= 0 {
			return cfgVal
		}
		return confVal
	}
	e.socket = str(s.socket, p.cfg.SocketPath, g.SocketPath)
	e.backend = str(s.backend, p.cfg.BackendName, g.BackendName)
	e.mode = str(s.mode, p.cfg.Mode, g.Mode)
	e.tokenFile = str(s.tokenFile, p.cfg.TokenFile, g.TokenFile)
	e.caFile = str(s.caFile, p.cfg.CAFile, g.CAFile)
	if s.companions {
		e.companions = p.cfg.CompanionBackends
	} else if len(g.CompanionBackends) > 0 {
		e.companions = g.CompanionBackends
	} else {
		e.companions = p.cfg.CompanionBackends
	}
	// Conf entries first so a same-name edit wins the dedup — a
	// mid-run API_BACKENDS change must REPLACE the startup value,
	// not be shadowed by it.
	e.statics = dedupStatic(append(
		append([]StaticBackend{}, g.StaticBackends...),
		p.cfg.StaticBackends...))
	e.gapMin = num(s.gapMin, p.cfg.GapMin, g.GapMin)
	e.failCycles = int(num(s.failCycles, int64(p.cfg.FailCycles), int64(g.FailCycles)))
	e.frozen = int(num(s.frozen, int64(p.cfg.FrozenCycles), int64(g.FrozenCycles)))
	e.recoverC = int(num(s.recoverC, int64(p.cfg.RecoverCycles), int64(g.RecoverCycles)))
	p.refreshClient()
}

// refreshClient rebuilds the TLS client when the effective CA
// changed (conf edit or bundle rotation). Skipped entirely for an
// injected HTTPClient or InsecureTLS — the -sk client never consults
// the CA. An unreadable/invalid CA keeps the last-good client and
// retries next cycle.
func (p *Prober) refreshClient() {
	if p.cfg.HTTPClient != nil || p.cfg.InsecureTLS {
		return
	}
	var statKey string
	if p.eff.caFile != "" {
		// Stat-gate before caClient's read+PEM-parse+sha256: an
		// unchanged (dev,ino,size,mtime) fingerprint proves the
		// bundle can't have rotated — hostconfig writes CAs by
		// atomic rename, which always lands a new inode. A stat
		// error falls through to caClient, which reports it and
		// keeps the last-good client (unchanged contract).
		if sk, err := fsx.FileStatKey(p.eff.caFile); err == nil {
			statKey = sk
			if sk == p.caStat {
				return
			}
		}
	}
	cl, key, err := caClient(p.eff.caFile)
	if err != nil {
		if p.client == nil {
			// Lazy build still failing — the CA has not landed yet
			// (hostconfig renders guard.conf after agent start).
			// Warn and retry next cycle; probes in between report
			// probe-side errors.
			logger().Warn("apiprober: CA load failed — no probe client yet",
				"ca", p.eff.caFile, "error", err)
			return
		}
		logger().Error("apiprober: CA load failed — keeping previous TLS client",
			"ca", p.eff.caFile, "error", err)
		return
	}
	p.caStat = statKey
	if key != p.caKey {
		if p.client != nil {
			p.client.CloseIdleConnections() // drop the rotated client's pool
		}
		p.client, p.caKey = cl, key
		logger().Info("apiprober: built TLS client — effective CA loaded",
			"ca", p.eff.caFile)
	}
}

// probeClient returns the probe HTTP client, building it on first
// use — refreshClient runs per Cycle, but a probe issued before the
// CA exists (or with the stat-gate deciding the bundle is unchanged
// while the client was never built) must not nil-pointer. A CA-load
// failure here classifies probe-side (TLS trust) — it is never
// apiserver evidence.
func (p *Prober) probeClient() (*http.Client, error) {
	if p.client != nil {
		return p.client, nil
	}
	cl, key, err := caClient(p.eff.caFile)
	if err != nil {
		return nil, err
	}
	p.client, p.caKey = cl, key
	logger().Info("apiprober: TLS client built on first probe — CA landed",
		"ca", p.eff.caFile)
	return p.client, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// dedupStatic keeps the first entry per name — later duplicates are
// dropped (a same-named entry present in both the startup config and
// the live guard conf must not be double-probed; ordering decides
// precedence, see refreshGuard).
func dedupStatic(in []StaticBackend) []StaticBackend {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, sb := range in {
		if sb.Name == "" || seen[sb.Name] {
			continue
		}
		seen[sb.Name] = true
		out = append(out, sb)
	}
	return out
}
