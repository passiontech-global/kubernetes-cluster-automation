// setup.go — the two Setup gate helpers every module's Setup is
// built on, making the "knobs → Deps.Disabled → register" contract
// structural instead of comment-enforced:
//
//	cfg := knobs{interval: envx.GetenvDuration(...), limit: envx.GetenvIntMin(...)}
//	if d.Disabled {
//		return nil // gate off — register nothing, but the parses above already warned
//	}
//	return AddPeriodic(d.Mgr, d.Name, cfg.interval, ...)
//
// The ordering matters and is only comment-enforced in the
// hand-rolled versions: knob parsing must run BEFORE the Disabled
// gate so unparseable env values warn even for a disabled module
// (the corednspatcher/metricsserverpatcher contract on
// Deps.Disabled), while register — manager Adds, builder watches —
// must run only when enabled. SetupWithConfig makes the ordering
// structural for modules WITH knobs: a parse that silently ran
// after the gate is impossible to write. SetupNoConfig is the same
// gate for modules with NO env parsing — there is nothing to warn
// about, but routing the bare `if d.Disabled { return nil }`
// through the helper keeps a future knob from landing AFTER the
// gate, the regression the hand-rolled shape invites.
package shared

// SetupWithConfig runs parse (knob resolution — its warnings fire
// even for a disabled module), then honors Deps.Disabled: a
// disabled module returns nil without register ever running; an
// enabled one hands the parsed config to register and propagates
// its error. C is the module's private knob struct — the type
// parameter keeps register type-safe without an any-cast.
func SetupWithConfig[C any](d Deps, parse func() C, register func(C) error) error {
	cfg := parse()
	if d.Disabled {
		return nil
	}
	return register(cfg)
}

// SetupNoConfig runs register only when the module is enabled —
// the no-knob counterpart of SetupWithConfig for modules whose
// Setup has no env parsing to warn about. Deps.Disabled returns nil
// before register ever runs; an enabled module hands straight to
// register and propagates its error. Modules that later grow a knob
// must switch to SetupWithConfig so the parse lands BEFORE the gate
// — SetupNoConfig has no parse slot, so the ordering cannot silently
// invert.
func SetupNoConfig(d Deps, register func() error) error {
	if d.Disabled {
		return nil
	}
	return register()
}
