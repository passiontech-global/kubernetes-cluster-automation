// setup.go — SetupWithConfig: the "parse knobs → honor
// Deps.Disabled → register" contract every module's Setup
// implements by hand today:
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
// structural: a parse that silently ran after the gate is
// impossible to write.
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
