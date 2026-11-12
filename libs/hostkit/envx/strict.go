// strict.go — the strict env-getter family: node-automation-
// controller's ConfigMap-flag contract, ported verbatim from its
// retired internal/platform/envx and kept exactly, because these are
// the env contract of the controller's operator-facing flag
// ConfigMaps (the ported shell-operator CronJobs/kuberhealthy
// checks):
//
//   - an unparseable or out-of-range value warns via Warnf and falls
//     back to the default rather than being silently accepted — a
//     typo'd knob pinned to its default must be visible from outside;
//   - warn records keep that app's kv names ("key"/"value"/"default"/
//     "min", not the lenient family's "env" convention) so its log
//     pipeline sees the same record shape it always emitted;
//   - durations accept ONLY Go duration format with a >=1s floor —
//     every duration knob is a sweep interval where <=0 would panic
//     time.NewTicker and a sub-second value would hot-loop the sweep
//     (Duration in envx.go additionally accepts a bare integer as
//     seconds for shell-knob parity; GetenvDuration does not);
//   - Gate is exact-match: defaultOn=true enables unless the value is
//     exactly "false" (explicit opt-out); defaultOn=false enables only
//     when the value is exactly "true" (opt-in). Bool's lenient
//     1/true/yes/on vocabulary does not apply — but a set value drawn
//     from it (any casing) warns once per key while keeping the
//     default, so a casing slip cannot silently pin a gate.
package envx

import (
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Getenv reads a string env knob, returning def when unset or empty —
// identical semantics to String; the Getenv name is kept so the strict
// family reads as one contract.
func Getenv(key, def string) string {
	return String(key, def)
}

// GetenvInt reads an integer env knob. An unparseable value warns and
// falls back to def; the parsed value is kept verbatim — <=0 is a
// legitimate setting for the replica-pin knobs (minReplicas<=0
// disables the pin).
func GetenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		Warnf("unparseable integer env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// GetenvDuration reads a duration env knob. Unparseable values warn
// and fall back to def; so do parsed values < 1s — every duration
// knob is a sweep interval, where <=0 is never meaningful and would
// panic time.NewTicker downstream in shared.Periodic, and a
// sub-second interval would hot-loop the sweep.
func GetenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			return d
		}
		Warnf("invalid duration env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// parseFiniteFloat parses v as float64, rejecting NaN and ±Inf — the
// shared gate behind GetenvFloat and GetenvFloatPositive: non-finite
// values silently corrupt threshold comparisons downstream (NaN !=
// everything, +Inf > everything), so they take the same
// warn-and-default path as unparseable input.
func parseFiniteFloat(v string) (float64, bool) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// GetenvFloat reads a float env knob with the same warn-and-fallback
// contract as GetenvInt.
func GetenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, ok := parseFiniteFloat(v); ok {
			return f
		}
		Warnf("unparseable float env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// GetenvIntMin is GetenvInt with a lower bound: parsed values < min
// warn and fall back to def (e.g. a negative restart-limit knob would
// flag every object). min applies to the PARSED value only — def is
// returned verbatim whether or not it satisfies the bound, so callers
// may express "disabled" defaults outside the valid-input range.
func GetenvIntMin(key string, def, min int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= min {
			return n
		}
		Warnf("invalid integer env value, using default",
			"key", key, "value", v, "default", def, "min", min)
	}
	return def
}

// GetenvFloatPositive is GetenvFloat restricted to strictly positive
// values: unparseable input and f <= 0 warn and fall back to def.
// Values > 1 are kept — several threshold knobs document ">1 disables
// the check" as the operator escape hatch.
func GetenvFloatPositive(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, ok := parseFiniteFloat(v); ok && f > 0 {
			return f
		}
		Warnf("invalid float env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// gateIntentWarned remembers which keys already had their bool-like
// misspelling warned about — one line per key per process (Gate
// resolves in every sweep; a stale "True" in a ConfigMap must not
// spam the log). The table is capped: env keys are compile-time
// constants in practice, but nothing stops a caller resolving
// dynamic key names — on overflow the table is cleared so warn-once
// restarts rather than the map leaking.
var gateIntentWarned = struct {
	mu sync.Mutex
	m  map[string]struct{}
}{m: map[string]struct{}{}}

// gateIntentWarnCap bounds gateIntentWarned.m.
const gateIntentWarnCap = 1024

// gateIntentWarnOnce reports whether this is the first warning for
// key — atomic under the mutex so concurrent Gate resolutions still
// warn exactly once.
func gateIntentWarnOnce(key string) bool {
	gateIntentWarned.mu.Lock()
	defer gateIntentWarned.mu.Unlock()
	if _, ok := gateIntentWarned.m[key]; ok {
		return false
	}
	if len(gateIntentWarned.m) >= gateIntentWarnCap {
		clear(gateIntentWarned.m)
	}
	gateIntentWarned.m[key] = struct{}{}
	return true
}

// looksLikeGateIntent reports whether v reads as boolean intent Gate
// will silently drop: Bool's lenient vocabulary (1/0, true/false,
// yes/no, on/off) in any casing. Exact "true"/"false" — the two
// values Gate actually applies — are handled before this runs and
// never land here; anything else in the vocabulary is a mis-cased or
// synonym spelling that quietly fell back to the default.
func looksLikeGateIntent(v string) bool {
	switch strings.ToLower(v) {
	case "1", "0", "true", "false", "yes", "no", "on", "off":
		return true
	}
	return false
}

// Gate resolves a feature-gate env var. defaultOn=false is the
// opt-in convention (enabled only when the value is exactly "true" —
// the destructive/opt-in gates); defaultOn=true is the always-on
// convention the ported CronJobs/kuberhealthy checks kept (enabled
// unless the value is exactly "false" — an explicit opt-out via the
// base-flags ConfigMap).
//
// A set value that LOOKS like boolean intent but misses the exact
// spelling (e.g. "True", "0", "on") warns once per key and keeps the
// default — the returned behavior is unchanged, but a knob pinned to
// its default by a casing slip becomes visible from the outside.
func Gate(key string, defaultOn bool) bool {
	v := os.Getenv(key)
	switch v {
	case "false":
		return false
	case "true":
		return true
	}
	if looksLikeGateIntent(v) {
		if gateIntentWarnOnce(key) {
			Warnf("bool-like gate value not applied — set exactly \"true\" or \"false\", using default",
				"key", key, "value", v, "default_on", defaultOn)
		}
	}
	return defaultOn
}
