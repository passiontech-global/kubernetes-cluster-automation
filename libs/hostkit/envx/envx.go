// Package envx packages the env-getter helpers shared by the apps in
// this monorepo — originally lifted out of node-host-agent's cmd/agent,
// which used them to parse its NODE_HOST_AGENT_* knobs — so subsystem
// packages can own their env contracts. Each func reads os.Getenv
// itself; unset/empty semantics mirror the original helpers exactly.
//
// Two contracts live here, kept distinct because they are different
// user-facing agreements:
//
//   - the lenient family (String, Bool, Int, Int64, Duration, List,
//     … and the *Knob table constructors) — node-host-agent's
//     shell-knob convention: unrecognised input quietly falls back to
//     the default;
//   - the strict family (the Getenv* getters and Gate, marked below)
//     — node-automation-controller's ConfigMap-flag convention,
//     ported verbatim from its retired internal/platform/envx: an
//     unparseable or out-of-range value warns (through Warnf) and
//     falls back to the default, durations require Go format and a
//     >=1s floor, and Gate accepts only exact "true"/"false".
package envx

import (
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// String returns the env value, or def when unset or empty.
func String(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Bool parses a boolean env var; unset/empty/unrecognised → def.
// Accepts 1/0, true/false, yes/no, on/off (case-sensitive).
func Bool(key string, def bool) bool {
	switch os.Getenv(key) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// Mode is the tri-state of the NODE_HOST_AGENT_ENABLE_* knobs: On
// and Off are explicit operator choices; Auto defers the decision to
// the consumer — a detect function or a compiled default (the
// descriptor registry in cmd/agent is the consumer today).
type Mode int

const (
	// ModeAuto leaves the enabled decision to the consumer's own
	// detect logic.
	ModeAuto Mode = iota
	ModeOn
	ModeOff
)

// ModeEnv parses a tri-state enable knob: "1"/"true"/"yes"/"on" →
// ModeOn, "0"/"false"/"no"/"off" → ModeOff, and "auto"/unset/empty —
// plus anything unrecognised, mirroring Bool's lenient contract —
// → def (which may itself be ModeAuto). The getter is named ModeEnv,
// not Mode, so it can't collide with the type.
func ModeEnv(key string, def Mode) Mode {
	switch os.Getenv(key) {
	case "1", "true", "yes", "on":
		return ModeOn
	case "0", "false", "no", "off":
		return ModeOff
	default:
		return def
	}
}

// Int parses an int env var; unset/empty/non-numeric → def.
func Int(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// Int64 parses an int64 env var; unset/empty/non-numeric → def.
func Int64(key string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(key), 10, 64); err == nil {
		return v
	}
	return def
}

// Or is the env → conf → (caller) chain for string knobs: an unset or
// empty env falls through to the conf value, which may itself be
// empty — the consumer's compiled default then applies.
func Or(key, confVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return confVal
}

// Str returns a unless empty — the conf → compiled-default tail of the
// fallback chains.
func Str(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// IsSet reports whether key is present and non-empty — the
// env-presence check layered config fallbacks (env → conf file →
// compiled default) use to know whether the env layer spoke. It
// answers "did the env say anything", not "is the value valid" —
// parse-level fallback stays with the consuming getter.
func IsSet(key string) bool { return os.Getenv(key) != "" }

// IntOr is env → conf → def for int knobs (conf ints are raw counts;
// <=0 = unset). A set-but-non-numeric env yields def, not confVal.
func IntOr(key string, confVal, def int) int {
	if os.Getenv(key) != "" {
		return Int(key, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// Int64Or is env → conf → def for int64 knobs. A set-but-non-numeric
// env yields def, not confVal.
func Int64Or(key string, confVal, def int64) int64 {
	if os.Getenv(key) != "" {
		return Int64(key, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// DurOr is env → conf-seconds → def for duration knobs (conf carries
// bare seconds like the shell *_S knobs). A set-but-unparseable or
// non-positive env yields def, not confSeconds.
func DurOr(key string, confSeconds int, def time.Duration) time.Duration {
	if os.Getenv(key) != "" {
		return Duration(key, def)
	}
	if confSeconds > 0 {
		// Same overflow guard as Duration: a conf value past the
		// int64-second ceiling would wrap to a bogus interval.
		if int64(confSeconds) > math.MaxInt64/int64(time.Second) {
			Warnf("conf duration overflows int64 — using default",
				"env", key, "conf_seconds", confSeconds, "default", def)
			return def
		}
		return time.Duration(confSeconds) * time.Second
	}
	return def
}

// Duration parses a Go duration ("1h", "30s"); a bare integer is
// treated as seconds for parity with the shell knobs it replaces.
// Unset/empty → def. Unparseable or non-positive values warn and fall
// back to def — a ≤0 interval would panic time.NewTicker inside the
// subsystem and crash-loop the daemon.
func Duration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var d time.Duration
	if parsed, err := time.ParseDuration(v); err == nil {
		d = parsed
	} else if n, err := strconv.Atoi(v); err == nil {
		// The bare-integer seconds path must not wrap: values past
		// MaxInt64/1e9 seconds overflow int64 nanoseconds and can land
		// on a bogus positive interval the <=0 check below would miss.
		if int64(n) > math.MaxInt64/int64(time.Second) ||
			int64(n) < math.MinInt64/int64(time.Second) {
			Warnf("env duration overflows int64 — using default",
				"env", key, "value", v, "default", def)
			return def
		}
		d = time.Duration(n) * time.Second
	} else {
		// Neither shape parsed — a typo'd knob silently pinned to the
		// default is impossible to spot from the outside.
		Warnf("unparseable env duration ignored — using default",
			"env", key, "value", v, "default", def)
		return def
	}
	if d <= 0 {
		Warnf("non-positive env duration ignored — using default",
			"env", key, "value", v, "default", def)
		return def
	}
	return d
}

// List parses a comma-separated env var, trimming spaces and dropping
// empty entries; unset/empty → nil (the consumer applies its own
// defaults — nil vs empty slice matters to callers).
func List(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IntList parses a comma-separated env var of ints; unset/empty → nil.
// Non-numeric entries are skipped with a warning.
func IntList(key string) []int {
	var out []int
	for _, p := range List(key) {
		n, err := strconv.Atoi(p)
		if err != nil {
			Warnf("non-numeric env list entry ignored",
				"env", key, "value", p)
			continue
		}
		out = append(out, n)
	}
	return out
}

// Warnf is the sink for the "invalid env value — using default"
// diagnostics emitted by the getters (Duration, IntList, and the
// strict Getenv* family below). Its default implementation is a
// dispatcher: it reads warnfHook first and falls back to the package
// slog logger when no hook is installed — so SetWarnf rebinds the
// sink WITHOUT touching this var, and getter traffic keeps routing
// through the var (one atomic load per call) race-free.
//
// Rebinding — two shapes, one rule:
//   - SetWarnf is the supported path: atomic swap, race-free against
//     concurrent getter calls, composable (SetWarnf(nil) restores the
//     slog default). node-automation-controller's startup init() and
//     every test use it.
//   - The legacy direct assignment (`envx.Warnf = f`) still works —
//     the var stays assignable — but it REPLACES the dispatcher, so
//     the var write is racy against concurrent getter traffic and it
//     orphans any installed hook (later SetWarnf calls route nowhere
//     until the var is reassigned). Only legal strictly before the
//     first getter call, same as the original pre-SetWarnf ordering
//     contract; whichever path installed the current sink last wins.
var warnfHook atomic.Pointer[func(msg string, kv ...any)]

var Warnf = func(msg string, kv ...any) {
	if f := warnfHook.Load(); f != nil {
		(*f)(msg, kv...)
		return
	}
	logger().Warn(msg, kv...)
}

// SetWarnf atomically rebinds the diagnostic sink; nil restores the
// package slog default. Race-free against concurrent Warnf traffic, so
// tests and late-rebinding apps rebind through here instead of
// assigning the Warnf var.
func SetWarnf(f func(msg string, kv ...any)) {
	if f == nil {
		warnfHook.Store(nil)
		return
	}
	warnfHook.Store(&f)
}

// --------------------------------------------------------------------
// Strict family — node-automation-controller's ConfigMap-flag contract.
//
// The Getenv* getters and Gate below were ported verbatim from
// apps/node-automation-controller/internal/platform/envx and keep its
// semantics exactly, because they are the env contract of the
// controller's operator-facing flag ConfigMaps (the ported
// shell-operator CronJobs/kuberhealthy checks):
//
//   - an unparseable or out-of-range value warns via Warnf and falls
//     back to the default rather than being silently accepted — a
//     typo'd knob pinned to its default must be visible from outside;
//   - warn records keep that app's kv names ("key"/"value"/"default"/
//     "min", not this package's "env" convention) so its log pipeline
//     sees the same record shape it always emitted;
//   - durations accept ONLY Go duration format with a >=1s floor —
//     every duration knob is a sweep interval where <=0 would panic
//     time.NewTicker and a sub-second value would hot-loop the sweep
//     (Duration above additionally accepts a bare integer as seconds
//     for shell-knob parity; GetenvDuration does not);
//   - Gate is exact-match: defaultOn=true enables unless the value is
//     exactly "false" (explicit opt-out); defaultOn=false enables only
//     when the value is exactly "true" (opt-in). Bool's lenient
//     1/true/yes/on vocabulary does not apply — but a set value drawn
//     from it (any casing) warns once per key while keeping the
//     default, so a casing slip cannot silently pin a gate.
// --------------------------------------------------------------------

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

// GetenvFloat reads a float env knob with the same warn-and-fallback
// contract as GetenvInt. ParseFloat also accepts "NaN"/"Inf"/"+Inf"/
// "-Inf" — non-finite values silently corrupt threshold comparisons
// downstream (NaN != everything, +Inf > everything), so they take the
// same warn-and-default path as unparseable input.
func GetenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil &&
			!math.IsNaN(f) && !math.IsInf(f, 0) {
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
// Non-finite values take the same warn-and-default path as
// GetenvFloat — "+Inf" parses and satisfies f > 0, but it silently
// disables every threshold comparison downstream. Values > 1 are
// kept — several threshold knobs document ">1 disables the check" as
// the operator escape hatch.
func GetenvFloatPositive(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil &&
			!math.IsNaN(f) && !math.IsInf(f, 0) && f > 0 {
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
// spam the log), the same once-per pattern hostutil uses for its
// rename-fallback warning.
var gateIntentWarned sync.Map

// looksLikeGateIntent reports whether v reads as boolean intent Gate
// will silently drop: Bool's lenient vocabulary (1/0, true/false,
// yes/no, on/off) in any casing. Exact "true"/"false" — the two values
// Gate actually applies — are handled before this runs and never land
// here; anything else in the vocabulary is a mis-cased or synonym
// spelling that quietly fell back to the default.
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
		// LoadOrStore makes the warn-once decision atomic: exactly one
		// concurrent resolver becomes the warner for this key.
		if _, dup := gateIntentWarned.LoadOrStore(key, struct{}{}); !dup {
			Warnf("bool-like gate value not applied — set exactly \"true\" or \"false\", using default",
				"key", key, "value", v, "default_on", defaultOn)
		}
	}
	return defaultOn
}

// Knob is one row of a package's declarative env surface: Name is the
// env var and Resolve lands its value — through the helpers above, so
// the env → conf → compiled-default chains keep their documented
// precedence — into the Config field the closure captured. The *Knob
// constructors cover the common single-getter chains; write a bare
// {Name, Resolve} literal for bespoke resolutions — Resolve receives
// Name, so the env string still appears exactly once per row. Build
// the table inside ConfigFromEnv (Resolve closures capture &cfg) and
// pass it to Apply.
type Knob struct {
	Name    string
	Resolve func(name string)
}

// Apply resolves each knob in table order — the engine behind a
// table-driven ConfigFromEnv env surface.
func Apply(knobs []Knob) {
	for _, k := range knobs {
		k.Resolve(k.Name)
	}
}

// StringKnob binds env name → *p via String (env → def).
func StringKnob(name string, p *string, def string) Knob {
	return Knob{name, func(k string) { *p = String(k, def) }}
}

// BoolKnob binds env name → *p via Bool (env → def).
func BoolKnob(name string, p *bool, def bool) Knob {
	return Knob{name, func(k string) { *p = Bool(k, def) }}
}

// IntKnob binds env name → *p via Int (env → def).
func IntKnob(name string, p *int, def int) Knob {
	return Knob{name, func(k string) { *p = Int(k, def) }}
}

// Int64Knob binds env name → *p via Int64 (env → def).
func Int64Knob(name string, p *int64, def int64) Knob {
	return Knob{name, func(k string) { *p = Int64(k, def) }}
}

// DurationKnob binds env name → *p via Duration (env → def).
func DurationKnob(name string, p *time.Duration, def time.Duration) Knob {
	return Knob{name, func(k string) { *p = Duration(k, def) }}
}

// OrKnob binds env name → *p via Or (env → conf; an empty conf flows
// to the consumer's compiled default, exactly as Or documents).
func OrKnob(name string, p *string, conf string) Knob {
	return Knob{name, func(k string) { *p = Or(k, conf) }}
}

// StrOrKnob binds env name → *p via Str(Or(k, conf), def) — the full
// env → conf → compiled-default string chain in one row.
func StrOrKnob(name string, p *string, conf, def string) Knob {
	return Knob{name, func(k string) { *p = Str(Or(k, conf), def) }}
}

// IntOrKnob binds env name → *p via IntOr (env → conf → def).
func IntOrKnob(name string, p *int, conf, def int) Knob {
	return Knob{name, func(k string) { *p = IntOr(k, conf, def) }}
}

// Int64OrKnob binds env name → *p via Int64Or (env → conf → def).
func Int64OrKnob(name string, p *int64, conf, def int64) Knob {
	return Knob{name, func(k string) { *p = Int64Or(k, conf, def) }}
}

// DurOrKnob binds env name → *p via DurOr (env → conf-seconds → def).
func DurOrKnob(name string, p *time.Duration, confSeconds int, def time.Duration) Knob {
	return Knob{name, func(k string) { *p = DurOr(k, confSeconds, def) }}
}

// ListKnob binds env name → *p via List (unset/empty → nil).
func ListKnob(name string, p *[]string) Knob {
	return Knob{name, func(k string) { *p = List(k) }}
}

// IntListKnob binds env name → *p via IntList (unset/empty → nil).
func IntListKnob(name string, p *[]int) Knob {
	return Knob{name, func(k string) { *p = IntList(k) }}
}
