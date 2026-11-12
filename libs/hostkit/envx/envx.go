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
//     … and the *Knob table constructors in knobs.go) —
//     node-host-agent's shell-knob convention: unrecognised input
//     quietly falls back to the default;
//   - the strict family (the Getenv* getters and Gate, in strict.go)
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

// parseBoolToken classifies v against the lenient boolean vocabulary
// shared by Bool and ModeEnv: 1/true/yes/on → true, 0/false/no/off →
// false, anything else → ok=false so the caller applies its default.
func parseBoolToken(v string) (val, ok bool) {
	switch v {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}

// Bool parses a boolean env var; unset/empty/unrecognised → def.
// Accepts 1/0, true/false, yes/no, on/off (case-sensitive).
func Bool(key string, def bool) bool {
	if val, ok := parseBoolToken(os.Getenv(key)); ok {
		return val
	}
	return def
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
	if val, ok := parseBoolToken(os.Getenv(key)); ok {
		if val {
			return ModeOn
		}
		return ModeOff
	}
	return def
}

// intValue parses v as an int, falling back to def — the shared tail
// of Int and IntOr (an unset env never reaches it: IntOr only calls
// it for a non-empty value, where "" would parse-fail to def anyway).
func intValue(v string, def int) int {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// Int parses an int env var; unset/empty/non-numeric → def.
func Int(key string, def int) int {
	return intValue(os.Getenv(key), def)
}

// int64Value is intValue for int64 knobs.
func int64Value(v string, def int64) int64 {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	return def
}

// Int64 parses an int64 env var; unset/empty/non-numeric → def.
func Int64(key string, def int64) int64 {
	return int64Value(os.Getenv(key), def)
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
	if v := os.Getenv(key); v != "" {
		return intValue(v, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// Int64Or is env → conf → def for int64 knobs. A set-but-non-numeric
// env yields def, not confVal.
func Int64Or(key string, confVal, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		return int64Value(v, def)
	}
	if confVal > 0 {
		return confVal
	}
	return def
}

// maxDurationSeconds is the largest whole-second count a
// time.Duration can hold — the shared overflow bound for the
// bare-integer seconds path in durationValue and DurOr's
// conf-seconds path.
const maxDurationSeconds = math.MaxInt64 / int64(time.Second)

// DurOr is env → conf-seconds → def for duration knobs (conf carries
// bare seconds like the shell *_S knobs). A set-but-unparseable or
// non-positive env yields def, not confSeconds.
func DurOr(key string, confSeconds int, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		return durationValue(key, v, def)
	}
	if confSeconds > 0 {
		// Same overflow guard as durationValue: a conf value past the
		// int64-second ceiling would wrap to a bogus interval.
		if int64(confSeconds) > maxDurationSeconds {
			Warnf("conf duration overflows int64 — using default",
				"env", key, "conf_seconds", confSeconds, "default", def)
			return def
		}
		return time.Duration(confSeconds) * time.Second
	}
	return def
}

// durationValue parses an already-read env value v as a duration —
// the shared tail of Duration and DurOr so neither re-reads the env.
func durationValue(key, v string, def time.Duration) time.Duration {
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
		if int64(n) > maxDurationSeconds ||
			int64(n) < -maxDurationSeconds {
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

// Duration parses a Go duration ("1h", "30s"); a bare integer is
// treated as seconds for parity with the shell knobs it replaces.
// Unset/empty → def. Unparseable or non-positive values warn and fall
// back to def — a ≤0 interval would panic time.NewTicker inside the
// subsystem and crash-loop the daemon.
func Duration(key string, def time.Duration) time.Duration {
	return durationValue(key, os.Getenv(key), def)
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

// warnfHook is the atomic diagnostic sink Warnf dispatches to —
// SetWarnf swaps it without touching Warnf itself, so getter traffic
// stays race-free (one atomic load per call) and late rebinds cannot
// tear a func value mid-call.
var warnfHook atomic.Pointer[func(msg string, kv ...any)]

// Warnf is the sink for the "invalid env value — using default"
// diagnostics emitted by the getters (Duration, IntList, and the
// strict Getenv* family in strict.go). It dispatches through
// warnfHook first and falls back to the package slog logger when no
// hook is installed — SetWarnf is the only rebind path, so every
// caller (tests included) shares the same race-free contract.
func Warnf(msg string, kv ...any) {
	if f := warnfHook.Load(); f != nil {
		(*f)(msg, kv...)
		return
	}
	logger().Warn(msg, kv...)
}

// SetWarnf atomically rebinds the diagnostic sink; nil restores the
// package slog default. Race-free against concurrent Warnf traffic.
func SetWarnf(f func(msg string, kv ...any)) {
	if f == nil {
		warnfHook.Store(nil)
		return
	}
	warnfHook.Store(&f)
}
