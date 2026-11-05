// Package envx packages the env-getter helpers cmd/agent used to parse
// NODE_HOST_AGENT_* knobs, so subsystem packages can own their env
// contracts. Each func reads os.Getenv itself; unset/empty semantics
// mirror the original helpers exactly.
package envx

import (
	"os"
	"strconv"
	"strings"
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
		d = time.Duration(n) * time.Second
	} else {
		// Neither shape parsed — a typo'd knob silently pinned to the
		// default is impossible to spot from the outside.
		logger().Warn("unparseable env duration ignored — using default",
			"env", key, "value", v, "default", def)
		return def
	}
	if d <= 0 {
		logger().Warn("non-positive env duration ignored — using default",
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
			logger().Warn("non-numeric env list entry ignored",
				"env", key, "value", p)
			continue
		}
		out = append(out, n)
	}
	return out
}
