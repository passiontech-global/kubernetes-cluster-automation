package shared

import (
	"os"
	"strconv"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Env helpers — every module resolves its own knobs and sub-feature
// gates from env inside Setup (the same flag ConfigMaps the
// shell-operator read), so main.go carries no per-module config.
// REGISTRATION gates are the exception: they live in the shared.Module
// registry (cmd/manager/modules.go) and arrive pre-resolved as
// Deps.Disabled — a module must not re-read its own GateEnv here.
// Semantics match the contract documented in cmd/manager/main.go's
// header: unparseable or out-of-range values warn and fall back to the
// default rather than being silently discarded.

// Getenv reads a string env knob, returning def when unset or empty.
func Getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
		logf.Log.WithName("env").Info("unparseable integer env value, using default",
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
		logf.Log.WithName("env").Info("invalid duration env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// GetenvFloat reads a float env knob with the same warn-and-fallback
// contract as GetenvInt.
func GetenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		logf.Log.WithName("env").Info("unparseable float env value, using default",
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
		logf.Log.WithName("env").Info("invalid integer env value, using default",
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
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
		logf.Log.WithName("env").Info("invalid float env value, using default",
			"key", key, "value", v, "default", def)
	}
	return def
}

// Gate resolves a feature-gate env var. defaultOn=false is the
// opt-in convention (enabled only when the value is exactly "true" —
// the destructive/opt-in gates); defaultOn=true is the always-on
// convention the ported CronJobs/kuberhealthy checks kept (enabled
// unless the value is exactly "false" — an explicit opt-out via the
// base-flags ConfigMap).
func Gate(key string, defaultOn bool) bool {
	if defaultOn {
		return os.Getenv(key) != "false"
	}
	return os.Getenv(key) == "true"
}
