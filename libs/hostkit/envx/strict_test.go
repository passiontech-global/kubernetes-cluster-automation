package envx

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Strict-family tests — transplanted verbatim (env-key names aside)
// from node-automation-controller's retired internal/platform/envx
// env_test.go so the ported contract stays asserted, plus coverage
// for GetenvIntMin/GetenvFloatPositive/Warnf that app did not carry.

func TestGetenv(t *testing.T) {
	const key = "ENVX_TEST_GETENV"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := Getenv(key, "def"); got != "def" {
			t.Fatalf("Getenv=%q, want %q", got, "def")
		}
	})

	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "/custom/labels.txt")
		if got := Getenv(key, "def"); got != "/custom/labels.txt" {
			t.Fatalf("Getenv=%q, want %q", got, "/custom/labels.txt")
		}
	})
}

func TestGetenvInt(t *testing.T) {
	const key = "ENVX_TEST_GETENV_INT"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetenvInt(key, 4); got != 4 {
			t.Fatalf("GetenvInt=%d, want 4", got)
		}
	})
	t.Run("valid returns value", func(t *testing.T) {
		t.Setenv(key, "7")
		if got := GetenvInt(key, 4); got != 7 {
			t.Fatalf("GetenvInt=%d, want 7", got)
		}
	})
	t.Run("zero and negative are honored", func(t *testing.T) {
		// minReplicas<=0 is the documented "disable the pin" setting —
		// GetenvInt must not clamp it away.
		for v, want := range map[string]int{"0": 0, "-2": -2} {
			t.Setenv(key, v)
			if got := GetenvInt(key, 4); got != want {
				t.Fatalf("GetenvInt(%q)=%d, want %d", v, got, want)
			}
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "not-a-number")
		if got := GetenvInt(key, 4); got != 4 {
			t.Fatalf("GetenvInt=%d, want 4", got)
		}
	})
}

func TestGetenvDuration(t *testing.T) {
	const key = "ENVX_TEST_GETENV_DURATION"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetenvDuration(key, 5*time.Minute); got != 5*time.Minute {
			t.Fatalf("GetenvDuration=%s, want 5m", got)
		}
	})
	t.Run("valid returns value", func(t *testing.T) {
		t.Setenv(key, "10m")
		if got := GetenvDuration(key, 5*time.Minute); got != 10*time.Minute {
			t.Fatalf("GetenvDuration=%s, want 10m", got)
		}
	})
	// Every duration knob feeds a ticker interval — <=0 would panic
	// time.NewTicker and a sub-second one would hot-loop the sweep,
	// so both must fall back to the default, not be honored.
	t.Run("non-positive falls back to default", func(t *testing.T) {
		for _, v := range []string{"0s", "-5m"} {
			t.Setenv(key, v)
			if got := GetenvDuration(key, 5*time.Minute); got != 5*time.Minute {
				t.Fatalf("GetenvDuration(%q)=%s, want 5m", v, got)
			}
		}
	})
	t.Run("sub-second falls back to default", func(t *testing.T) {
		for _, v := range []string{"1ns", "500ms", "999ms"} {
			t.Setenv(key, v)
			if got := GetenvDuration(key, 5*time.Minute); got != 5*time.Minute {
				t.Fatalf("GetenvDuration(%q)=%s, want 5m", v, got)
			}
		}
	})
	t.Run("one second is honored", func(t *testing.T) {
		t.Setenv(key, "1s")
		if got := GetenvDuration(key, 5*time.Minute); got != time.Second {
			t.Fatalf("GetenvDuration=%s, want 1s", got)
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "not-a-duration")
		if got := GetenvDuration(key, 5*time.Minute); got != 5*time.Minute {
			t.Fatalf("GetenvDuration=%s, want 5m", got)
		}
	})
	// The strict contract does NOT share Duration's bare-integer-as-
	// seconds extension — "45" is unparseable here, not 45s.
	t.Run("bare integer falls back to default", func(t *testing.T) {
		t.Setenv(key, "45")
		if got := GetenvDuration(key, 5*time.Minute); got != 5*time.Minute {
			t.Fatalf("GetenvDuration=%s, want 5m", got)
		}
	})
}

func TestGetenvFloat(t *testing.T) {
	const key = "ENVX_TEST_GETENV_FLOAT"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetenvFloat(key, 0.5); got != 0.5 {
			t.Fatalf("GetenvFloat=%v, want 0.5", got)
		}
	})
	t.Run("valid returns value", func(t *testing.T) {
		t.Setenv(key, "0.25")
		if got := GetenvFloat(key, 0.5); got != 0.25 {
			t.Fatalf("GetenvFloat=%v, want 0.25", got)
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "not-a-float")
		if got := GetenvFloat(key, 0.5); got != 0.5 {
			t.Fatalf("GetenvFloat=%v, want 0.5", got)
		}
	})
	// ParseFloat accepts non-finite literals — they must take the
	// warn-and-default path or threshold comparisons silently corrupt.
	t.Run("non-finite falls back to default", func(t *testing.T) {
		for _, v := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "inf", "Infinity"} {
			t.Setenv(key, v)
			if got := GetenvFloat(key, 0.5); got != 0.5 {
				t.Fatalf("GetenvFloat(%q)=%v, want 0.5", v, got)
			}
		}
	})
}

func TestGetenvIntMin(t *testing.T) {
	const key = "ENVX_TEST_GETENV_INT_MIN"

	t.Run("unset returns default verbatim", func(t *testing.T) {
		// def is returned without the bound applied — "disabled"
		// defaults may sit outside the valid-input range.
		t.Setenv(key, "")
		if got := GetenvIntMin(key, -1, 0); got != -1 {
			t.Fatalf("GetenvIntMin=%d, want -1", got)
		}
	})
	t.Run("at or above min returns value", func(t *testing.T) {
		for v, want := range map[string]int{"0": 0, "10": 10} {
			t.Setenv(key, v)
			if got := GetenvIntMin(key, 10, 0); got != want {
				t.Fatalf("GetenvIntMin(%q)=%d, want %d", v, got, want)
			}
		}
	})
	t.Run("below min falls back to default", func(t *testing.T) {
		t.Setenv(key, "-1")
		if got := GetenvIntMin(key, 10, 0); got != 10 {
			t.Fatalf("GetenvIntMin=%d, want 10", got)
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "bogus")
		if got := GetenvIntMin(key, 10, 0); got != 10 {
			t.Fatalf("GetenvIntMin=%d, want 10", got)
		}
	})
}

func TestGetenvFloatPositive(t *testing.T) {
	const key = "ENVX_TEST_GETENV_FLOAT_POSITIVE"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetenvFloatPositive(key, 0.9); got != 0.9 {
			t.Fatalf("GetenvFloatPositive=%v, want 0.9", got)
		}
	})
	t.Run("positive returns value", func(t *testing.T) {
		t.Setenv(key, "0.25")
		if got := GetenvFloatPositive(key, 0.9); got != 0.25 {
			t.Fatalf("GetenvFloatPositive=%v, want 0.25", got)
		}
	})
	// ">1 disables the check" is the documented operator escape hatch.
	t.Run("above one is honored", func(t *testing.T) {
		t.Setenv(key, "1.5")
		if got := GetenvFloatPositive(key, 0.9); got != 1.5 {
			t.Fatalf("GetenvFloatPositive=%v, want 1.5", got)
		}
	})
	t.Run("zero and negative fall back to default", func(t *testing.T) {
		for _, v := range []string{"0", "-0.5"} {
			t.Setenv(key, v)
			if got := GetenvFloatPositive(key, 0.9); got != 0.9 {
				t.Fatalf("GetenvFloatPositive(%q)=%v, want 0.9", v, got)
			}
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "bogus")
		if got := GetenvFloatPositive(key, 0.9); got != 0.9 {
			t.Fatalf("GetenvFloatPositive=%v, want 0.9", got)
		}
	})
	// ParseFloat accepts non-finite literals — "+Inf" satisfies the
	// f > 0 check but silently disables every threshold comparison
	// downstream, so it takes the same warn-and-default path as
	// GetenvFloat.
	t.Run("non-finite falls back to default", func(t *testing.T) {
		for _, v := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "inf", "Infinity"} {
			t.Setenv(key, v)
			if got := GetenvFloatPositive(key, 0.9); got != 0.9 {
				t.Fatalf("GetenvFloatPositive(%q)=%v, want 0.9", v, got)
			}
		}
	})
}

func TestGate(t *testing.T) {
	const key = "ENVX_TEST_GATE"

	t.Run("opt-in requires exactly true", func(t *testing.T) {
		for v, want := range map[string]bool{
			"":      false, // unset
			"true":  true,
			"false": false,
			"TRUE":  false, // exact match only — same as the old == "true"
			"1":     false,
		} {
			t.Setenv(key, v)
			if got := Gate(key, false); got != want {
				t.Fatalf("Gate(%q, false)=%v, want %v", v, got, want)
			}
		}
	})

	t.Run("default-on disables only on exact false", func(t *testing.T) {
		for v, want := range map[string]bool{
			"":      true, // unset
			"true":  true,
			"false": false,
			"TRUE":  true, // exact match only — same as the old != "false"
			"0":     true,
		} {
			t.Setenv(key, v)
			if got := Gate(key, true); got != want {
				t.Fatalf("Gate(%q, true)=%v, want %v", v, got, want)
			}
		}
	})
}

// Warnf is the one sink every rejected env value flows through —
// capture it to prove the strict getters actually warn (the fallback
// values alone don't show the diagnostic fired).
func TestWarnfIsInvokedOnRejectedValues(t *testing.T) {
	var calls []string
	orig := Warnf
	Warnf = func(msg string, kv ...any) { calls = append(calls, fmt.Sprint(msg, kv)) }
	t.Cleanup(func() { Warnf = orig })

	t.Setenv("ENVX_TEST_WARNF_INT", "bogus")
	GetenvInt("ENVX_TEST_WARNF_INT", 1)
	t.Setenv("ENVX_TEST_WARNF_DUR", "500ms")
	GetenvDuration("ENVX_TEST_WARNF_DUR", time.Minute)
	t.Setenv("ENVX_TEST_WARNF_LIST", "1,x")
	IntList("ENVX_TEST_WARNF_LIST")

	if len(calls) != 3 {
		t.Fatalf("Warnf invoked %d times, want 3: %v", len(calls), calls)
	}
}

// A gate value that reads as boolean intent but misses the exact
// "true"/"false" spelling warns exactly once per key per process and
// keeps the default outcome in both defaultOn modes — the warning must
// surface the silent pin without changing Gate's contract. (The plain
// `Warnf = f` assignment in TestWarnfIsInvokedOnRejectedValues above
// stays as the legacy rebind-path check; this one goes through
// SetWarnf, the atomic path.)
func TestGateWarnsOnIntentLikeMisspellings(t *testing.T) {
	var calls []string
	SetWarnf(func(msg string, kv ...any) { calls = append(calls, fmt.Sprint(msg, kv)) })
	t.Cleanup(func() { SetWarnf(nil) })

	const keyPrefix = "ENVX_TEST_GATE_INTENT_"
	intents := []string{"True", "False", "TRUE", "FALSE", "1", "0", "yes", "no", "on", "off", "Yes", "ON"}
	for i, v := range intents {
		key := fmt.Sprintf("%s%d", keyPrefix, i) // fresh key: warn-once is per KEY
		t.Setenv(key, v)
		before := len(calls)
		// Warn path keeps the default: opt-in stays off, default-on stays on.
		if got := Gate(key, false); got {
			t.Fatalf("Gate(%q, false)=%v, want false (default kept)", v, got)
		}
		if got := Gate(key, true); !got {
			t.Fatalf("Gate(%q, true)=%v, want true (default kept)", v, got)
		}
		if len(calls) != before+1 {
			t.Fatalf("Gate(%q): want exactly one new warning, got %d (%v)", v, len(calls)-before, calls[before:])
		}
	}

	// Once per key per process: the first resolve of a key warns, a
	// later resolve of the SAME key with another intent-like value is
	// silent.
	const key = "ENVX_TEST_GATE_INTENT_ONCE"
	t.Setenv(key, "0")
	if !Gate(key, true) {
		t.Fatal(`Gate("0", true)=false, want true`)
	}
	t.Setenv(key, "True")
	if !Gate(key, true) {
		t.Fatal(`Gate("True", true)=false, want true`)
	}
	if len(calls) != len(intents)+1 {
		t.Fatalf("warn-once violated: %d calls, want %d", len(calls), len(intents)+1)
	}

	// Exact spellings and unset stay silent — they are the applied
	// contract, not dropped intent.
	for _, v := range []string{"true", "false", ""} {
		t.Setenv(key, v)
		Gate(key, true)
		Gate(key, false)
	}
	if len(calls) != len(intents)+1 {
		t.Fatalf("exact/unset values warned: %d calls, want %d", len(calls), len(intents)+1)
	}
}

// SetWarnf must be race-free against concurrent getter traffic — the
// swap goes through the atomic pointer while warnings keep flowing
// (this is the -race exercise; the counter only proves the sink ran).
func TestSetWarnfRaceAgainstGetterTraffic(t *testing.T) {
	t.Setenv("ENVX_TEST_WARNF_RACE", "bogus")
	var warns atomic.Int64
	SetWarnf(func(string, ...any) { warns.Add(1) })
	t.Cleanup(func() { SetWarnf(nil) })

	// Deterministic overlap: readers run a fixed iteration count and
	// the writer hammers SetWarnf until they ALL finish, so every
	// getter call provably runs while a counting hook is installed.
	// The previous shape (writer finishes 20k swaps then closes stop)
	// let a CPU-starved reader miss its first scheduling slot
	// entirely — warns stayed 0 and the test flaked under load.
	var readers sync.WaitGroup
	readers.Add(4)
	for range 4 {
		go func() {
			defer readers.Done()
			for range 2000 {
				GetenvInt("ENVX_TEST_WARNF_RACE", 1)
			}
		}()
	}
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
				SetWarnf(func(string, ...any) { warns.Add(1) })
			}
		}
	}()
	readers.Wait()
	close(stop)
	writer.Wait()
	SetWarnf(nil)

	if warns.Load() == 0 {
		t.Fatal("sink never invoked during the hammer")
	}
}

// The three rebind shapes and their routing, in one sequence:
// SetWarnf installs through the atomic hook (the default Warnf var
// dispatches to it), a second SetWarnf overrides the first, and the
// legacy direct `Warnf = f` assignment still routes — the var is the
// sink either way. After a direct assignment the hook is orphaned
// (documented at Warnf): the test ends there so the restore cleanup
// re-establishes the dispatcher before anything else routes.
func TestWarnfRebindShapesRoute(t *testing.T) {
	orig := Warnf
	t.Cleanup(func() {
		Warnf = orig  // re-install the dispatcher FIRST…
		SetWarnf(nil) // …then clear the hook it dispatches to
	})

	var which []string
	SetWarnf(func(string, ...any) { which = append(which, "hook1") })
	Warnf("a")
	SetWarnf(func(string, ...any) { which = append(which, "hook2") })
	Warnf("b")
	Warnf = func(string, ...any) { which = append(which, "direct") }
	Warnf("c")

	want := []string{"hook1", "hook2", "direct"}
	if !slices.Equal(which, want) {
		t.Fatalf("rebind routing = %v, want %v", which, want)
	}
}
