package envx

import (
	"testing"
	"time"
)

func TestGetenv(t *testing.T) {
	const key = "NAC_TEST_GETENV"

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
	const key = "NAC_TEST_GETENV_INT"

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
	const key = "NAC_TEST_GETENV_DURATION"

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
}

func TestGetenvFloat(t *testing.T) {
	const key = "NAC_TEST_GETENV_FLOAT"

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
}

func TestGate(t *testing.T) {
	const key = "NAC_TEST_GATE"

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
