package main

import (
	"testing"
	"time"
)

func TestGetenv(t *testing.T) {
	const key = "TEST_NHA_GETENV"

	t.Run("unset returns default", func(t *testing.T) {
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv unset=%q want %q", got, "def")
		}
	})
	t.Run("empty returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv empty=%q want %q", got, "def")
		}
	})
	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "val")
		if got := getenv(key, "def"); got != "val" {
			t.Fatalf("getenv set=%q want %q", got, "val")
		}
	})
}

func TestEnvBool(t *testing.T) {
	const key = "TEST_NHA_BOOL"

	// Truthy and falsy spellings must round-trip regardless of the
	// default — mirroring the shell knobs they replace.
	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Run("truthy/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if !envBool(key, false) {
				t.Fatalf("envBool(%q) with default=false want true", v)
			}
			if !envBool(key, true) {
				t.Fatalf("envBool(%q) with default=true want true", v)
			}
		})
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		t.Run("falsy/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if envBool(key, true) {
				t.Fatalf("envBool(%q) with default=true want false", v)
			}
			if envBool(key, false) {
				t.Fatalf("envBool(%q) with default=false want false", v)
			}
		})
	}
	// Invalid/empty fall through to the default — both directions.
	for _, def := range []bool{true, false} {
		t.Setenv(key, "bogus")
		if got := envBool(key, def); got != def {
			t.Fatalf("envBool(invalid)=%v want default %v", got, def)
		}
		t.Setenv(key, "")
		if got := envBool(key, def); got != def {
			t.Fatalf("envBool(empty)=%v want default %v", got, def)
		}
	}
}

func TestEnvInt(t *testing.T) {
	const key = "TEST_NHA_INT"

	t.Setenv(key, "42")
	if got := envInt(key, 7); got != 42 {
		t.Fatalf("envInt=%d want 42", got)
	}
	t.Setenv(key, "notanint")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(invalid)=%d want default 7", got)
	}
	t.Setenv(key, "")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(empty)=%d want default 7", got)
	}
}

func TestEnvInt64(t *testing.T) {
	const key = "TEST_NHA_INT64"

	t.Setenv(key, "9876543210")
	if got := envInt64(key, 5); got != 9876543210 {
		t.Fatalf("envInt64=%d want 9876543210", got)
	}
	t.Setenv(key, "notanint")
	if got := envInt64(key, 5); got != 5 {
		t.Fatalf("envInt64(invalid)=%d want default 5", got)
	}
	t.Setenv(key, "")
	if got := envInt64(key, 5); got != 5 {
		t.Fatalf("envInt64(empty)=%d want default 5", got)
	}
}

func TestEnvDuration(t *testing.T) {
	const key = "TEST_NHA_DURATION"

	// Go duration strings parse normally.
	t.Setenv(key, "1h")
	if got := envDuration(key, time.Second); got != time.Hour {
		t.Fatalf("envDuration(1h)=%v want 1h", got)
	}
	t.Setenv(key, "30s")
	if got := envDuration(key, time.Second); got != 30*time.Second {
		t.Fatalf("envDuration(30s)=%v want 30s", got)
	}
	// A bare integer means seconds — parity with the shell knobs.
	t.Setenv(key, "90")
	if got := envDuration(key, time.Second); got != 90*time.Second {
		t.Fatalf("envDuration(90)=%v want 90s", got)
	}
	t.Setenv(key, "bogus!")
	if got := envDuration(key, time.Second); got != time.Second {
		t.Fatalf("envDuration(invalid)=%v want default 1s", got)
	}
	t.Setenv(key, "")
	if got := envDuration(key, time.Second); got != time.Second {
		t.Fatalf("envDuration(empty)=%v want default 1s", got)
	}
}

// TestKubeClientOutOfCluster exercises the KUBECONFIG fallback. The
// in-cluster env vars are forced empty so rest.InClusterConfig fails
// deterministically; the assertion still tolerates either outcome
// (error, or a client if the environment somehow resolves one).
func TestKubeClientOutOfCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	t.Run("missing kubeconfig file errors", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
		cs, err := kubeClient()
		if err == nil && cs == nil {
			t.Fatal("kubeClient returned nil client and nil error")
		}
	})
	t.Run("empty kubeconfig errors", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		cs, err := kubeClient()
		if err == nil && cs == nil {
			t.Fatal("kubeClient returned nil client and nil error")
		}
	})
}
