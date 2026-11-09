// config_test.go — the HEALTH_* env resolution for the ported
// kuberhealthy checks: defaults when unset, csv trimming on the DNS
// hostnames, warn-and-fallback on invalid knobs, and the documented
// escapes (MaxRestarts 0, quota threshold >1).
package ported

import (
	"reflect"
	"testing"
	"time"
)

// blankPortedEnv isolates every resolver from ambient HEALTH_* values
// — envx treats "" as unset, so pinning the knobs empty makes the
// default assertions deterministic on any host.
func blankPortedEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"HEALTH_DNS_HOSTNAMES",
		"HEALTH_HTTP_CONTENT_URL",
		"HEALTH_HTTP_EXPECTED_CONTENT",
		"HEALTH_POD_CHECK_NAMESPACE",
		"HEALTH_MAX_POD_RESTARTS",
		"HEALTH_POD_SKIP_DURATION",
		"HEALTH_RESOURCE_QUOTA_THRESHOLD",
	} {
		t.Setenv(k, "")
	}
}

func TestDNSConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		blankPortedEnv(t)
		c := DNSConfigFromEnv()
		want := []string{
			"kubernetes.default.svc.cluster.local",
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local",
		}
		if !reflect.DeepEqual(c.Hostnames, want) {
			t.Fatalf("Hostnames = %v, want %v", c.Hostnames, want)
		}
	})

	t.Run("csv is trimmed and empties dropped", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_DNS_HOSTNAMES",
			" a.example.com ,, b.example.com ,")
		c := DNSConfigFromEnv()
		want := []string{"a.example.com", "b.example.com"}
		if !reflect.DeepEqual(c.Hostnames, want) {
			t.Fatalf("Hostnames = %v, want %v", c.Hostnames, want)
		}
	})
}

func TestHTTPContentConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		blankPortedEnv(t)
		c := HTTPContentConfigFromEnv()
		if c.URL != "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy" {
			t.Fatalf("URL = %q", c.URL)
		}
		if c.Expected != "Healthy" {
			t.Fatalf("Expected = %q", c.Expected)
		}
	})

	t.Run("overrides land verbatim", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_HTTP_CONTENT_URL", "http://x/-/healthy")
		t.Setenv("HEALTH_HTTP_EXPECTED_CONTENT", "OK")
		c := HTTPContentConfigFromEnv()
		if c.URL != "http://x/-/healthy" || c.Expected != "OK" {
			t.Fatalf("HTTPContent = %+v", c)
		}
	})
}

func TestPodsConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		blankPortedEnv(t)
		c := PodsConfigFromEnv()
		if c.Namespace != "kube-system" || c.MaxRestarts != 10 ||
			c.SkipDuration != 10*time.Minute {
			t.Fatalf("Pods = %+v, want kube-system/10/10m", c)
		}
	})

	t.Run("valid values override", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_POD_CHECK_NAMESPACE", "observability")
		t.Setenv("HEALTH_MAX_POD_RESTARTS", "3")
		t.Setenv("HEALTH_POD_SKIP_DURATION", "5m")
		c := PodsConfigFromEnv()
		if c.Namespace != "observability" || c.MaxRestarts != 3 ||
			c.SkipDuration != 5*time.Minute {
			t.Fatalf("Pods = %+v", c)
		}
	})

	t.Run("invalid knobs fall back to defaults", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_POD_CHECK_NAMESPACE", "")
		t.Setenv("HEALTH_MAX_POD_RESTARTS", "-1") // below the min-0 bound
		t.Setenv("HEALTH_POD_SKIP_DURATION", "500ms")
		c := PodsConfigFromEnv()
		if c.Namespace != "kube-system" || c.MaxRestarts != 10 ||
			c.SkipDuration != 10*time.Minute {
			t.Fatalf("Pods = %+v, want defaults on invalid input", c)
		}
	})

	t.Run("zero restart ceiling is a legitimate setting", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_MAX_POD_RESTARTS", "0")
		if c := PodsConfigFromEnv(); c.MaxRestarts != 0 {
			t.Fatalf("MaxRestarts = %d, want 0 kept (min bound is 0)",
				c.MaxRestarts)
		}
	})
}

func TestQuotaConfigFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		blankPortedEnv(t)
		if c := QuotaConfigFromEnv(); c.Threshold != 0.9 {
			t.Fatalf("Threshold = %v, want 0.9", c.Threshold)
		}
	})

	t.Run("valid override and >1 escape kept", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_RESOURCE_QUOTA_THRESHOLD", "0.75")
		if c := QuotaConfigFromEnv(); c.Threshold != 0.75 {
			t.Fatalf("Threshold = %v, want 0.75", c.Threshold)
		}
		t.Setenv("HEALTH_RESOURCE_QUOTA_THRESHOLD", "1.5")
		if c := QuotaConfigFromEnv(); c.Threshold != 1.5 {
			t.Fatalf("Threshold = %v, want 1.5 (disable escape)", c.Threshold)
		}
	})

	t.Run("non-positive and junk fall back to 0.9", func(t *testing.T) {
		blankPortedEnv(t)
		for _, v := range []string{"junk", "0", "-0.5"} {
			t.Setenv("HEALTH_RESOURCE_QUOTA_THRESHOLD", v)
			if c := QuotaConfigFromEnv(); c.Threshold != 0.9 {
				t.Fatalf("Threshold(%q) = %v, want 0.9", v, c.Threshold)
			}
		}
	})
}
