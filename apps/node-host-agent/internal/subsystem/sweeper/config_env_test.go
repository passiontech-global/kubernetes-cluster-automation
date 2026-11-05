package sweeper

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/data/openebs")
	t.Setenv("NODE_HOST_AGENT_SWEEP_MIN_AGE", "2h")
	t.Setenv("NODE_HOST_AGENT_SWEEP_MAX_DELETE", "7")
	t.Setenv("NODE_HOST_AGENT_SWEEP_INTERVAL", "30m")
	t.Setenv("NODE_HOST_AGENT_MOUNTS_FILE", "/host/proc/mounts")
	t.Setenv("NODE_HOST_AGENT_REQUEST_TIMEOUT", "5s")

	cs := testutil.FakeKube()
	cfg := ConfigFromEnv(EnvDeps{Client: cs})
	if cfg.Client != cs {
		t.Fatal("ConfigFromEnv did not pass the client through")
	}
	if cfg.BaseDir != "/data/openebs" {
		t.Fatalf("BaseDir=%q", cfg.BaseDir)
	}
	if cfg.MinAge != 2*time.Hour {
		t.Fatalf("MinAge=%v", cfg.MinAge)
	}
	if cfg.MaxDelete != 7 {
		t.Fatalf("MaxDelete=%d", cfg.MaxDelete)
	}
	if cfg.Interval != 30*time.Minute {
		t.Fatalf("Interval=%v", cfg.Interval)
	}
	if cfg.MountsFile != "/host/proc/mounts" {
		t.Fatalf("MountsFile=%q", cfg.MountsFile)
	}
	if cfg.RequestTimeout != 5*time.Second {
		t.Fatalf("RequestTimeout=%v", cfg.RequestTimeout)
	}
}

// The concourse-cache env-config test moved to
// internal/subsystem/concoursecache (TestConfigFromEnv).
