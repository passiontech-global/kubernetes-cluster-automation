package concoursecache

import (
	"reflect"
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_SWEEP_BASE_DIR", "/data/openebs")
	t.Setenv("NODE_HOST_AGENT_CONCOURSE_CACHE_INTERVAL", "45m")

	k := ConfigFromEnv()
	if k.CacheRoot != "/data/openebs" {
		t.Fatalf("CacheRoot=%q", k.CacheRoot)
	}
	if k.Interval != 45*time.Minute {
		t.Fatalf("Interval=%v", k.Interval)
	}
	if !reflect.DeepEqual(k.Config, Config{}) {
		t.Fatalf("pruner config should stay script-parity defaults: %+v", k.Config)
	}
}
