package concoursecache

import (
	"reflect"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envnames.EnvSweepBaseDir, "/data/openebs")
	t.Setenv(envnames.EnvConcourseCacheInterval, "45m")

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
