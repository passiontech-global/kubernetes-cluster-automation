// collect_k0sdrift_test.go — k0s.yaml extraArgs drift findings and the k0s.yaml stat cache.

package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"os"
	"strings"
	"testing"
	"time"
)

func k0sDrift(t *testing.T, c *Collector, reason, key string) (float64, bool) {
	t.Helper()
	return metricValue(t, c, "node_k0s_config_drift",
		map[string]string{"reason": reason, "key": key})
}

// k0sCleanYAML renders a k0s.yaml whose controllerManager.extraArgs
// matches the default ExpectedKCMArgs exactly — the only shape that
// produces zero missing-key findings.
func k0sCleanYAML(extraKeys ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: k0s.k0sproject.io/v1beta1\n" +
		"kind: ClusterConfig\nspec:\n  controllerManager:\n    extraArgs:\n")
	for _, k := range defaultExpectedKCMArgs {
		b.WriteString("      " + k + ": \"5\"\n")
	}
	for _, k := range extraKeys {
		b.WriteString("      " + k + ": \"9\"\n")
	}
	return b.String()
}

func TestK0sDriftRemovedFlag(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  api:\n    extraArgs:\n      concurrent-service-syncs: \"5\"\n")
	if v, ok := k0sDrift(t, New(cfg), "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (removed flag present)", v, ok)
	}
}

func TestK0sDriftMissingConfig(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	// k0s.yaml absent → unreadable finding (drift=1 under the new schema).
	if v, ok := k0sDrift(t, New(cfg), "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 (config missing)", v, ok)
	}
}

func TestK0sDriftUnparseable(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile, "  {not: [valid: yaml\n")
	if v, ok := k0sDrift(t, New(cfg), "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 (unparseable)", v, ok)
	}
}

func TestK0sNoDriftCleanConfig(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML())
	if v, ok := k0sDrift(t, New(cfg), "none", "none"); !ok || v != 0 {
		t.Fatalf("none=%v ok=%v want 0 (clean config)", v, ok)
	}
}

func TestK0sDriftMissingKey(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	// An empty extraArgs block → every expected KCM key is missing.
	testutil.WriteFile(t, cfg.K0sConfigFile,
		"apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n"+
			"spec:\n  controllerManager:\n    extraArgs: {}\n")
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "missing-key", "kube-api-qps"); !ok || v != 1 {
		t.Fatalf("missing-key=%v ok=%v want 1", v, ok)
	}
	if _, ok := k0sDrift(t, c, "none", "none"); ok {
		t.Fatal("none series emitted alongside findings")
	}
}

func TestK0sDriftExtraKey(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML("bogus-extra-flag"))
	if v, ok := k0sDrift(t, New(cfg), "extra-key", "bogus-extra-flag"); !ok || v != 1 {
		t.Fatalf("extra-key=%v ok=%v want 1", v, ok)
	}
}

func TestK0sDriftRemovedFlagNotDoubleCounted(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	// The removed flag sits INSIDE controllerManager.extraArgs: it
	// must report as removed-flag only, not also as extra-key.
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML("concurrent-service-syncs"))
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1", v, ok)
	}
	if _, ok := k0sDrift(t, c, "extra-key", "concurrent-service-syncs"); ok {
		t.Fatal("removed flag double-reported as extra-key")
	}
}

func TestK0sMetricAbsentOnWorker(t *testing.T) {
	cfg, _ := fixture(t)
	// No k0scontroller.service → worker → no series even if config exists.
	testutil.WriteFile(t, cfg.K0sConfigFile, "spec:\n  concurrent-service-syncs: true\n")
	c := New(cfg)
	for _, r := range []string{"removed-flag", "missing-key", "unreadable", "none"} {
		key := "x"
		if r == "unreadable" {
			key = "k0s.yaml"
		} else if r == "none" {
			key = "none"
		}
		if v, ok := k0sDrift(t, c, r, key); ok {
			t.Fatalf("node_k0s_config_drift{reason=%s}=%v emitted on non-controller node", r, v)
		}
	}
}

func TestK0sDriftDuplicateRemovedFlagsDeduped(t *testing.T) {
	// A duplicated flag in the config list must emit ONE finding —
	// the precompiled map keys dedupe. Duplicate identical series
	// would make prometheus Gather fail outright (metricValue's
	// Gather → t.Fatal covers that).
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML("concurrent-service-syncs"))
	cfg.RemovedFlags = []string{"concurrent-service-syncs", "concurrent-service-syncs"}
	c := New(cfg)
	if v, ok := k0sDrift(t, c, "removed-flag", "concurrent-service-syncs"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (single finding)", v, ok)
	}
}

// bumpMtime forces a distinct mtime so the k0s.yaml stat cache sees
// the file as changed — same-second writes can alias otherwise.
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	mt := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func TestK0sConfigCacheRevalidates(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML())
	c := New(cfg)

	// First scrape loads the file; unchanged mtime+size would serve
	// the cache — findings stay consistent across scrapes.
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("clean config none=%v ok=%v want 0", v, ok)
	}
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("second scrape none=%v ok=%v want 0", v, ok)
	}

	// Content change + bumped mtime → the next scrape re-reads.
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML("bogus-extra-flag"))
	bumpMtime(t, cfg.K0sConfigFile)
	if v, ok := k0sDrift(t, c, "extra-key", "bogus-extra-flag"); !ok || v != 1 {
		t.Fatalf("extra-key=%v ok=%v want 1 after config change", v, ok)
	}

	// File gone → unreadable finding, never a stale cached parse.
	if err := os.Remove(cfg.K0sConfigFile); err != nil {
		t.Fatal(err)
	}
	if v, ok := k0sDrift(t, c, "unreadable", "k0s.yaml"); !ok || v != 1 {
		t.Fatalf("unreadable=%v ok=%v want 1 after file removal", v, ok)
	}

	// Restored → findings track the new file again.
	testutil.WriteFile(t, cfg.K0sConfigFile, k0sCleanYAML())
	bumpMtime(t, cfg.K0sConfigFile)
	if v, ok := k0sDrift(t, c, "none", "none"); !ok || v != 0 {
		t.Fatalf("restored config none=%v ok=%v want 0", v, ok)
	}
}

func TestRemovedFlagsCustom(t *testing.T) {
	// A custom flag list replaces the default entirely — a config
	// carrying the default removed flag must not drift when the custom
	// list doesn't contain it.
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.K0sUnitFile, "[Unit]\n")
	testutil.WriteFile(t, cfg.K0sConfigFile,
		"spec:\n  api:\n    extraArgs:\n      concurrent-service-syncs: \"5\"\n")
	cfg.RemovedFlags = []string{"some-other-flag"}
	if _, ok := k0sDrift(t, New(cfg), "removed-flag", "concurrent-service-syncs"); ok {
		t.Fatal("default removed flag reported despite custom list")
	}

	// And the custom flag itself is honoured.
	testutil.WriteFile(t, cfg.K0sConfigFile, "spec:\n  some-other-flag: true\n")
	if v, ok := k0sDrift(t, New(cfg), "removed-flag", "some-other-flag"); !ok || v != 1 {
		t.Fatalf("removed-flag=%v ok=%v want 1 (custom removed flag present)", v, ok)
	}
}
