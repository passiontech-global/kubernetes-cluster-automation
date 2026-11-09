// olm_csv_autopatch_test.go — coverage for the W20-CP3 durable-patch
// duties: the argocd-operator probe patch, the node-maintenance
// --leader-elect strip, the InstallPlan ResolutionFailed read, and
// the int64/float64 number coercion the dynamic client produces.
package datastore

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ---------------------------------------------------------------------------
// unstructuredNumber — the int64/float64/json.Number coercion
// ---------------------------------------------------------------------------

func TestUnstructuredNumber(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want float64
		ok   bool
	}{
		{"int64", int64(60), 60, true},
		{"float64", float64(60.5), 60.5, true},
		{"int", int(7), 7, true},
		{"json.Number", json.Number("42"), 42, true},
		{"json.Number bad", json.Number("abc"), 0, false},
		{"string", "60", 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := unstructuredNumber(c.in)
			if ok != c.ok || got != c.want {
				t.Fatalf("unstructuredNumber(%v) = (%v,%v), want (%v,%v)",
					c.in, got, ok, c.want, c.ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ensureManagerStartupProbe / ensureLivenessInitialDelay
// ---------------------------------------------------------------------------

// The startupProbe is cloned from livenessProbe with the ~30m runway
// (10s x 180) — a manager with no livenessProbe gets no invented
// probe, and an existing startupProbe is left alone.
func TestEnsureManagerStartupProbe(t *testing.T) {
	ctr := map[string]any{
		"name": "manager",
		"livenessProbe": map[string]any{
			"httpGet": map[string]any{"path": "/healthz", "port": int64(8081)},
		},
	}
	if !ensureManagerStartupProbe(ctr) {
		t.Fatal("missing startupProbe must be patched")
	}
	sp, ok := ctr["startupProbe"].(map[string]any)
	if !ok {
		t.Fatalf("startupProbe absent after patch: %v", ctr)
	}
	if sp["periodSeconds"] != olmArgocdStartupPeriodSeconds ||
		sp["failureThreshold"] != olmArgocdStartupFailureThreshold {
		t.Fatalf("startupProbe = %v, want period %v x %v",
			sp, olmArgocdStartupPeriodSeconds, olmArgocdStartupFailureThreshold)
	}
	// The clone carries the liveness handler through.
	if _, ok := sp["httpGet"]; !ok {
		t.Fatalf("startupProbe lost the liveness httpGet: %v", sp)
	}
	// Idempotent — a second pass writes nothing.
	if ensureManagerStartupProbe(ctr) {
		t.Fatal("existing startupProbe must not be rewritten")
	}
}

func TestEnsureManagerStartupProbeNoLiveness(t *testing.T) {
	ctr := map[string]any{"name": "manager"}
	if ensureManagerStartupProbe(ctr) {
		t.Fatal("no livenessProbe — must not invent a startupProbe")
	}
	if _, ok := ctr["startupProbe"]; ok {
		t.Fatal("startupProbe written without a liveness source")
	}
}

// livenessProbe.initialDelaySeconds is floored at 60 once a
// startupProbe exists — absent, low, and non-numeric values all
// raise; a value already at/above the floor is untouched.
func TestEnsureLivenessInitialDelay(t *testing.T) {
	cases := []struct {
		name  string
		delay any
		want  any // nil = field absent
		ok    bool
	}{
		{"absent", nil, olmLivenessMinInitialDelay, true},
		{"below floor", int64(10), olmLivenessMinInitialDelay, true},
		{"at floor", int64(60), int64(60), false},
		{"above floor", int64(120), int64(120), false},
		{"float below", float64(30), olmLivenessMinInitialDelay, true},
		{"non-numeric", "soon", olmLivenessMinInitialDelay, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lp := map[string]any{}
			if c.delay != nil {
				lp["initialDelaySeconds"] = c.delay
			}
			ctr := map[string]any{"livenessProbe": lp}
			if got := ensureLivenessInitialDelay(ctr); got != c.ok {
				t.Fatalf("ensureLivenessInitialDelay = %v, want %v", got, c.ok)
			}
			if got := lp["initialDelaySeconds"]; got != c.want {
				t.Fatalf("initialDelaySeconds = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEnsureLivenessInitialDelayNoProbe(t *testing.T) {
	if ensureLivenessInitialDelay(map[string]any{}) {
		t.Fatal("container without livenessProbe must not be patched")
	}
}

// ---------------------------------------------------------------------------
// ensureArgocdOperatorProbes / stripManagerLeaderElect — the CSV spec
// walk over spec.install.spec.deployments[].spec.template.spec.containers[]
// ---------------------------------------------------------------------------

// csvDeploymentsObj builds the unstructured CSV shape both patchers
// walk, with one deployment carrying the given containers.
func csvDeploymentsObj(containers ...map[string]any) map[string]any {
	cs := make([]any, 0, len(containers))
	for _, c := range containers {
		cs = append(cs, c)
	}
	return map[string]any{
		"spec": map[string]any{
			"install": map[string]any{
				"spec": map[string]any{
					"deployments": []any{map[string]any{
						"spec": map[string]any{
							"template": map[string]any{
								"spec": map[string]any{"containers": cs},
							},
						},
					}},
				},
			},
		},
	}
}

// managerCtr is the container shape the argocd patch targets.
func managerCtr() map[string]any {
	return map[string]any{
		"name": "manager",
		"livenessProbe": map[string]any{
			"httpGet": map[string]any{"path": "/healthz", "port": int64(8081)},
		},
	}
}

func TestEnsureArgocdOperatorProbes(t *testing.T) {
	obj := csvDeploymentsObj(managerCtr(),
		map[string]any{"name": "metrics", "image": "x"})
	if !ensureArgocdOperatorProbes(obj) {
		t.Fatal("unpatched manager must report changed")
	}
	// The write-back contract: NestedSlice deep-copies, so the patch
	// must have landed back on the top-level object — read it back
	// through unstructured, not the local container map.
	deps, found, err := unstructured.NestedSlice(obj,
		"spec", "install", "spec", "deployments")
	if err != nil || !found || len(deps) != 1 {
		t.Fatalf("deployments not written back: found=%v err=%v", found, err)
	}
	mgr := deps[0].(map[string]any)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if _, ok := mgr["startupProbe"]; !ok {
		t.Fatal("startupProbe missing on the written-back object")
	}
	lp := mgr["livenessProbe"].(map[string]any)
	if lp["initialDelaySeconds"] != olmLivenessMinInitialDelay {
		t.Fatalf("liveness initialDelaySeconds = %v, want %v",
			lp["initialDelaySeconds"], olmLivenessMinInitialDelay)
	}
	// Idempotent — a second pass over the patched object is a no-op.
	if ensureArgocdOperatorProbes(obj) {
		t.Fatal("already-patched CSV must report unchanged")
	}
}

func TestEnsureArgocdOperatorProbesSkipsNonManager(t *testing.T) {
	obj := csvDeploymentsObj(map[string]any{
		"name": "metrics",
		"livenessProbe": map[string]any{
			"httpGet": map[string]any{"path": "/", "port": int64(8080)},
		},
	})
	if ensureArgocdOperatorProbes(obj) {
		t.Fatal("non-manager container must not be patched")
	}
}

func TestEnsureArgocdOperatorProbesNoDeployments(t *testing.T) {
	if ensureArgocdOperatorProbes(map[string]any{"spec": map[string]any{}}) {
		t.Fatal("CSV without deployments must report unchanged")
	}
}

// stripManagerLeaderElect removes --leader-elect and
// --leader-elect=true from the manager container args — both bare
// and =true spellings die; other args and other containers survive.
func TestStripManagerLeaderElect(t *testing.T) {
	obj := csvDeploymentsObj(
		map[string]any{
			"name": "manager",
			"args": []any{
				"--leader-elect",
				"--log-level=info",
				"--leader-elect=true",
				"--leader-elect=false",
			},
		},
		map[string]any{
			"name": "sidecar",
			"args": []any{"--leader-elect"},
		})
	if !stripManagerLeaderElect(obj) {
		t.Fatal("leader-elect args must be stripped")
	}
	deps, _, _ := unstructured.NestedSlice(obj,
		"spec", "install", "spec", "deployments")
	containers := deps[0].(map[string]any)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	mgrArgs := containers[0].(map[string]any)["args"].([]any)
	want := []any{"--log-level=info", "--leader-elect=false"}
	if len(mgrArgs) != len(want) {
		t.Fatalf("manager args = %v, want %v", mgrArgs, want)
	}
	for i := range want {
		if mgrArgs[i] != want[i] {
			t.Fatalf("manager args = %v, want %v", mgrArgs, want)
		}
	}
	// The sidecar keeps its flag — only the manager container is in
	// scope.
	sideArgs := containers[1].(map[string]any)["args"].([]any)
	if len(sideArgs) != 1 || sideArgs[0] != "--leader-elect" {
		t.Fatalf("sidecar args touched: %v", sideArgs)
	}
	// Idempotent.
	if stripManagerLeaderElect(obj) {
		t.Fatal("stripped CSV must report unchanged")
	}
}

func TestStripManagerLeaderElectClean(t *testing.T) {
	obj := csvDeploymentsObj(map[string]any{
		"name": "manager",
		"args": []any{"--log-level=info"},
	})
	if stripManagerLeaderElect(obj) {
		t.Fatal("clean args must report unchanged")
	}
}

// ---------------------------------------------------------------------------
// resolutionFailed — the InstallPlan ResolutionFailed=True read
// ---------------------------------------------------------------------------

func TestResolutionFailed(t *testing.T) {
	cases := []struct {
		name string
		obj  map[string]any
		want bool
	}{
		{"no status", map[string]any{}, false},
		{"no conditions", map[string]any{
			"status": map[string]any{}}, false},
		{"resolution failed true", map[string]any{
			"status": map[string]any{"conditions": []any{
				map[string]any{"type": "ResolutionFailed", "status": "True"},
			}}}, true},
		{"resolution failed false", map[string]any{
			"status": map[string]any{"conditions": []any{
				map[string]any{"type": "ResolutionFailed", "status": "False"},
				map[string]any{"type": "Installed", "status": "True"},
			}}}, false},
		{"other condition true", map[string]any{
			"status": map[string]any{"conditions": []any{
				map[string]any{"type": "Installed", "status": "True"},
			}}}, false},
		{"malformed entries skipped", map[string]any{
			"status": map[string]any{"conditions": []any{
				"not-a-map",
				map[string]any{"type": "ResolutionFailed", "status": "True"},
			}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolutionFailed(c.obj); got != c.want {
				t.Fatalf("resolutionFailed = %v, want %v", got, c.want)
			}
		})
	}
}
