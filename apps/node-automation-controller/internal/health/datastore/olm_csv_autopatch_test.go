// olm_csv_autopatch_test.go — coverage for the W20-CP3 durable-patch
// duties: the argocd-operator probe patch, the node-maintenance
// --leader-elect strip, the InstallPlan ResolutionFailed read, and
// the int64/float64 number coercion the dynamic client produces —
// plus the gated write-heal shapes: the spec.approved=true InstallPlan
// heal (captured patch body) and the persisted-cooldown gate both
// heals run through.
package datastore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

// installPlan builds an everest-namespace InstallPlan aged `age`
// carrying the given spec fields.
func installPlan(name string, age time.Duration,
	spec map[string]any) *unstructured.Unstructured {
	plan := probetest.UnstructuredObj(
		"operators.coreos.com/v1alpha1", "InstallPlan", "everest", name, 1, 0)
	plan.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	if spec != nil {
		plan.Object["spec"] = spec
	}
	return plan
}

// The captured patch body: a stuck everest plan is approved via
// spec.approved=true — the granted state — never via spec.approval
// (the Automatic|Manual policy ENUM; writing "Approved" there was the
// silent no-op this test pins the fix for), and the cooldown stamp
// rides the same patch.
func TestAutoApproveStuckInstallPlanPatchesApprovedField(t *testing.T) {
	base := time.Now()
	plan := installPlan("install-db-operator",
		olmInstallPlanApproveMinAge+time.Minute,
		map[string]any{"approval": "Manual", "approved": false})
	dyn := probetest.OpDyn(plan)
	var bodies []string
	dyn.PrependReactor("patch", "installplans",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			bodies = append(bodies,
				string(action.(ktesting.PatchAction).GetPatch()))
			return false, nil, nil // fall through to the fake's write
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*olmHealthCheck](t, p)

	chk.autoApproveStuckInstallPlans(ctx, logr.Discard(), base)
	if len(bodies) != 1 {
		t.Fatalf("patch calls = %d, want 1", len(bodies))
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &doc); err != nil {
		t.Fatalf("patch body %q: %v", bodies[0], err)
	}
	spec, _ := doc["spec"].(map[string]any)
	if approved, _ := spec["approved"].(bool); !approved {
		t.Fatalf("patch body spec = %v, want spec.approved=true", spec)
	}
	if _, hit := spec["approval"]; hit {
		t.Fatalf("patch body still writes the approval ENUM: %v", spec)
	}
	meta, _ := doc["metadata"].(map[string]any)
	annos, _ := meta["annotations"].(map[string]any)
	if _, ok := annos[olmInstallPlanApproveAnno]; !ok {
		t.Fatalf("patch body missing the %s cooldown stamp: %v",
			olmInstallPlanApproveAnno, doc)
	}
}

// Quiet paths: a young plan, an already-approved plan, a
// ResolutionFailed plan and an out-of-scope-namespace plan are all
// left alone.
func TestAutoApproveStuckInstallPlanQuietPaths(t *testing.T) {
	base := time.Now()
	cases := []struct {
		name string
		plan *unstructured.Unstructured
	}{
		{"young plan", installPlan("young", time.Minute,
			map[string]any{"approval": "Manual", "approved": false})},
		{"already approved", installPlan("approved",
			olmInstallPlanApproveMinAge+time.Minute,
			map[string]any{"approval": "Manual", "approved": true})},
		{"resolution failed", func() *unstructured.Unstructured {
			plan := installPlan("broken", time.Hour,
				map[string]any{"approval": "Manual", "approved": false})
			plan.Object["status"] = map[string]any{"conditions": []any{
				map[string]any{"type": "ResolutionFailed", "status": "True"}}}
			return plan
		}()},
		{"out-of-namespace", func() *unstructured.Unstructured {
			plan := installPlan("medik8s", time.Hour,
				map[string]any{"approval": "Manual", "approved": false})
			plan.SetNamespace("operators") // the intentional Manual gate
			return plan
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dyn := probetest.OpDyn(c.plan)
			patches := 0
			dyn.PrependReactor("patch", "installplans",
				func(ktesting.Action) (bool, runtime.Object, error) {
					patches++
					return false, nil, nil
				})
			p := testProberDyn(fake.NewSimpleClientset(), dyn)
			chk := probetest.MustCheck[*olmHealthCheck](t, p)
			chk.autoApproveStuckInstallPlans(ctx, logr.Discard(), base)
			if patches != 0 {
				t.Fatalf("%s: patched %d times, want 0", c.name, patches)
			}
		})
	}
}

// The persisted half of the 30m approve cooldown: a plan whose
// approval was REVERTED mid-window (approved=false again) but whose
// passiontech.dev/last-installplan-approve stamp is fresh draws no
// patch from a fresh check process — the restart-resume shape an
// in-RAM-only ledger would re-fire every restart.
func TestAutoApproveStuckInstallPlanCooldownGate(t *testing.T) {
	base := time.Now()
	plan := installPlan("install-db-operator", time.Hour,
		map[string]any{"approval": "Manual", "approved": false})
	plan.SetAnnotations(map[string]string{
		olmInstallPlanApproveAnno: base.Add(-10 * time.Minute).
			UTC().Format(time.RFC3339)})
	dyn := probetest.OpDyn(plan)
	patches := 0
	dyn.PrependReactor("patch", "installplans",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*olmHealthCheck](t, p)

	chk.autoApproveStuckInstallPlans(ctx, logr.Discard(), base)
	if patches != 0 {
		t.Fatalf("patched %d times inside the persisted cooldown, want 0",
			patches)
	}
}

// argocdOperatorCSV builds an unpatched argocd-operator CSV (manager
// container without the startupProbe — the drift shape the sweep
// heals).
func argocdOperatorCSV(name string) *unstructured.Unstructured {
	csv := probetest.UnstructuredObj("operators.coreos.com/v1alpha1",
		"ClusterServiceVersion", "operators", name, 1, 0)
	csv.Object["spec"] = csvDeploymentsObj(managerCtr())["spec"]
	return csv
}

// The CSV durable-patch write carries the cooldown stamp in the SAME
// merge patch, and the persisted stamp suppresses a FRESH check
// process (empty in-RAM ledger — the restart-resume shape) inside the
// window even after OLM re-asserts the bundle spec (drift again,
// annotations untouched) — the patch-vs-revert fight the gate exists
// to stop.
func TestAutoPatchOperatorCSVsGateAndStamp(t *testing.T) {
	base := time.Now()
	csv := argocdOperatorCSV("argocd-operator.v2.7.1")
	dyn := probetest.OpDyn(csv)
	var body string
	dyn.PrependReactor("patch", "clusterserviceversions",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			body = string(action.(ktesting.PatchAction).GetPatch())
			return false, nil, nil
		})
	chk := probetest.MustCheck[*olmHealthCheck](t,
		testProberDyn(fake.NewSimpleClientset(), dyn))

	// First sweep: drift healed, stamp landed.
	chk.autoPatchOperatorCSVs(ctx, logr.Discard(), base)
	if body == "" {
		t.Fatal("unpatched argocd-operator CSV must be patched")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("patch body %q: %v", body, err)
	}
	meta, _ := doc["metadata"].(map[string]any)
	annos, _ := meta["annotations"].(map[string]any)
	if _, ok := annos[olmCSVPatchHealAnno]; !ok {
		t.Fatalf("patch body missing the %s cooldown stamp: %v",
			olmCSVPatchHealAnno, doc)
	}

	// OLM re-asserts the bundle mid-window: the spec drifts back, the
	// annotations (ours included) survive — an OLM upgrade rewrites
	// spec/status, not foreign metadata.
	got, err := dyn.Resource(olmCSVGVR).Namespace("operators").
		Get(ctx, "argocd-operator.v2.7.1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reasserted := argocdOperatorCSV("argocd-operator.v2.7.1")
	reasserted.SetAnnotations(got.GetAnnotations())
	if _, err := dyn.Resource(olmCSVGVR).Namespace("operators").
		Update(ctx, reasserted, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	patches := 0
	dyn.PrependReactor("patch", "clusterserviceversions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	// A FRESH check process — the prober owns its instances, so a new
	// prober is the restarted operator: empty csvPatched ledger.
	chk2 := probetest.MustCheck[*olmHealthCheck](t,
		testProberDyn(fake.NewSimpleClientset(), dyn))
	chk2.autoPatchOperatorCSVs(ctx, logr.Discard(),
		base.Add(10*time.Minute))
	if patches != 0 {
		t.Fatalf("re-patched %d times inside the persisted cooldown, want 0",
			patches)
	}
}
