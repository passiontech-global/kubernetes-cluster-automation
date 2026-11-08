// operator_watchdog_targets_w16_test.go — coverage for the W16-G1
// operatorTargets rows: the argo-rollouts row tracks the Rollout GVR
// with the generic stale-generation signature, and the
// cloudflare-tunnel-gateway-controller row scopes its gateway/route
// resources to the cloudflare-tunnel GatewayClass via the cftOwns*
// filters.
package watchdogs

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// w16Target finds one watched-operator row by name.
func w16Target(t *testing.T, name string) operatorTarget {
	t.Helper()
	for _, tgt := range operatorTargets {
		if tgt.name == name {
			return tgt
		}
	}
	t.Fatalf("operatorTargets missing row %q", name)
	return operatorTarget{}
}

// The argo-rollouts row watches the Rollout GVR with the generic
// staleObservedGeneration signature — no custom predicate, same
// shape as the other typed-operator rows.
func TestArgoRolloutsTargetRow(t *testing.T) {
	tgt := w16Target(t, "argo-rollouts-controller")
	if tgt.leaseNS != "argo-rollouts" {
		t.Fatalf("leaseNS = %q, want argo-rollouts", tgt.leaseNS)
	}
	if tgt.leaseOptional {
		t.Fatal("argo-rollouts leader-elects — must not be leaseOptional")
	}
	if len(tgt.resources) != 1 || tgt.resources[0].gvr != kube.GVRArgoRollout {
		t.Fatalf("resources = %+v, want exactly the Rollout GVR", tgt.resources)
	}
	if tgt.resources[0].stuck == nil {
		t.Fatal("Rollout row carries no stuck predicate")
	}
}

// cftGatewayFixture builds a Gateway carrying a gatewayClassName.
func cftGatewayFixture(class string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"gatewayClassName": class},
	}}
	o.SetNamespace("cloudflare-tunnel-system")
	o.SetName("http-gateway")
	return o
}

// The Gateway owns-filter keeps cloudflare-tunnel-classed objects
// (and unattributable ones, fail-open like cilium's filter) and
// drops provably foreign classes.
func TestCftOwnsGatewayObject(t *testing.T) {
	if !cftOwnsGatewayObject(nil, nil, cftGatewayFixture("cloudflare-tunnel")) {
		t.Fatal("cloudflare-tunnel Gateway must be owned by the cft row")
	}
	if cftOwnsGatewayObject(nil, nil, cftGatewayFixture("cilium")) {
		t.Fatal("cilium-classed Gateway must NOT be owned by the cft row")
	}
	if !cftOwnsGatewayObject(nil, nil, cftGatewayFixture("")) {
		t.Fatal("unattributable Gateway stays in the stuck set (fail-open)")
	}
}

// ---------------------------------------------------------------------------
// W5.8 — reason-keyed FirstSeen + ExternalSecret v1beta1 dedup
// ---------------------------------------------------------------------------

// Distinct stuck reasons on the same object carry DISTINCT first-seen
// keys — a Certificate stuck under no_status_conditions must not
// share (and reset) the stale_observed_generation window.
func TestOperatorFirstSeenKeyedPerReason(t *testing.T) {
	base := time.Now()
	stuck := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate",
		"apps", "tls", 5, 0)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(stuck))
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)
	var certTarget operatorTarget
	for _, op := range operatorTargets {
		if op.name == "cert-manager" {
			certTarget = op
			break
		}
	}
	var rep probefw.SweepReport
	scan := chk.scanOperatorResources(probefw.WithSweepSnapshot(ctx),
		logf.FromContext(ctx), certTarget, base, &rep)
	for _, reason := range []string{opReasonNoConditions, kcmReasonStaleGen} {
		key := "cert-manager/certificates/apps/tls/" + reason
		if !scan.live[key] {
			t.Fatalf("reason %q key not judged live: %v", reason, scan.live)
		}
	}
}

// The external-secrets target scans ExternalSecrets under BOTH API
// versions (older installs still serve v1beta1) — but when the v1
// census came back non-empty the v1beta1 rows are SKIPPED: the same
// object served under two versions must not be scanned twice.
func TestExternalSecretV1Beta1SkippedWhenV1Present(t *testing.T) {
	base := time.Now()
	v1 := probetest.UnstructuredObj("external-secrets.io/v1", "ExternalSecret",
		"apps", "stale-es", 5, 3)
	dyn := &limitRecordingDyn{Interface: probetest.OpDyn(v1)}
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)
	var esTarget operatorTarget
	for _, op := range operatorTargets {
		if op.name == "external-secrets" {
			esTarget = op
			break
		}
	}
	var rep probefw.SweepReport
	scan := chk.scanOperatorResources(probefw.WithSweepSnapshot(ctx),
		logf.FromContext(ctx), esTarget, base, &rep)
	for _, gvr := range dyn.listGvrs {
		if gvr == kube.GVRExternalSecretV1Beta1 {
			t.Fatal("v1beta1 externalsecrets listed although v1 objects are present")
		}
	}
	// The v1 rows still judged the object live under both reasons.
	for _, reason := range []string{opReasonNoConditions, kcmReasonStaleGen} {
		if !scan.live["external-secrets/externalsecrets/apps/stale-es/"+reason] {
			t.Fatalf("stuck ExternalSecret not judged live under %q: %v", reason, scan.live)
		}
	}
}

// And the inverse: a cluster serving ONLY v1beta1 (or an empty v1
// census) still scans the v1beta1 rows.
func TestExternalSecretV1Beta1ScannedWhenV1Empty(t *testing.T) {
	base := time.Now()
	v1beta1 := probetest.UnstructuredObj("external-secrets.io/v1beta1", "ExternalSecret",
		"apps", "legacy-es", 5, 3)
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(v1beta1))
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)
	var esTarget operatorTarget
	for _, op := range operatorTargets {
		if op.name == "external-secrets" {
			esTarget = op
			break
		}
	}
	var rep probefw.SweepReport
	scan := chk.scanOperatorResources(probefw.WithSweepSnapshot(ctx),
		logf.FromContext(ctx), esTarget, base, &rep)
	if len(scan.live) == 0 {
		t.Fatal("v1beta1-only cluster must still produce live stuck keys")
	}
}
