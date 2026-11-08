// operator_watchdog_targets_w16_test.go — coverage for the W16-G1
// operatorTargets rows: the argo-rollouts row tracks the Rollout GVR
// with the generic stale-generation signature, and the
// cloudflare-tunnel-gateway-controller row scopes its gateway/route
// resources to the cloudflare-tunnel GatewayClass via the cftOwns*
// filters.
package watchdogs

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

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
