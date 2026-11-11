// Identity usage-source extraction and reserved-range exemption for
// the cilium identity auditor: CEP/CES identity-id readers, the
// reserved-identity check used before orphan accounting.
// split from cilium_identity_auditor.go (see its header for the module contract).
package ciliumidentityauditor

import (
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// endpointIdentityID extracts .status.identity.id — numeric in real
// objects (int64) but float64 in hand-built fixtures.
func endpointIdentityID(ep *unstructured.Unstructured) string {
	if id, ok := kube.NestedInt64(
		ep.Object, "status", "identity", "id"); ok {
		return strconv.FormatInt(id, 10)
	}
	if f, ok := kube.NestedFloat64(
		ep.Object, "status", "identity", "id"); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return ""
}

// sliceIdentityIDs extracts every endpoint's identity id from a
// CiliumEndpointSlice's .spec.endpoints[].identity.id — the CES
// replacement for the CEP's .status.identity.id. Non-numeric entries
// are skipped like the CEP path does.
func sliceIdentityIDs(ces *unstructured.Unstructured) []string {
	endpoints, _ := kube.NestedSlice(
		ces.Object, "spec", "endpoints")
	out := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := kube.NestedInt64(
			m, "identity", "id"); ok {
			out = append(out, strconv.FormatInt(id, 10))
			continue
		}
		if f, ok := kube.NestedFloat64(
			m, "identity", "id"); ok {
			out = append(out, strconv.FormatInt(int64(f), 10))
		}
	}
	return out
}

// reservedIdentity exempts Cilium's reserved identity range from
// orphan accounting: a numeric name <= ciliumReservedIDMax (upstream
// GC never reaps 1–255) or a security label carrying the `reserved:`
// prefix (reserved:host, reserved:world, ... — checked in both
// metadata.labels, where Cilium actually stores identity labels, and
// .spec.security-labels for shape tolerance).
func reservedIdentity(id *unstructured.Unstructured) bool {
	if n, err := strconv.ParseInt(id.GetName(), 10, 64); err == nil &&
		n <= ciliumReservedIDMax {
		return true
	}
	for k := range id.GetLabels() {
		if strings.HasPrefix(k, "reserved:") {
			return true
		}
	}
	secLabels, _ := kube.NestedStringMap(
		id.Object, "spec", "security-labels")
	for k := range secLabels {
		if strings.HasPrefix(k, "reserved:") {
			return true
		}
	}
	return false
}
