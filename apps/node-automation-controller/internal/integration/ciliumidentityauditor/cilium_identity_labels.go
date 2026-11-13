// Security-label cardinality profiling for the cilium identity
// auditor: names the label keys inflating the eBPF identity table
// once occupancy passes the warn threshold.
// split from cilium_identity_auditor.go (see its header for the module contract).
package ciliumidentityauditor

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// topSecurityLabelKeys profiles .spec.security-labels across the
// identity list and returns the n keys carrying the most distinct
// values, rendered "key(count)" for one structured log field.
// Cilium mints one identity per distinct security-label SET, so an
// identity-table blow-up is always a high-cardinality key — a
// per-pod label, a churning version tag — and the cardinality of
// its VALUES is what names it (a key seen on every identity with
// one fixed value mints nothing). Sort is count-desc then key-asc
// so the report is deterministic.
func topSecurityLabelKeys(ids []unstructured.Unstructured, n int) []string {
	values := map[string]map[string]struct{}{}
	for i := range ids {
		sec, _ := kube.NestedStringMap(
			ids[i].Object, "spec", "security-labels")
		for k, v := range sec {
			if values[k] == nil {
				values[k] = map[string]struct{}{}
			}
			values[k][v] = struct{}{}
		}
	}
	type kv struct {
		key string
		n   int
	}
	keys := make([]kv, 0, len(values))
	for k, set := range values {
		keys = append(keys, kv{k, len(set)})
	}
	slices.SortFunc(keys, func(a, b kv) int {
		if c := cmp.Compare(b.n, a.n); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s(%d)", k.key, k.n))
	}
	return out
}
