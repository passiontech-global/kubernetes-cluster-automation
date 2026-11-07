// helpers.go — small accessors over jinja values (mapGet/mapStr/
// mapBool/mapList/nodeNameOf) plus the string-slice utilities
// derive() builds its ordered outputs with.
package topology

import (
	"sort"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
)

// --- helpers over jinja values ---

func mapGet(m any, key string) any {
	if om, ok := m.(*OMap); ok {
		if v, ok := om.Get(key); ok {
			return v
		}
	}
	return jinja.NewUndefined(key)
}

func mapStr(m any, key string) string { return jinja.Stringify(mapGet(m, key)) }

func mapBool(m any, key string) bool { return jinja.Truthy(mapGet(m, key)) }

func mapList(m any, key string) []any { return jinja.ToIter(mapGet(m, key)) }

func nodeNameOf(v any) string { return mapStr(v, "name") }

// LastOctet returns the trailing dotted quad of an IPv4 address —
// the default marker_octet a node entry falls back to when the
// registry does not pin one (ops/nebulasign shares the derivation,
// which is why it is exported rather than duplicated).
func LastOctet(ip string) string {
	if i := strings.LastIndex(ip, "."); i >= 0 {
		return ip[i+1:]
	}
	return ip
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func difference(in, excl []string) []string {
	set := map[string]bool{}
	for _, e := range excl {
		set[e] = true
	}
	var out []string
	for _, x := range in {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
