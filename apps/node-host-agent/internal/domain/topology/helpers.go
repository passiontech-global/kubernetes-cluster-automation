// helpers.go — the string-slice utilities derive() builds its
// ordered outputs with, plus nodeNameOf. The mapGet/mapList jinja
// accessors are gone: *jinja.OMap's Get/Slice typed getters are that
// family's single home now.
package topology

import (
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// --- helpers over jinja values ---

func nodeNameOf(v any) string {
	if om, ok := v.(*jinja.OMap); ok {
		return om.Str("name")
	}
	return ""
}

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

// UniqSorted returns the distinct entries of in in ascending sort
// order — the canonical normalisation derive() applies to every
// peer-set it emits (relay targets, egress, resolvers, cert
// subnets) and ops/nebulasign reuses when it renders the registry's
// cert subnets into the nebula-sign job list.
func UniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	slices.Sort(out)
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
