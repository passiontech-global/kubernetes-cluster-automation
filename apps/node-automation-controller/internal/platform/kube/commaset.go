// commaset.go — the comma-separated-name-set parser. Mirrors
// guardstate.ParseCircuitAnnotation exactly (split on ",", TrimSpace
// each part, skip empties — webhook names are DNS-1123 subdomains, so
// a comma can never appear inside one), promoted to the platform leaf
// so non-webhook call sites stop re-splitting by hand.
package kube

import "strings"

// ParseCommaSet splits a comma-separated value into a trimmed,
// non-empty name set. Order is not preserved (set semantics); an
// empty or absent value yields an empty set.
func ParseCommaSet(s string) map[string]bool {
	out := map[string]bool{}
	for n := range strings.SplitSeq(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}
