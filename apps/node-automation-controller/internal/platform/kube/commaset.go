// commaset.go — the comma-separated-name-set parser. Mirrors
// guardstate.ParseCircuitAnnotation exactly (split on ",", TrimSpace
// each part, skip empties — webhook names are DNS-1123 subdomains, so
// a comma can never appear inside one), promoted to the platform leaf
// so non-webhook call sites stop re-splitting by hand.
package kube

import "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

// ParseCommaSet splits a comma-separated value into a trimmed,
// non-empty name set. Order is not preserved (set semantics); an
// empty or absent value yields a non-nil empty map so callers may
// insert directly without nil-map panics.
func ParseCommaSet(s string) map[string]bool {
	set := envx.ParseCommaSet(s)
	if set == nil {
		return map[string]bool{}
	}
	return set
}
