// circuit_annotation.go — the passiontech.dev/circuit-broken-webhooks
// annotation: the C1 circuit breaker's persistent trip record, kept on
// the webhook config object itself so it survives pod restarts and
// stays human-readable in kubectl describe. The value is a plain
// comma-separated name set — webhook names are DNS-1123 subdomains,
// which can never contain a comma, so the split is unambiguous.
package webhookguard

import (
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// webhookCircuitAnno records, on the webhook config object itself,
// the comma-separated names of the sub-webhooks the C1 circuit
// breaker flipped to failurePolicy=Ignore — the trip record
// survives pod restarts and is human-readable in kubectl describe.
// Comma-separated is unambiguous: webhook names are DNS-1123
// subdomains, which can never contain a comma.
const webhookCircuitAnno = kube.AnnoCircuitBrokenWebhooks

// parseCircuitAnnotation splits the comma-separated annotation value
// into a name set. Webhook names are DNS-1123 subdomains — commas can
// never appear in them, so the plain split is unambiguous.
func parseCircuitAnnotation(v string) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}
