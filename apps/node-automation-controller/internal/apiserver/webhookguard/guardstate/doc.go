// Package guardstate is webhookguard's shared leaf: the Guard dep
// bundle every duty reads (clients, queue name, clock, probe seam,
// maintenance-mutex verdict), the per-run Snapshot the facade lists
// once and hands to all four sweeps, the W5.5/W9-CP1 endpoint
// census machinery, and the webhook-config helpers more than one
// duty needs (kind label values, the circuit-broken annotation, the
// fail-closed predicate, the CRD conversion service key). It imports
// no sibling duty package — the duties and the facade all depend on
// it, never the reverse.
package guardstate
