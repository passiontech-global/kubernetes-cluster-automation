// Package heal is the shared preamble + actuation behind every
// pod-kill heal in the tree — the sequence ~10 modules hand-roll
// (probefw.DeletePodHeal, externalsecretnudge's connect bounce,
// datastore's db-operator heal, the watchdogs' leader kills, ...):
//
//	per-key cooldown on the heals ledger
//	-> maintenance mutex, FAIL CLOSED (unverifiable counts as held)
//	-> pick the target (OldestRunningPod for the operator-pod shape)
//	-> UID-preconditioned delete (raw Delete via DeletePod, or the
//	   policy/v1 Eviction via EvictPod when the pod may sit under a
//	   PodDisruptionBudget)
//	-> stamp the ledger ONLY when the delete is delivered
//
// The budget grant the preamble consumes is part of that sequence:
// EvictPodV pairs the grant with the eviction and refunds it when
// the eviction is refused (PDB 429, L1 hold or quorum denial — any
// clean deferral that delivered no heal; see budget.go), so a
// PDB-hung target cannot burn one fleet grant per sweep. Refunds
// live at the GATE OWNER only — low-level DeletePod/EvictPod never
// refund, because they cannot know whether a gate charged the
// budget (exactly-once contract in budget.go).
//
// heal is a leaf platform package: it imports only platform/kube and
// platform/state, returns verdicts and errors, and NEVER calls
// metrics on the shared path — the caller owns IncError and its heal
// counters so the shared path cannot blur which module acted or hide
// a failure behind a generic counter name. The one exception is
// Gate (heal.go), which only ever IncErrors the queue name the
// CALLER passes in — the module identity stays at the call site.
package heal
