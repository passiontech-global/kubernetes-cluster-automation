// Package reap is the shared delete-loop skeleton ~9 janitor/cleaner
// modules hand-roll (evicted-pod-janitor, failed-jobs-janitor,
// orphan-endpointslice-cleaner, volumeattachment-cleaner,
// zombie-sidecar-reaper, cilium-identity-auditor,
// helmrelease-unlocker, ...):
//
//	optional deterministic order (Less) — a capped sweep must pick
//	    the same victims every cycle, not whichever ordering the
//	    apiserver returned
//	-> optional live re-confirm (Confirm) — a List snapshot can lag
//	    a Get; fail closed when the confirm itself is unverifiable
//	-> per-target ACTION log in the module's own wording (LogTarget)
//	-> the delete itself (Delete) — callers pass UID-preconditioned
//	    deletes so a same-named recreate never inherits the reap
//	-> per-delete churn cap (Cap) — failed attempts consume it too:
//	    the cap exists to bound API churn, and a rejected delete is
//	    the same apiserver write as a delivered one
//	-> (deleted, failed, capped) back to the caller, which emits its
//	    own "sweep done" / "cap reached" lines
//
// Filter/collect stays module code: what qualifies as a reap target
// is each module's whole reason for existing — Sweep takes the
// already-vetted items slice (so the "release the big list before
// issuing deletes" idiom stays possible: collect small targets,
// nil the objects, then Sweep).
//
// reap is a leaf platform package: it imports nothing above
// platform and NEVER calls metrics — per-item failures report
// through OnError so the module IncErrors its own queue and keeps
// the failure wording its own.
package reap
