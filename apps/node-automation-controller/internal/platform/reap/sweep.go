// sweep.go — the generic cap+confirm+delete loop doc.go describes.
// Everything a module might phrase differently lives in Options
// closures; everything every module writes identically (sort, cap
// accounting, skip/continue discipline, the deleted/failed tally)
// lives here.
package reap

import (
	"context"
	"slices"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Options is the per-module wiring for one Sweep. Every field but
// Delete is optional; the nil cases are the common shapes:
//
//   - Cap 0 means unlimited — small-fleet sweeps that never needed
//     a cap keep none.
//   - Less nil keeps the list order — deterministic already when the
//     backing list is (a typed List is apiserver-ordered by name).
//   - Confirm nil skips the live re-check — for targets whose
//     list-time vetting is sufficient (terminal phases, ages).
//   - LogTarget nil skips the per-target ACTION line entirely.
//   - OnError nil swallows failures silently — almost never right:
//     a delete failure with no IncError makes a wedged janitor
//     invisible. Sweep still counts it into failed either way.
type Options[T any] struct {
	// Cap bounds delete ATTEMPTS per sweep — successful and failed
	// alike, since the cap exists to bound apiserver churn and a
	// rejected delete is the same write as a delivered one. 0 =
	// unlimited.
	Cap int
	// Less, when set, orders items before the cap applies — the
	// deterministic-victims rule: a capped sweep must reap the same
	// candidates every cycle (oldest-first, name order, ...), not
	// whichever ordering the apiserver happened to return. The sort
	// is STABLE so equal-rank items keep their list order. items is
	// sorted in place — pass a slice the sweep may reorder.
	Less func(a, b T) bool
	// Confirm, when set, re-vets each item against live state right
	// before its delete (the orphan-endpointslice shape: re-Get the
	// owner in case the List snapshot lagged). proceed=false skips
	// the item quietly. An error means "could not verify" — the
	// item is kept (fail closed), the error reports through
	// OnError, and the attempt does NOT consume the delete cap: no
	// delete was issued.
	Confirm func(ctx context.Context, item T) (proceed bool, err error)
	// Delete issues the actual delete for one item — callers pass
	// UID-preconditioned deletes (kube.UIDDeleteOptions) so a
	// same-named object recreated since the list is not reaped.
	Delete func(ctx context.Context, item T) error
	// LogTarget, when set, emits the per-target ACTION line in the
	// module's own wording — called after Confirm passes, before
	// Delete, so the log sequence reads identically to the
	// hand-rolled loops (ACTION line then the delete attempt).
	LogTarget func(log logr.Logger, item T)
	// OnError handles a failed Confirm or Delete for one item —
	// the module IncErrors its own queue and logs in its own
	// wording (reap is a leaf; it cannot know the queue name).
	// The failure still tallies into failed for a Delete error;
	// a Confirm error is a defer, not a delete attempt.
	OnError func(log logr.Logger, item T, err error)
}

// Sweep runs the shared delete loop over items — the already-vetted
// target list the caller built during its filter/collect pass. It
// orders by Less (stable, in place), then per item: cap check,
// Confirm re-vet, LogTarget, Delete, tally. The cap breaks the loop
// EARLY — capped=true tells the caller remaining items exist so it
// can emit its "cap reached" line; it is false when items simply ran
// out, even at exactly Cap attempts.
//
// deleted counts delivered deletes, failed counts Delete errors
// (Confirm errors report via OnError but count in neither — no
// delete was attempted). The caller owns the "sweep done" log and
// any per-reason metric increments — Sweep returns the tally, it
// never logs or meters itself.
func Sweep[T any](ctx context.Context, log logr.Logger, items []T,
	opts Options[T]) (deleted, failed int, capped bool) {

	if opts.Less != nil {
		slices.SortStableFunc(items, func(a, b T) int {
			if opts.Less(a, b) {
				return -1
			}
			if opts.Less(b, a) {
				return 1
			}
			return 0
		})
	}
	for i := range items {
		if opts.Cap > 0 && deleted+failed >= opts.Cap {
			return deleted, failed, true
		}
		item := items[i]
		if opts.Confirm != nil {
			proceed, err := opts.Confirm(ctx, item)
			switch {
			case err != nil:
				// Could not verify — keep the item (fail closed)
				// and report; no delete was attempted so the cap
				// is untouched.
				if opts.OnError != nil {
					opts.OnError(log, item, err)
				}
				continue
			case !proceed:
				continue
			}
		}
		if opts.LogTarget != nil {
			opts.LogTarget(log, item)
		}
		if err := opts.Delete(ctx, item); err != nil {
			if opts.OnError != nil {
				opts.OnError(log, item, err)
			}
			failed++
			continue
		}
		deleted++
	}
	return deleted, failed, false
}

// DeleteErrorHandler builds the standard OnError callback for Sweep:
// NotFound and Conflict (UID precondition) log as benign races without
// calling incError; all other errors log and invoke incError.
func DeleteErrorHandler[T any](kind string, ref func(T) string,
	incError func()) func(log logr.Logger, item T, err error) {
	return func(log logr.Logger, item T, err error) {
		target := ref(item)
		switch {
		case apierrors.IsNotFound(err):
			log.Info("SKIP: "+kind+" already gone — raced with an external delete",
				kind, target)
		case apierrors.IsConflict(err):
			log.Info("SKIP: "+kind+" recreated since the list — UID precondition fired",
				kind, target)
		default:
			if incError != nil {
				incError()
			}
			log.Error(err, kind+" delete failed", kind, target)
		}
	}
}
