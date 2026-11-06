// Package orphansweep is the orphan-admission-webhook sweep — one of
// the four independent duties behind the admission-webhook-guard
// run: it drops Mutating/Validating webhook entries whose backend
// Service lives in a namespace that no longer exists. The sweep is
// stateless — every cluster input arrives through the shared
// guardstate.Snapshot and the guard's clients are reached via snap.G.
package orphansweep
