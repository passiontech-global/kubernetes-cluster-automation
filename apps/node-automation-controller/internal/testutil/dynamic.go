// dynamic.go — re-exports of internal/platform/testhelp's dynamic
// fake machinery. The ~70-GVK table and the real-scheme fake moved
// DOWN to the platform leaf so platform tests (kube maintenance,
// heal) can List the same CRDs domain tests can — testutil itself is
// off-limits there because it imports internal/shared. Domain tests
// keep importing testutil; prefer testhelp in new platform tests.
//
// The contract is unchanged: NewDynamicClient Lists every CRD the
// modules read with zero per-call-site list-kind plumbing; NewFakeDyn
// remains the escape hatch for runtime-discovered GVRs (merged with
// DynListKinds when the autopilot Plan must also list).
package testutil

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

var (
	// NewDynamicClient returns a dynamic fake that can List every CRD
	// GVK the modules read (see testhelp for the GVK table).
	NewDynamicClient = testhelp.NewDynamicClient
	// DynScheme returns a fresh scheme with built-ins + every known CRD.
	DynScheme = testhelp.DynScheme
	// DynListKinds is the GVR->ListKind map NewDynamicClient knows —
	// merge into a custom map for NewFakeDyn over ad-hoc GVRs.
	DynListKinds = testhelp.DynListKinds
	// NewFakeDyn builds a dynamic fake with explicit GVR->ListKind
	// mappings — for GVRs outside the shared table.
	NewFakeDyn = testhelp.NewFakeDyn
	// Unstructured builds a bare CR fixture (apiVersion/kind/ns/name +
	// top-level fields) — the one-liner for hand-rolled literals.
	Unstructured = testhelp.Unstructured
)
