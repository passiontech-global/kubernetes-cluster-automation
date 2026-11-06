// probe.go — re-exports of internal/platform/testhelp's probe seams.
// The implementations moved DOWN to the platform leaf so platform's
// own tests can reach them (testutil is off-limits there: it imports
// internal/shared for the manager/contract helpers, and platform must
// stay a leaf). Domain tests keep importing testutil — the aliases
// make the move transparent; prefer testhelp in new platform tests.
package testutil

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

type (
	// StubTransport answers HTTP requests in-process (see testhelp).
	StubTransport = testhelp.StubTransport
	// TrackingBody records body bytes consumed before Close.
	TrackingBody = testhelp.TrackingBody
	// ErrReadCloser fails every Read — a mid-stream body death.
	ErrReadCloser = testhelp.ErrReadCloser
)

var (
	// ProbeResponse is the minimal *http.Response probe code reads.
	ProbeResponse = testhelp.ProbeResponse
	// ProbeRVJSON is the list-envelope shape the list-RV probe decodes.
	ProbeRVJSON = testhelp.ProbeRVJSON
	// ProbeRVSplit serves watch-cache vs quorum list RVs — the wedge.
	ProbeRVSplit = testhelp.ProbeRVSplit
	// ProbeClientset points a real clientset at an httptest apiserver.
	ProbeClientset = testhelp.ProbeClientset
	// ProbeHealthzHandler serves nodes/<any>/proxy/healthz.
	ProbeHealthzHandler = testhelp.ProbeHealthzHandler
	// ProbeLogReactor answers get/pods subresource=log.
	ProbeLogReactor = testhelp.ProbeLogReactor
)
