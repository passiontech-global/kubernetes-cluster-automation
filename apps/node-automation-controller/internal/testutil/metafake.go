// metafake.go — re-exports of internal/platform/testhelp's metadata
// fake. Same move as dynamic.go/probe.go: the implementation lives
// at the platform leaf so platform's own tests can reach it;
// domain tests keep importing testutil.
package testutil

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

var (
	// NewMetaClient builds a fake metadata.Interface seeded with
	// PartialObjectMetadata objects (see testhelp for the shape).
	NewMetaClient = testhelp.NewMetaClient
	// MetaObj projects an ObjectMeta to a PartialObjectMetadata
	// seed carrying the given apiVersion/kind.
	MetaObj = testhelp.MetaObj
)
