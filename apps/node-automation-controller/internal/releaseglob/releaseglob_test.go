// Package releaseglob guards the release trigger contract: the
// `paths:` globs in .github/workflows/release-node-automation-controller.yml
// must name exactly the hostkit/jinja trees this module's ./cmd/...
// actually imports (plus the module's go.mod/go.sum).
package releaseglob

import (
	"testing"

	hkreleaseglob "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/releaseglob"
)

func TestReleaseWorkflowGlobsMatchCmdDeps(t *testing.T) {
	hkreleaseglob.CheckReleaseWorkflowGlobs(t, "node-automation-controller")
}
