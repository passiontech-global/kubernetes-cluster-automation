// Package releaseglob guards the release trigger contract: the
// `paths:` globs in .github/workflows/release-node-host-agent.yml must
// name exactly the hostkit/jinja trees this module's ./cmd/... actually
// imports (plus libs/hostkit/go.mod and go.sum).
package releaseglob

import (
	"testing"

	hkreleaseglob "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/releaseglob"
)

func TestReleaseWorkflowGlobsMatchCmdDeps(t *testing.T) {
	hkreleaseglob.CheckReleaseWorkflowGlobs(t, "node-host-agent")
}
