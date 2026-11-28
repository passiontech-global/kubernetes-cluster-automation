// ciyml_test.go — guards ci.yml's docker-detect consumers() mapping and
// mise.toml consumers against GOWORK=off `go list -deps ./cmd/...`.
package releaseglob

import (
	"testing"

	hkreleaseglob "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/releaseglob"
)

func TestDockerDetectMappingMatchesDeps(t *testing.T) {
	hkreleaseglob.CheckDockerDetectMapping(t)
}

func TestMiseTomlConsumers(t *testing.T) {
	hkreleaseglob.CheckMiseTomlConsumers(t)
}
