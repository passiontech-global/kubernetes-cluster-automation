// ciyml_test.go — guards ci.yml's docker-detect consumers(), mise.toml
// consumers, and ko-detect case block against GOWORK=off `go list -deps`.
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

func TestKoDetectMatchesCmdDeps(t *testing.T) {
	hkreleaseglob.CheckKoDetect(t)
}
