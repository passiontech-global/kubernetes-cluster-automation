// logging.go — package logger for the nebula checks; per module
// AGENTS.md a subpackage keeps the PARENT's log identity — the
// subsystem attribute is the external log contract.
package nebula

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the package logger; see logx.For for why resolution is per call.
func logger() *slog.Logger { return logx.For("nethealth") }
