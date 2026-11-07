// logging.go — the package logger. The name stays "nodereporter"
// (not "npd") so the slog subsystem attribute is byte-identical to
// the pre-split package — log identity is part of the subsystem's
// external contract (the kernelfail precedent).
package npd

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger; see logx.For for why
// resolution is per call.
func logger() *slog.Logger { return logx.For("nodereporter") }
