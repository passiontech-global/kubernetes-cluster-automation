package kernelfail

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger. The name stays
// "hostmetrics" (not "kernelfail") so the slog subsystem attribute
// is byte-identical to the pre-split package — log identity is
// part of the subsystem's external contract (the wdeps precedent).
func logger() *slog.Logger { return logx.For("hostmetrics") }
