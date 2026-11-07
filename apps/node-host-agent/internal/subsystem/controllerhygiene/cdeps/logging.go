package cdeps

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger. The name stays
// "controllerhygiene" (not "cdeps") so the slog subsystem attribute
// is byte-identical to the pre-split package — log identity is part
// of the subsystem's external contract.
func logger() *slog.Logger { return logx.For("controllerhygiene") }
