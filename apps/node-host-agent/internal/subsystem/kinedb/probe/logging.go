package probe

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger. The name stays "kinedb" so
// the slog subsystem attribute is byte-identical to the pre-split
// package — log identity is part of the subsystem's external
// contract (the cdeps convention).
func logger() *slog.Logger { return logx.For("kinedb") }
