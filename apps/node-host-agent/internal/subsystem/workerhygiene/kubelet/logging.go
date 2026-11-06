package kubelet

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger. The name stays
// "workerhygiene" so the slog subsystem attribute is byte-identical
// to the pre-split package.
func logger() *slog.Logger { return logx.For("workerhygiene") }
