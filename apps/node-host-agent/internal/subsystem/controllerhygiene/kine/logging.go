package kine

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the subsystem logger. The name stays
// "controllerhygiene" so the slog subsystem attribute is
// byte-identical to the pre-split package.
func logger() *slog.Logger { return logx.For("controllerhygiene") }
