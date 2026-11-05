package sweeper

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

// logger returns the package logger; see logx.For for why resolution is per call.
func logger() *slog.Logger { return logx.For("sweeper") }
