package nodereporter

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/logx"
)

// logger returns the package logger; see logx.For for why resolution is per call.
func logger() *slog.Logger { return logx.For("nodereporter") }
