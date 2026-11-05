package janitor

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/logx"
)

// logger returns the package logger; see logx.For for why resolution is per call.
// Named "janitor" (not the former host package "workerhygiene") — every line the
// janitor emits already carries the distinguishing "subsystem"="janitor" attr.
func logger() *slog.Logger { return logx.For("janitor") }
