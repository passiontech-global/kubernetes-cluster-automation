package concoursecache

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/logx"
)

// logger returns the package logger; see logx.For for why resolution is per call.
// Named "concourse-cache" (not the former host package "sweeper") — the pruner's
// lines already carry the "subsystem"="concourse-cache" attr, so they stay
// distinguishable (the attr is kept for log-stream continuity).
func logger() *slog.Logger { return logx.For("concourse-cache") }
