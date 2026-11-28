// localbin.go — resolveLocalBinary, lifted out of main.go: the
// "which binary does hubsync mirror to targets" question, including
// the test seams for its two failure shapes.
package main

import (
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
)

// osExecutable is os.Executable as a var — tests stub it to exercise
// the "(deleted)"/missing-path fallbacks in resolveLocalBinary.
var osExecutable = os.Executable

// resolveLocalBinary finds the binary hubsync mirrors to targets via
// hostctx.ResolveLocalBinaryWith after checking EnvHubsyncLocalBinary.
func resolveLocalBinary() string {
	if v := os.Getenv(envnames.EnvHubsyncLocalBinary); v != "" {
		return v
	}
	return hostctx.ResolveLocalBinaryWith(osExecutable, hostctx.DefaultLocalBinary)
}
