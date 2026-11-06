// localbin.go — resolveLocalBinary, lifted out of main.go: the
// "which binary does hubsync mirror to targets" question, including
// the test seams for its two failure shapes.
package main

import (
	"os"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

// osExecutable is os.Executable as a var — tests stub it to exercise
// the "(deleted)"/missing-path fallbacks in resolveLocalBinary.
var osExecutable = os.Executable

// resolveLocalBinary finds the binary hubsync mirrors to targets.
// LocalBinary mirrors the running binary — the DaemonSet ships it at
// /node-host-agent, but resolving our own path keeps the mirror
// correct wherever the binary actually lives. Two failure shapes are
// normalised: os.Executable reports "<path> (deleted)" when the
// running image was replaced in place (sha256File would fail every
// cycle on that literal path), and a still-nonexistent resolved path
// falls back to the DS's fixed /node-host-agent.
func resolveLocalBinary() string {
	if v := os.Getenv(envnames.EnvHubsyncLocalBinary); v != "" {
		return v
	}
	const fallback = "/node-host-agent"
	exe, err := osExecutable()
	if err != nil {
		return fallback
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	if _, err := os.Stat(exe); err != nil {
		return fallback
	}
	return exe
}
