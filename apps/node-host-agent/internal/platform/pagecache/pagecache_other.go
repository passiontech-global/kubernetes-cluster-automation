//go:build !linux

package pagecache

import "os"

// dontNeed is a no-op off Linux — the agent only ships on Linux
// (DaemonSet + standalone systemd), the stub keeps `go test` usable
// on dev machines.
func dontNeed(_ *os.File) {}
