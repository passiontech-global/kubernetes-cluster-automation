//go:build !linux

package workerhygiene

import "errors"

// ioniceIdle is a no-op off Linux — ioprio_set(2) is Linux-only and
// the agent only ships to Linux nodes; the build tag keeps the
// package portable for tooling.
func ioniceIdle(int) error {
	return errors.New("workerhygiene: ioprio_set unsupported on this platform")
}
