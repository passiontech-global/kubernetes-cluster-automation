//go:build !linux

package wdeps

import "errors"

func detachLoop(string) error {
	return errors.New("workerhygiene: LOOP_CLR_FD unsupported on this platform")
}
