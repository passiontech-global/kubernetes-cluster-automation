//go:build !linux

package wdeps

func inotifySameOFD(_, _, _, _ int) bool { return false }
