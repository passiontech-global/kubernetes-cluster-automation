package hostmetrics

import "testing"

func TestDefaultKmsgDevicePaths(t *testing.T) {
	paths := defaultKmsgDevicePaths("/host")
	if len(paths) == 0 {
		t.Fatal("expected non-empty default kmsg device paths")
	}
	pathsEmpty := defaultKmsgDevicePaths("")
	if len(pathsEmpty) == 0 {
		t.Fatal("expected non-empty default kmsg device paths for empty hostRoot")
	}
}
