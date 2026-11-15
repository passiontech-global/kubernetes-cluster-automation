package kubelet

import "testing"

func TestLogger(t *testing.T) {
	if logger() == nil {
		t.Fatal("expected non-nil logger")
	}
}
