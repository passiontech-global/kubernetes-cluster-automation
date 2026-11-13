// warning_handler_test.go — coverage for NewWarningHandler: it returns
// the guard's own filter type — the shape main type-asserts onto the
// shared rest.Config.
package kube

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestNewWarningHandlerType(t *testing.T) {
	h := NewWarningHandler()
	if _, ok := h.(EndpointGuardWarnings); !ok {
		t.Fatalf("NewWarningHandler = %T, want EndpointGuardWarnings", h)
	}
	var _ rest.WarningHandler = h
}
