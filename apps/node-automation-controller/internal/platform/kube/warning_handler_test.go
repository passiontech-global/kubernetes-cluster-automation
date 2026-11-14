// warning_handler_test.go — coverage for NewWarningHandler: it returns
// the guard's own filter type — the shape main type-asserts onto the
// shared rest.Config.
package kube

import (
	"context"
	"testing"

	"k8s.io/client-go/rest"
)

type spyWarningHandler struct {
	calls []string
}

func (s *spyWarningHandler) HandleWarningHeaderWithContext(_ context.Context, code int, agent, message string) {
	s.calls = append(s.calls, message)
}

func TestNewWarningHandlerType(t *testing.T) {
	h := NewWarningHandler()
	if _, ok := h.(EndpointGuardWarnings); !ok {
		t.Fatalf("NewWarningHandler = %T, want EndpointGuardWarnings", h)
	}
	var _ rest.WarningHandler = h
}

func TestEndpointGuardWarnings_FiltersEndpointsDeprecation(t *testing.T) {
	spy := &spyWarningHandler{}
	h := EndpointGuardWarnings{Delegate: spy}

	h.HandleWarningHeader(299, "apiserver", "v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice")
	h.HandleWarningHeaderWithContext(t.Context(), 299, "apiserver", "some other deprecation")
	h.HandleWarningHeader(200, "apiserver", "v1 Endpoints is deprecated")

	if len(spy.calls) != 2 || spy.calls[0] != "some other deprecation" || spy.calls[1] != "v1 Endpoints is deprecated" {
		t.Fatalf("unexpected delegated warnings: %v", spy.calls)
	}
}
