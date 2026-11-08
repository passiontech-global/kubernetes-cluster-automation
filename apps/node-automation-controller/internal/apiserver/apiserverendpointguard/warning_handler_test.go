// warning_handler_test.go — coverage for the endpointsWarningClient
// wiring: a config that already carries the guard's filter reuses the
// incoming shared client, anything else builds a fresh filtered one.
package apiserverendpointguard

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestEndpointsWarningClient(t *testing.T) {
	cfg := &rest.Config{Host: "http://127.0.0.1:1"}

	// A shared client over a filtered config is reused as-is — no
	// second transport for zero behavioral gain.
	filtered := rest.CopyConfig(cfg)
	filtered.WarningHandler = NewWarningHandler()
	stub, err := endpointsWarningClient(filtered, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := endpointsWarningClient(filtered, stub)
	if err != nil {
		t.Fatal(err)
	}
	if got != stub {
		t.Fatal("filtered config must reuse the incoming client")
	}

	// Unfiltered config with a shared client: a fresh filtered client
	// is built; the caller's client is not returned.
	got, err = endpointsWarningClient(cfg, stub)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got == stub {
		t.Fatal("unfiltered config must build a fresh dynamic client")
	}

	// dyn == nil always builds one.
	got, err = endpointsWarningClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil dyn must build a dynamic client")
	}
}

// NewWarningHandler returns the guard's own filter type — the shape
// main type-asserts onto the shared rest.Config.
func TestNewWarningHandlerType(t *testing.T) {
	h := NewWarningHandler()
	if _, ok := h.(endpointGuardWarnings); !ok {
		t.Fatalf("NewWarningHandler = %T, want endpointGuardWarnings", h)
	}
	var _ rest.WarningHandler = h

}
