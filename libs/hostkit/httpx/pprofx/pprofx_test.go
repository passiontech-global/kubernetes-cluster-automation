package pprofx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegister(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux)

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s returned 404 after Register", path)
		}
	}
}

func TestHandlers(t *testing.T) {
	const want = "/debug/pprof/"
	handlers := Handlers()
	for _, path := range []string{
		"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile",
		"/debug/pprof/symbol", "/debug/pprof/trace",
	} {
		h, ok := handlers[path]
		if !ok || h == nil {
			t.Fatalf("Handlers() missing entry for %s", path)
		}
	}
	if len(handlers) != 5 {
		t.Fatalf("Handlers() returned %d entries, want 5", len(handlers))
	}

	// Handlers mounted on a fresh mux serve like Register's.
	mux := http.NewServeMux()
	for path, h := range handlers {
		mux.Handle(path, h)
	}
	for _, path := range []string{want, "/debug/pprof/profile", "/debug/pprof/trace"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s returned 404 via Handlers()", path)
		}
	}

	// Each call returns a fresh map — mutating one caller's copy
	// must not leak into the next.
	handlers["/injected"] = http.NotFoundHandler()
	if _, leaked := Handlers()["/injected"]; leaked {
		t.Fatal("Handlers() returned a shared map; mutation leaked across calls")
	}
}
