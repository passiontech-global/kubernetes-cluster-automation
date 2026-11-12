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
