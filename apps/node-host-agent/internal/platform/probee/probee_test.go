package probee

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTP2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if !HTTP2xx(context.Background(), srv.URL+"/ok", 5*time.Second) {
		t.Fatal("HTTP2xx: 200 endpoint reported false")
	}
	if HTTP2xx(context.Background(), srv.URL+"/wedged", 5*time.Second) {
		t.Fatal("HTTP2xx: 500 endpoint reported true")
	}
	if HTTP2xx(context.Background(), "://bogus", 5*time.Second) {
		t.Fatal("HTTP2xx: malformed URL reported true")
	}
}

func TestHTTP2xxTLSSelfSigned(t *testing.T) {
	// KCM/scheduler parity: a self-signed cert must not fail the probe.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !HTTP2xx(context.Background(), srv.URL, 5*time.Second) {
		t.Fatal("HTTP2xx: self-signed TLS endpoint reported false")
	}
}

func TestHTTPAnyCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// A 500 still proves the event loop is alive — the
	// probeAnyCode contract.
	if !HTTPAnyCode(context.Background(), srv.URL, 5*time.Second) {
		t.Fatal("HTTPAnyCode: 500 endpoint reported false")
	}
	if HTTPAnyCode(context.Background(), "http://127.0.0.1:1/", 2*time.Second) {
		t.Fatal("HTTPAnyCode: unreachable endpoint reported true")
	}
}

func TestHTTPGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := HTTPGet(context.Background(), srv.URL+"/ok", 5*time.Second); err != nil {
		t.Fatalf("HTTPGet: 200 endpoint errored: %v", err)
	}
	if err := HTTPGet(context.Background(), srv.URL+"/wedged", 5*time.Second); err == nil {
		t.Fatal("HTTPGet: 503 endpoint reported nil error")
	}
	if err := HTTPGet(context.Background(), "http://127.0.0.1:1/", 2*time.Second); err == nil {
		t.Fatal("HTTPGet: unreachable endpoint reported nil error")
	}
}

func TestHTTPStatus(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	code, err := HTTPStatus(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("HTTPStatus: got code=%d err=%v, want 503/nil", code, err)
	}
	if gotAuth != "" {
		t.Fatalf("HTTPStatus: Authorization sent with empty bearer: %q", gotAuth)
	}

	code, err = HTTPStatus(context.Background(), srv.URL, "tok123", 5*time.Second)
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("HTTPStatus: got code=%d err=%v, want 503/nil", code, err)
	}
	if gotAuth != "Bearer tok123" {
		t.Fatalf("HTTPStatus: Authorization = %q, want %q", gotAuth, "Bearer tok123")
	}
}

func TestHTTPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = w.Write([]byte("the body"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	b, err := HTTPBody(context.Background(), srv.URL+"/ok", 5*time.Second)
	if err != nil || string(b) != "the body" {
		t.Fatalf("HTTPBody: got %q err=%v", b, err)
	}
	if _, err := HTTPBody(context.Background(), srv.URL+"/missing", 5*time.Second); err == nil {
		t.Fatal("HTTPBody: 404 endpoint reported nil error")
	}
}

func TestHTTPBodyInsecure(t *testing.T) {
	// The KCM /metrics scrape keeps the body even on a 500 — no
	// status check — and accepts self-signed certs.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("partial metrics"))
	}))
	defer srv.Close()

	b, err := HTTPBodyInsecure(context.Background(), srv.URL, 5*time.Second)
	if err != nil || b != "partial metrics" {
		t.Fatalf("HTTPBodyInsecure: got %q err=%v, want body/nil", b, err)
	}
}

func TestBodyOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("ok"))
		case "/padded":
			_, _ = w.Write([]byte("  ok\n"))
		case "/wedged-body":
			// A wedged service answering 500 with body "ok" still
			// reads as ok — the status code is deliberately not
			// checked (probeBodyOK parity).
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("ok"))
		default:
			_, _ = w.Write([]byte("degraded"))
		}
	}))
	defer srv.Close()

	if !BodyOK(context.Background(), srv.URL+"/ok", 5*time.Second) {
		t.Fatal("BodyOK: \"ok\" body reported false")
	}
	if !BodyOK(context.Background(), srv.URL+"/padded", 5*time.Second) {
		t.Fatal("BodyOK: padded \"ok\" body reported false")
	}
	if BodyOK(context.Background(), srv.URL+"/bad", 5*time.Second) {
		t.Fatal("BodyOK: non-ok body reported true")
	}
	if !BodyOK(context.Background(), srv.URL+"/wedged-body", 5*time.Second) {
		t.Fatal("BodyOK: 500-with-ok-body reported false (status must not gate)")
	}
	if BodyOK(context.Background(), "http://127.0.0.1:1/", 2*time.Second) {
		t.Fatal("BodyOK: unreachable endpoint reported true")
	}
}

// unixServer starts an http.Server on a unix socket under t.TempDir.
func unixServer(t *testing.T, h http.Handler) (socket string) {
	t.Helper()
	socket = filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

func TestUnixGet(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/healthz" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))

	b, err := UnixGet(context.Background(), socket, "/v1/healthz")
	if err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("UnixGet: got %q err=%v", b, err)
	}
	if _, err := UnixGet(context.Background(), socket, "/bad"); err == nil {
		t.Fatal("UnixGet: 500 endpoint reported nil error")
	}
	if _, err := UnixGet(context.Background(),
		filepath.Join(t.TempDir(), "missing.sock"), "/x"); err == nil {
		t.Fatal("UnixGet: missing socket reported nil error")
	}
}

func TestUnixDial(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := UnixDial(context.Background(), socket, 5*time.Second); err != nil {
		t.Fatalf("UnixDial: live socket errored: %v", err)
	}
	if err := UnixDial(context.Background(),
		filepath.Join(t.TempDir(), "missing.sock"), 2*time.Second); err == nil {
		t.Fatal("UnixDial: missing socket reported nil error")
	}
}

// udpDNSFake answers UDP datagrams with a minimal well-formed DNS
// response: same id, QR bit set. qr=false echoes the datagram back
// unchanged (a response WITHOUT the QR bit — must not pass).
func udpDNSFake(t *testing.T, qr bool) (addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			if qr && n >= 3 {
				resp[2] |= 0x80
			}
			_, _ = pc.WriteTo(resp, src)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSQuery(t *testing.T) {
	if !DNSQuery(udpDNSFake(t, true), "kubernetes.default.svc.cluster.local",
		2*time.Second) {
		t.Fatal("DNSQuery: responding listener reported false")
	}
	// A datagram echo without the QR bit is a query, not a response.
	if DNSQuery(udpDNSFake(t, false), "example.test", 2*time.Second) {
		t.Fatal("DNSQuery: QR-less echo reported true")
	}
	// Silence (nothing answering) must fail — the wedge verdict.
	if DNSQuery("127.0.0.1:1", "example.test", 300*time.Millisecond) {
		t.Fatal("DNSQuery: dead listener reported true")
	}
}

func TestProbesHonorDeadline(t *testing.T) {
	// A handler that outlives the probe timeout: the client-side
	// deadline must fire first.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	start := time.Now()
	if err := HTTPGet(context.Background(), srv.URL, 100*time.Millisecond); err == nil {
		t.Fatal("HTTPGet: hanging endpoint reported nil error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("HTTPGet: deadline ignored, took %v", d)
	}

	start = time.Now()
	if HTTP2xx(context.Background(), srv.URL, 100*time.Millisecond) {
		t.Fatal("HTTP2xx: hanging endpoint reported true")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("HTTP2xx: deadline ignored, took %v", d)
	}
}

// Silence the unused-import-style lint for the package logger — it
// exists so future probe additions can log without a new file.
var _ = logger
